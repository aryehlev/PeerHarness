//! RFC 8785 JSON Canonicalization Scheme (JCS) over an integer-only JSON subset, and a
//! strict parser (architecture section 4, ADR-002).
//!
//! ## Canonical form ([`canonicalize`])
//!
//! * No insignificant whitespace.
//! * Object members sorted by their keys compared as sequences of **UTF-16 code units**.
//! * Strings escaped exactly like ECMAScript `JSON.stringify`: `\"`, `\\`, `\b`, `\f`,
//!   `\n`, `\r`, `\t`; every other code point below U+0020 as `\u00xx` with lowercase
//!   hex; everything else (including `/`, DEL and all non-ASCII) emitted literally as
//!   UTF-8.
//! * `null`, `true`, `false` as literals.
//! * **Numbers must be integers with `|n| <= 2^53-1`** and are written in plain decimal.
//!   Floats (any value serde_json holds as `f64`, including `1.0`, `1e2` and `-0`) and
//!   larger integers are rejected. Within this subset the output is identical to
//!   RFC 8785.
//!
//! ## Strict parsing ([`parse_strict`])
//!
//! Rejects, in addition to invalid JSON: input over a byte limit, nesting deeper than a
//! depth limit, duplicate object keys (serde_json alone silently keeps the last one),
//! non-integer numbers and out-of-range integers, and trailing data.
//!
//! Depth counts containers: a top-level object or array has depth 1, an object inside
//! it depth 2, and so on. Scalars do not add depth.

use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::{Map, Number, Value};

use crate::error::{JcsError, ProtocolError};
use crate::limits::{MAX_DEPTH, MAX_EVENT_BYTES, MAX_FRAME_BYTES, MAX_FRAME_DEPTH};

/// The largest integer magnitude allowed: `2^53 - 1`.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Hard recursion bound for [`canonicalize`] on values built in memory.
pub const CANONICALIZE_MAX_DEPTH: usize = 64;

/// Size and depth limits for [`parse_strict`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseLimits {
    /// Maximum input size in bytes.
    pub max_bytes: usize,
    /// Maximum nesting depth.
    pub max_depth: usize,
}

impl ParseLimits {
    /// Limits for a single event envelope: 64 KiB, depth 8.
    pub const EVENT: ParseLimits = ParseLimits {
        max_bytes: MAX_EVENT_BYTES,
        max_depth: MAX_DEPTH,
    };
    /// Limits for a wire frame: 512 KiB, depth 10.
    pub const FRAME: ParseLimits = ParseLimits {
        max_bytes: MAX_FRAME_BYTES,
        max_depth: MAX_FRAME_DEPTH,
    };
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self::EVENT
    }
}

// ---------------------------------------------------------------------------------------
// Strict parser
// ---------------------------------------------------------------------------------------

struct Seed<'a> {
    depth: usize,
    max_depth: usize,
    failure: &'a Cell<Option<JcsError>>,
}

impl<'a> Seed<'a> {
    fn fail<E: de::Error>(&self, e: JcsError) -> E {
        self.failure.set(Some(e));
        E::custom("strict JSON violation")
    }

    fn child(&self) -> Seed<'a> {
        Seed {
            depth: self.depth + 1,
            max_depth: self.max_depth,
            failure: self.failure,
        }
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(self.fail(JcsError::IntegerOutOfRange));
        }
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(self.fail(JcsError::IntegerOutOfRange));
        }
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Value, E> {
        Err(self.fail(JcsError::NonInteger))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth + 1 > self.max_depth {
            return Err(self.fail(JcsError::TooDeep {
                max: self.max_depth,
            }));
        }
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(self.child())? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth + 1 > self.max_depth {
            return Err(self.fail(JcsError::TooDeep {
                max: self.max_depth,
            }));
        }
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(self.fail(JcsError::DuplicateKey));
            }
            let v = map.next_value_seed(self.child())?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

/// Parses `bytes` as a single JSON value under `limits`, rejecting duplicate keys,
/// excess depth, non-integer numbers, out-of-range integers and trailing data.
pub fn parse_strict(bytes: &[u8], limits: ParseLimits) -> Result<Value, JcsError> {
    if bytes.len() > limits.max_bytes {
        return Err(JcsError::TooLarge {
            size: bytes.len(),
            max: limits.max_bytes,
        });
    }
    let failure = Cell::new(None);
    let seed = Seed {
        depth: 0,
        max_depth: limits.max_depth,
        failure: &failure,
    };
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let result = seed.deserialize(&mut de).and_then(|v| de.end().map(|()| v));
    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(failure.get().unwrap_or(JcsError::Malformed {
            line: e.line(),
            column: e.column(),
        })),
    }
}

/// [`parse_strict`] for a `&str`.
pub fn parse_strict_str(s: &str, limits: ParseLimits) -> Result<Value, JcsError> {
    parse_strict(s.as_bytes(), limits)
}

/// Nesting depth of `v` (containers only; a scalar has depth 0).
pub fn depth(v: &Value) -> usize {
    // Iterative to stay safe on arbitrarily deep in-memory values.
    let mut max = 0usize;
    let mut stack: Vec<(&Value, usize)> = vec![(v, 0)];
    while let Some((v, d)) = stack.pop() {
        match v {
            Value::Array(a) => {
                max = max.max(d + 1);
                stack.extend(a.iter().map(|c| (c, d + 1)));
            }
            Value::Object(o) => {
                max = max.max(d + 1);
                stack.extend(o.values().map(|c| (c, d + 1)));
            }
            _ => {}
        }
    }
    max
}

// ---------------------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------------------

/// Compares two strings by UTF-16 code units, as RFC 8785 requires for member ordering.
pub fn cmp_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(out: &mut String, n: &Number) -> Result<(), JcsError> {
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(JcsError::IntegerOutOfRange);
        }
        out.push_str(&i.to_string());
        Ok(())
    } else if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(JcsError::IntegerOutOfRange);
        }
        out.push_str(&u.to_string());
        Ok(())
    } else {
        Err(JcsError::NonInteger)
    }
}

fn write_value(out: &mut String, v: &Value, depth: usize) -> Result<(), JcsError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n)?,
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            if depth + 1 > CANONICALIZE_MAX_DEPTH {
                return Err(JcsError::TooDeep {
                    max: CANONICALIZE_MAX_DEPTH,
                });
            }
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(o) => {
            if depth + 1 > CANONICALIZE_MAX_DEPTH {
                return Err(JcsError::TooDeep {
                    max: CANONICALIZE_MAX_DEPTH,
                });
            }
            let mut entries: Vec<(&String, &Value)> = o.iter().collect();
            entries.sort_by(|a, b| cmp_utf16(a.0, b.0));
            out.push('{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, val, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The RFC 8785 canonical form of `v` (integer-only subset).
pub fn canonicalize(v: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(&mut out, v, 0)?;
    Ok(out)
}

/// [`canonicalize`] as UTF-8 bytes.
pub fn canonicalize_bytes(v: &Value) -> Result<Vec<u8>, JcsError> {
    canonicalize(v).map(String::into_bytes)
}

/// Serializes `t` with serde and canonicalizes the result.
pub fn to_canonical_string<T: Serialize + ?Sized>(t: &T) -> Result<String, ProtocolError> {
    let v = to_value(t)?;
    Ok(canonicalize(&v)?)
}

/// `serde_json::to_value` with a payload-free error.
pub(crate) fn to_value<T: Serialize + ?Sized>(t: &T) -> Result<Value, ProtocolError> {
    serde_json::to_value(t).map_err(|_| ProtocolError::Schema {
        object: "serialized value",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        canonicalize(&parse_strict_str(s, ParseLimits::FRAME).unwrap()).unwrap()
    }

    #[test]
    fn rfc8785_key_ordering() {
        // RFC 8785 section 3.2.3 sorting example.
        let input = r#"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#;
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
                        \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
                        \"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(canon(input), expected);
    }

    #[test]
    fn utf16_vs_utf8_ordering() {
        // In UTF-16 the emoji's leading surrogate 0xD83D sorts before 0xFB33, while
        // UTF-8 byte order (and Rust's `str::cmp`) puts U+FB33 first.
        assert_eq!(cmp_utf16("\u{1f600}", "\u{fb33}"), Ordering::Less);
        assert_eq!("\u{1f600}".cmp("\u{fb33}"), Ordering::Greater);
        assert_eq!(
            canon(r#"{"10":1,"1":2,"a":3,"A":4,"":5}"#),
            r#"{"":5,"1":2,"10":1,"A":4,"a":3}"#
        );
        // U+10000 is the surrogate pair D800 DC00, which sorts before U+FFFF in UTF-16
        // although its code point (and UTF-8 encoding) is larger.
        assert_eq!(cmp_utf16("\u{10000}", "\u{ffff}"), Ordering::Less);
        assert_eq!("\u{10000}".cmp("\u{ffff}"), Ordering::Greater);
        assert_eq!(
            canon(r#"{"\uffff":1,"\ud800\udc00":2,"\ue000":3,"\ud7ff":4}"#),
            "{\"\u{d7ff}\":4,\"\u{10000}\":2,\"\u{e000}\":3,\"\u{ffff}\":1}"
        );
        // A key that is a prefix of another sorts first.
        assert_eq!(cmp_utf16("ab", "abc"), Ordering::Less);
        assert_eq!(cmp_utf16("", "a"), Ordering::Less);
    }

    #[test]
    fn escaping_edge_cases() {
        // DEL, U+2028, U+2029, U+FEFF and non-BMP characters are emitted literally;
        // only C0 controls, '"' and '\\' are escaped. '/' is never escaped.
        for (input, expected) in [
            ("\u{7f}", "\"\u{7f}\""),
            ("\u{2028}\u{2029}", "\"\u{2028}\u{2029}\""),
            ("\u{feff}", "\"\u{feff}\""),
            ("\u{1f600}", "\"\u{1f600}\""),
            ("\u{1f}", "\"\\u001f\""),
            ("\u{1b}", "\"\\u001b\""),
            ("</script>", "\"</script>\""),
        ] {
            assert_eq!(
                canonicalize(&Value::String(input.into())).unwrap(),
                expected
            );
        }
        // Escaped input forms canonicalize to the literal or short form.
        assert_eq!(canon(r#""\u007f\u2028\/\u00e9""#), "\"\u{7f}\u{2028}/é\"");
        assert_eq!(canon(r#""\u001F\u0008""#), "\"\\u001f\\b\"");
    }

    #[test]
    fn rfc8785_string_escaping() {
        // RFC 8785 section 3.2.2 "string" member.
        let input = r#"{"string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"}"#;
        assert_eq!(
            canon(input),
            "{\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
        let all_controls: String = (0u8..0x20).map(char::from).collect();
        let v = Value::String(all_controls);
        assert_eq!(
            canonicalize(&v).unwrap(),
            "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\""
        );
        assert_eq!(
            canonicalize(&Value::String("\u{7f}/\u{2028}é".into())).unwrap(),
            "\"\u{7f}/\u{2028}é\""
        );
    }

    #[test]
    fn rfc8785_integer_example() {
        // RFC 8785 section 3.2.2 restricted to the integer subset.
        let input = r#"{"numbers": [333333333, 4, 0, -7], "literals": [null, true, false]}"#;
        assert_eq!(
            canon(input),
            r#"{"literals":[null,true,false],"numbers":[333333333,4,0,-7]}"#
        );
    }

    #[test]
    fn numbers() {
        assert_eq!(canon("9007199254740991"), "9007199254740991");
        assert_eq!(canon("-9007199254740991"), "-9007199254740991");
        for bad in [
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551616",
        ] {
            let e = parse_strict_str(bad, ParseLimits::EVENT).unwrap_err();
            assert!(
                matches!(e, JcsError::IntegerOutOfRange | JcsError::NonInteger),
                "{bad}: {e:?}"
            );
        }
        for bad in [
            "1.0",
            "1e2",
            "1E2",
            "0.5",
            "-0",
            "-0.0",
            "[1.5]",
            "{\"a\":2.5}",
        ] {
            assert_eq!(
                parse_strict_str(bad, ParseLimits::EVENT),
                Err(JcsError::NonInteger),
                "{bad}"
            );
        }
        assert!(matches!(
            parse_strict_str("1e400", ParseLimits::EVENT),
            Err(JcsError::Malformed { .. }) | Err(JcsError::NonInteger)
        ));
        let float = serde_json::json!({"a": 1.5});
        assert_eq!(canonicalize(&float), Err(JcsError::NonInteger));
        let big = serde_json::json!(u64::MAX);
        assert_eq!(canonicalize(&big), Err(JcsError::IntegerOutOfRange));
    }

    #[test]
    fn duplicates_rejected() {
        assert_eq!(
            parse_strict_str(r#"{"a":1,"a":2}"#, ParseLimits::EVENT),
            Err(JcsError::DuplicateKey)
        );
        assert_eq!(
            parse_strict_str(r#"{"x":{"b":1,"b":1}}"#, ParseLimits::EVENT),
            Err(JcsError::DuplicateKey)
        );
        // Escaped and literal spellings of the same key are duplicates.
        assert_eq!(
            parse_strict_str(r#"{"a":1,"\u0061":2}"#, ParseLimits::EVENT),
            Err(JcsError::DuplicateKey)
        );
        assert!(parse_strict_str(r#"{"a":1,"A":2}"#, ParseLimits::EVENT).is_ok());
        // Nested inside arrays and deeper objects.
        for bad in [
            r#"[{"a":1,"a":2}]"#,
            r#"{"x":[1,{"y":{"k":1,"k":2}}]}"#,
            r#"{"x":{},"y":[{"z":{"q":[{"d":1,"d":2}]}}]}"#,
        ] {
            assert_eq!(
                parse_strict_str(bad, ParseLimits::EVENT),
                Err(JcsError::DuplicateKey),
                "{bad}"
            );
        }
        // The same key in sibling objects is not a duplicate.
        assert!(parse_strict_str(r#"[{"a":1},{"a":2}]"#, ParseLimits::EVENT).is_ok());
        assert!(parse_strict_str(r#"{"a":{"a":{"a":1}}}"#, ParseLimits::EVENT).is_ok());
    }

    #[test]
    fn integer_edges() {
        for ok in ["0", "-1", "1"] {
            assert!(parse_strict_str(ok, ParseLimits::EVENT).is_ok(), "{ok}");
        }
        assert_eq!(
            canon("[0, -1, 9007199254740991]"),
            "[0,-1,9007199254740991]"
        );
        for bad in ["-0", "[-0]", "{\"a\":-0}", "0e0", "-0e0", "0.0"] {
            assert_eq!(
                parse_strict_str(bad, ParseLimits::EVENT),
                Err(JcsError::NonInteger),
                "{bad}"
            );
        }
        for bad in ["01", "+1", "-", "1.", ".5", "0x10", "NaN", "Infinity"] {
            assert!(
                matches!(
                    parse_strict_str(bad, ParseLimits::EVENT),
                    Err(JcsError::Malformed { .. })
                ),
                "{bad}"
            );
        }
        // Values beyond i64/u64 are not silently truncated.
        for bad in ["-9223372036854775809", "99999999999999999999999"] {
            assert!(parse_strict_str(bad, ParseLimits::EVENT).is_err(), "{bad}");
        }
        // In-memory values outside the subset are refused by the canonicalizer too.
        assert_eq!(
            canonicalize(&serde_json::json!(i64::MIN)),
            Err(JcsError::IntegerOutOfRange)
        );
        assert_eq!(
            canonicalize(&serde_json::json!(-0.0)),
            Err(JcsError::NonInteger)
        );
    }

    #[test]
    fn depth_limits() {
        let limits = ParseLimits {
            max_bytes: 1024,
            max_depth: 3,
        };
        assert!(parse_strict_str("[[[1]]]", limits).is_ok());
        assert_eq!(
            parse_strict_str("[[[[1]]]]", limits),
            Err(JcsError::TooDeep { max: 3 })
        );
        assert_eq!(
            parse_strict_str(r#"{"a":{"b":{"c":{}}}}"#, limits),
            Err(JcsError::TooDeep { max: 3 })
        );
        assert!(parse_strict_str(r#"{"a":{"b":{"c":1}}}"#, limits).is_ok());
        assert_eq!(depth(&serde_json::json!({"a":[{"b":1}]})), 3);
        assert_eq!(depth(&serde_json::json!(1)), 0);
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        assert!(parse_strict_str(
            &deep,
            ParseLimits {
                max_bytes: 1 << 20,
                max_depth: 8
            }
        )
        .is_err());
    }

    #[test]
    fn size_and_syntax() {
        let limits = ParseLimits {
            max_bytes: 10,
            max_depth: 8,
        };
        assert_eq!(
            parse_strict_str("[1,2,3,4,5,6]", limits),
            Err(JcsError::TooLarge { size: 13, max: 10 })
        );
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1}x",
            "{\"a\":1}{}",
            "\"\\ud800\"",
            "'a'",
            "nul",
        ] {
            assert!(
                matches!(
                    parse_strict_str(bad, ParseLimits::EVENT),
                    Err(JcsError::Malformed { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            parse_strict(b"\"\xff\"", ParseLimits::EVENT),
            Err(JcsError::Malformed { .. })
        ));
        // whitespace around the value is fine
        assert!(parse_strict_str("  {\"a\": 1}\n", ParseLimits::EVENT).is_ok());
    }

    #[test]
    fn idempotent() {
        let s = canon(r#"{"b":[1,{"z":null,"y":"\u00e9\n"}],"a":true}"#);
        assert_eq!(canon(&s), s);
        assert_eq!(s, "{\"a\":true,\"b\":[1,{\"y\":\"é\\n\",\"z\":null}]}");
    }

    #[test]
    fn errors_do_not_echo_input() {
        let e =
            parse_strict_str(r#"{"SECRETKEY":1,"SECRETKEY":2}"#, ParseLimits::EVENT).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
        let e = parse_strict_str(r#"{"a": SECRET}"#, ParseLimits::EVENT).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }
}
