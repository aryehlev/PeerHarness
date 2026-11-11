//! A minimal order-preserving JSON document used to rewrite Claude Code settings.
//!
//! We cannot enable serde_json's `preserve_order` feature: Cargo unifies features across
//! the workspace and other crates rely on `serde_json::Map` being sorted. This type keeps
//! object members in file order, rejects duplicate keys while parsing, and serializes
//! back in the same order through serde_json's pretty printer.
//!
//! A number is kept as it stands in the file ([`Num`], ADR-051). serde_json reads one
//! into an integer or a float and writes the shortest form of that: `1.0` stays, and
//! `1e5` becomes `100000.0`, `12345678901234567890123` becomes
//! `1.2345678901234568e22` and `0.1234567890123456789` loses its last digits. The file
//! is its owner's and holds other tools' settings, so [`Doc::parse`] puts the text of
//! each number back after parsing, and writing copies it out (`raw_value`). We cannot
//! enable `arbitrary_precision` for the reason above: it changes `serde_json::Number`
//! for every crate.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::value::RawValue;
use serde_json::Number;

/// Message of the parse error raised for a duplicate key.
pub(crate) const DUPLICATE_KEY_MSG: &str = "duplicate key";

/// A JSON number as text: the text it has in the file, or serde_json's for one that
/// was made here. Two numbers are equal when their text is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Num(String);

impl From<Number> for Num {
    fn from(n: Number) -> Self {
        Num(n.to_string())
    }
}

/// A JSON value whose objects keep member order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Doc {
    Null,
    Bool(bool),
    Number(Num),
    String(String),
    Array(Vec<Doc>),
    Object(Obj),
}

/// An ordered JSON object with unique keys. Equality ignores member order.
#[derive(Clone, Debug, Default)]
pub(crate) struct Obj(Vec<(String, Doc)>);

impl PartialEq for Obj {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && self.0.iter().all(|(k, v)| other.get(k) == Some(v))
    }
}

impl Obj {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Doc> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub(crate) fn get_mut(&mut self, key: &str) -> Option<&mut Doc> {
        self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Replaces the value in place if `key` exists, else appends.
    pub(crate) fn insert(&mut self, key: &str, value: Doc) {
        match self.get_mut(key) {
            Some(slot) => *slot = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }

    /// Removes `key`, keeping the order of the remaining members.
    pub(crate) fn remove(&mut self, key: &str) -> Option<Doc> {
        let i = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(i).1)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &Doc)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut Doc)> {
        self.0.iter_mut().map(|(k, v)| (k.as_str(), v))
    }
}

impl Doc {
    pub(crate) fn str(s: &str) -> Self {
        Doc::String(s.to_owned())
    }

    pub(crate) fn number(n: u64) -> Self {
        Doc::Number(Number::from(n).into())
    }

    /// Parses a document, with every number as it is written in `bytes`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Doc, serde_json::Error> {
        let mut doc: Doc = serde_json::from_slice(bytes)?;
        // The parser took the bytes, so they are UTF-8 and well-formed JSON: the
        // numbers of the text and of the document are the same ones, in one order.
        if let Ok(text) = std::str::from_utf8(bytes) {
            let written = number_texts(text);
            if written.len() == doc.count_numbers() {
                doc.set_numbers(&mut written.into_iter());
            }
        }
        Ok(doc)
    }

    fn count_numbers(&self) -> usize {
        match self {
            Doc::Number(_) => 1,
            Doc::Array(a) => a.iter().map(Doc::count_numbers).sum(),
            Doc::Object(o) => o.iter().map(|(_, v)| v.count_numbers()).sum(),
            Doc::Null | Doc::Bool(_) | Doc::String(_) => 0,
        }
    }

    /// Gives every number its text, in document order.
    fn set_numbers<'a>(&mut self, written: &mut impl Iterator<Item = &'a str>) {
        match self {
            Doc::Number(n) => {
                if let Some(text) = written.next() {
                    n.0 = text.to_owned();
                }
            }
            Doc::Array(a) => a.iter_mut().for_each(|v| v.set_numbers(written)),
            Doc::Object(o) => o.iter_mut().for_each(|(_, v)| v.set_numbers(written)),
            Doc::Null | Doc::Bool(_) | Doc::String(_) => {}
        }
    }

    pub(crate) fn as_object(&self) -> Option<&Obj> {
        match self {
            Doc::Object(o) => Some(o),
            _ => None,
        }
    }

    pub(crate) fn as_object_mut(&mut self) -> Option<&mut Obj> {
        match self {
            Doc::Object(o) => Some(o),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&Vec<Doc>> {
        match self {
            Doc::Array(a) => Some(a),
            _ => None,
        }
    }

    pub(crate) fn as_array_mut(&mut self) -> Option<&mut Vec<Doc>> {
        match self {
            Doc::Array(a) => Some(a),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Doc::String(s) => Some(s),
            _ => None,
        }
    }

    /// Member `key` of an object; `None` for non-objects.
    pub(crate) fn get(&self, key: &str) -> Option<&Doc> {
        self.as_object()?.get(key)
    }

    pub(crate) fn get_mut(&mut self, key: &str) -> Option<&mut Doc> {
        self.as_object_mut()?.get_mut(key)
    }
}

impl Serialize for Doc {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Doc::Null => s.serialize_unit(),
            Doc::Bool(b) => s.serialize_bool(*b),
            Doc::Number(n) => RawValue::from_string(n.0.clone())
                .map_err(serde::ser::Error::custom)?
                .serialize(s),
            Doc::String(v) => s.serialize_str(v),
            Doc::Array(a) => {
                let mut seq = s.serialize_seq(Some(a.len()))?;
                for v in a {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Doc::Object(o) => {
                let mut map = s.serialize_map(Some(o.len()))?;
                for (k, v) in o.iter() {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Doc {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(DocVisitor)
    }
}

struct DocVisitor;

impl<'de> Visitor<'de> for DocVisitor {
    type Value = Doc;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Doc, E> {
        Ok(Doc::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Doc, E> {
        Ok(Doc::Number(Number::from(v).into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Doc, E> {
        Ok(Doc::Number(Number::from(v).into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Doc, E> {
        Number::from_f64(v)
            .map(|n| Doc::Number(n.into()))
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Doc, E> {
        Ok(Doc::str(v))
    }
    fn visit_string<E>(self, v: String) -> Result<Doc, E> {
        Ok(Doc::String(v))
    }
    fn visit_unit<E>(self) -> Result<Doc, E> {
        Ok(Doc::Null)
    }
    fn visit_none<E>(self) -> Result<Doc, E> {
        Ok(Doc::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Doc, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<Doc>()? {
            out.push(v);
        }
        Ok(Doc::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Doc, A::Error> {
        let mut obj = Obj::new();
        while let Some(k) = map.next_key::<String>()? {
            if obj.contains_key(&k) {
                return Err(de::Error::custom(DUPLICATE_KEY_MSG));
            }
            let v = map.next_value::<Doc>()?;
            obj.0.push((k, v));
        }
        Ok(Doc::Object(obj))
    }
}

/// The text of every number of a well-formed JSON document, in document order. A
/// number starts with a minus sign or a digit outside a string, and nothing else
/// does.
fn number_texts(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    // An escaped character, a quote among them, is not the end.
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < bytes.len()
                    && matches!(bytes[i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    i += 1;
                }
                // Only ASCII was stepped over, so both ends are character boundaries.
                out.push(&text[start..i]);
            }
            _ => i += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_round_trips() {
        let src = r#"{"z":1,"a":{"y":[1,-2,2.5,true,null,"s"],"b":{}},"m":[]}"#;
        let d: Doc = serde_json::from_str(src).unwrap();
        assert_eq!(serde_json::to_string(&d).unwrap(), src);
        assert_eq!(
            serde_json::to_string(&Doc::parse(src.as_bytes()).unwrap()).unwrap(),
            src
        );
    }

    /// A number is written back as it was read (ADR-051). Without that, each of these
    /// but the first and the last comes back as another text, and four of them as
    /// another value.
    #[test]
    fn numbers_keep_their_text() {
        let numbers = [
            "1.0",
            "1e5",
            "1E-7",
            "-0",
            "0.1234567890123456789",
            "12345678901234567890123",
            "9007199254740993",
            "18446744073709551616",
            "-9223372036854775809",
            "1.10",
            "0",
            "-12",
            "2.5e+3",
        ];
        // Among strings that look like numbers, escapes, and words with an `e` in them.
        let src = format!(
            r#"{{"a":[{}],"s":"1e5 \" 12 \\","t":true,"f":false,"n":null,"k-1":{{"2":3.00}},"e":"é -7"}}"#,
            numbers.join(",")
        );
        let doc = Doc::parse(src.as_bytes()).unwrap();
        assert_eq!(serde_json::to_string(&doc).unwrap(), src);
        // And through the pretty printer, which is what a settings file is written with.
        let pretty = serde_json::to_string_pretty(&doc).unwrap();
        for n in numbers {
            assert!(pretty.contains(&format!("    {n}")), "{n} in {pretty}");
        }
        assert!(pretty.contains("\"2\": 3.00"), "{pretty}");
        assert_eq!(
            Doc::parse(pretty.as_bytes()).unwrap(),
            doc,
            "read again, it is the same document"
        );
        // A number made here is serde_json's.
        assert_eq!(serde_json::to_string(&Doc::number(5)).unwrap(), "5");
        // What is not JSON is refused as before.
        assert!(Doc::parse(b"{\"a\": 01}").is_err());
        assert!(Doc::parse(b"{\"a\": 1e999}").is_err());
    }

    #[test]
    fn duplicates_rejected_at_any_depth() {
        for s in [r#"{"a":1,"a":1}"#, r#"{"x":[{"k":1,"k":2}]}"#] {
            let e = serde_json::from_str::<Doc>(s).unwrap_err();
            assert!(e.is_data());
            assert!(e.to_string().starts_with(DUPLICATE_KEY_MSG));
        }
    }

    #[test]
    fn object_ops_and_order_insensitive_eq() {
        let mut o = Obj::new();
        o.insert("b", Doc::Null);
        o.insert("a", Doc::Bool(true));
        o.insert("b", Doc::Bool(false));
        assert_eq!(o.iter().map(|(k, _)| k).collect::<Vec<_>>(), ["b", "a"]);
        let mut p = Obj::new();
        p.insert("a", Doc::Bool(true));
        p.insert("b", Doc::Bool(false));
        assert_eq!(o, p);
        assert_eq!(o.remove("b"), Some(Doc::Bool(false)));
        assert_eq!(o.remove("b"), None);
        assert_eq!(o.len(), 1);
        assert_ne!(o, p);
    }
}
