//! A minimal order-preserving JSON document used to rewrite Claude Code settings.
//!
//! We cannot enable serde_json's `preserve_order` feature: Cargo unifies features across
//! the workspace and other crates rely on `serde_json::Map` being sorted. This type keeps
//! object members in file order, rejects duplicate keys while parsing, and serializes
//! back in the same order through serde_json's pretty printer.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::Number;

/// Message of the parse error raised for a duplicate key.
pub(crate) const DUPLICATE_KEY_MSG: &str = "duplicate key";

/// A JSON value whose objects keep member order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Doc {
    Null,
    Bool(bool),
    Number(Number),
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
            Doc::Number(n) => n.serialize(s),
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
        Ok(Doc::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Doc, E> {
        Ok(Doc::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Doc, E> {
        Number::from_f64(v)
            .map(Doc::Number)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_round_trips() {
        let src = r#"{"z":1,"a":{"y":[1,-2,2.5,true,null,"s"],"b":{}},"m":[]}"#;
        let d: Doc = serde_json::from_str(src).unwrap();
        assert_eq!(serde_json::to_string(&d).unwrap(), src);
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
