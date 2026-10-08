use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use wirefilter_engine::{LhsValue, ListDefinition, ListMatcher, Type};

#[derive(Debug)]
pub struct BytesListDefinition;

impl ListDefinition for BytesListDefinition {
    fn deserialize_matcher<'de>(
        &self,
        _ty: Type,
        deserializer: &mut dyn erased_serde::Deserializer<'de>,
    ) -> Result<Box<dyn ListMatcher>, erased_serde::Error> {
        let matcher = erased_serde::deserialize::<BytesListMatcher>(deserializer)?;
        Ok(Box::new(matcher))
    }

    fn new_matcher(&self) -> Box<dyn ListMatcher> {
        Box::new(BytesListMatcher::new())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BytesListMode {
    /// The whole value must equal one of the items.
    Exact,
    /// Any item may appear anywhere inside the value (Aho-Corasick,
    /// ASCII case-insensitive).
    Substring,
}

/// A list as configured. Items are a set, so two lists with the same items
/// compare and serialize the same regardless of order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BytesListSpec {
    mode: BytesListMode,
    items: BTreeSet<String>,
}

#[derive(Clone)]
enum CompiledBytesList {
    Exact(HashSet<Vec<u8>>),
    Substring(AhoCorasick),
}

impl CompiledBytesList {
    fn build(name: &str, spec: &BytesListSpec) -> Result<Self, String> {
        match spec.mode {
            BytesListMode::Exact => Ok(Self::Exact(
                spec.items.iter().map(|s| s.as_bytes().to_vec()).collect(),
            )),
            BytesListMode::Substring => {
                // Skip empty patterns: they would match every value.
                let patterns: Vec<&[u8]> = spec
                    .items
                    .iter()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.as_bytes())
                    .collect();
                if patterns.len() != spec.items.len() {
                    log::warn!("Substring list '{name}': ignoring an empty item");
                }
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                    .map(Self::Substring)
                    .map_err(|e| format!("substring list '{name}': {e}"))
            }
        }
    }

    #[inline]
    fn matches(&self, haystack: &[u8]) -> bool {
        match self {
            Self::Exact(set) => set.contains(haystack),
            Self::Substring(ac) => ac.is_match(haystack),
        }
    }
}

/// The configured lists and their compiled forms, shared by every request
/// context so cloning the matcher is one `Arc` clone.
#[derive(Default)]
struct Lists {
    raw: HashMap<String, BytesListSpec>,
    compiled: HashMap<String, CompiledBytesList>,
}

impl Lists {
    fn compile(raw: HashMap<String, BytesListSpec>) -> Result<Self, String> {
        let compiled = raw
            .iter()
            .map(|(name, spec)| Ok((name.clone(), CompiledBytesList::build(name, spec)?)))
            .collect::<Result<_, String>>()?;
        Ok(Self { raw, compiled })
    }
}

#[derive(Clone)]
pub struct BytesListMatcher {
    lists: Arc<Lists>,
}

impl BytesListMatcher {
    pub fn new() -> Self {
        Self {
            lists: Arc::new(Lists::default()),
        }
    }

    /// Adds (or replaces) a list with the given matching mode. Fails when
    /// the list cannot be compiled, so a misconfigured list is never
    /// silently empty.
    pub fn add_list(
        &mut self,
        name: &str,
        mode: BytesListMode,
        items: &[&str],
    ) -> Result<(), String> {
        let spec = BytesListSpec {
            mode,
            items: items.iter().map(|s| s.to_string()).collect(),
        };
        let compiled = CompiledBytesList::build(name, &spec)?;
        let mut lists = Lists {
            raw: self.lists.raw.clone(),
            compiled: self.lists.compiled.clone(),
        };
        lists.raw.insert(name.to_string(), spec);
        lists.compiled.insert(name.to_string(), compiled);
        self.lists = Arc::new(lists);
        Ok(())
    }
}

impl std::fmt::Debug for BytesListMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesListMatcher")
            .field("lists", &self.lists.raw)
            .finish()
    }
}

impl PartialEq for BytesListMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.lists.raw == other.lists.raw
    }
}

impl Serialize for BytesListMatcher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.lists.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BytesListMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: HashMap<String, BytesListSpec> = HashMap::deserialize(deserializer)?;
        let lists = Lists::compile(raw).map_err(serde::de::Error::custom)?;
        Ok(Self {
            lists: Arc::new(lists),
        })
    }
}

impl ListMatcher for BytesListMatcher {
    fn match_value(&self, list_name: &str, val: &LhsValue<'_>) -> bool {
        let Some(list) = self.lists.compiled.get(list_name) else {
            return false;
        };
        let LhsValue::Bytes(bytes) = val else {
            return false;
        };
        list.matches(bytes)
    }

    fn clear(&mut self) {
        self.lists = Arc::new(Lists::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> LhsValue<'_> {
        LhsValue::Bytes(s.as_bytes().into())
    }

    fn matcher(lists: &[(&str, BytesListMode, &[&str])]) -> BytesListMatcher {
        let mut m = BytesListMatcher::new();
        for (name, mode, items) in lists {
            m.add_list(name, *mode, items).unwrap();
        }
        m
    }

    #[test]
    fn exact_matches_whole_value_only() {
        let m = matcher(&[("ua", BytesListMode::Exact, &["sqlmap", "nikto"])]);
        assert!(m.match_value("ua", &bytes("sqlmap")));
        assert!(m.match_value("ua", &bytes("nikto")));
        assert!(!m.match_value("ua", &bytes("sqlmap/1.0")));
        assert!(!m.match_value("ua", &bytes("SQLMAP")));
        assert!(!m.match_value("ua", &bytes("")));
    }

    #[test]
    fn substring_matches_anywhere() {
        let m = matcher(&[("ua", BytesListMode::Substring, &["sqlmap", "nikto"])]);
        assert!(m.match_value("ua", &bytes("sqlmap")));
        assert!(m.match_value("ua", &bytes("Mozilla sqlmap/1.0")));
        assert!(m.match_value("ua", &bytes("xxniktoxx")));
        assert!(!m.match_value("ua", &bytes("curl/8.0")));
        assert!(!m.match_value("ua", &bytes("")));
    }

    #[test]
    fn substring_is_ascii_case_insensitive() {
        let m = matcher(&[("ua", BytesListMode::Substring, &["SqlMap"])]);
        assert!(m.match_value("ua", &bytes("sqlmap/1.0")));
        assert!(m.match_value("ua", &bytes("Mozilla SQLMAP")));
        assert!(!m.match_value("ua", &bytes("sql map")));
    }

    #[test]
    fn substring_ignores_empty_patterns() {
        let m = matcher(&[("l", BytesListMode::Substring, &["", "abc"])]);
        assert!(!m.match_value("l", &bytes("zzz")));
        assert!(m.match_value("l", &bytes("zabcz")));
    }

    #[test]
    fn empty_substring_list_never_matches() {
        let m = matcher(&[("l", BytesListMode::Substring, &[])]);
        assert!(!m.match_value("l", &bytes("anything")));
    }

    #[test]
    fn works_on_non_utf8_bytes() {
        let m = matcher(&[
            ("s", BytesListMode::Substring, &["abc"]),
            ("e", BytesListMode::Exact, &["abc"]),
        ]);
        let raw: &[u8] = &[0xff, b'a', b'b', b'c', 0xfe];
        assert!(m.match_value("s", &LhsValue::Bytes(raw.into())));
        assert!(!m.match_value("e", &LhsValue::Bytes(raw.into())));
    }

    #[test]
    fn unknown_list_and_wrong_type_do_not_match() {
        let m = matcher(&[("l", BytesListMode::Exact, &["x"])]);
        assert!(!m.match_value("missing", &bytes("x")));
        assert!(!m.match_value("l", &LhsValue::Int(1)));
    }

    #[test]
    fn adding_a_list_keeps_the_others_and_replaces_by_name() {
        let mut m = matcher(&[("a", BytesListMode::Exact, &["1"])]);
        m.add_list("b", BytesListMode::Substring, &["2"]).unwrap();
        m.add_list("a", BytesListMode::Exact, &["3"]).unwrap();
        assert!(!m.match_value("a", &bytes("1")));
        assert!(m.match_value("a", &bytes("3")));
        assert!(m.match_value("b", &bytes("x2x")));
    }

    #[test]
    fn item_order_and_duplicates_do_not_matter() {
        let a = matcher(&[("l", BytesListMode::Exact, &["x", "y", "x"])]);
        let b = matcher(&[("l", BytesListMode::Exact, &["y", "x"])]);
        assert_eq!(a, b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    #[test]
    fn serde_round_trip_preserves_modes() {
        let m = matcher(&[
            ("exact", BytesListMode::Exact, &["a", "b"]),
            ("sub", BytesListMode::Substring, &["needle"]),
        ]);
        let json = serde_json::to_string(&m).unwrap();
        let back: BytesListMatcher = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
        assert!(back.match_value("exact", &bytes("a")));
        assert!(!back.match_value("exact", &bytes("ab")));
        assert!(back.match_value("sub", &bytes("hay needle stack")));
    }

    #[test]
    fn clear_removes_everything() {
        let mut m = matcher(&[("l", BytesListMode::Substring, &["x"])]);
        m.clear();
        assert!(!m.match_value("l", &bytes("x")));
    }
}
