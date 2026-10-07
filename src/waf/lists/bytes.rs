use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BytesListSpec {
    mode: BytesListMode,
    items: Vec<String>,
}

enum CompiledBytesList {
    Exact(HashSet<Vec<u8>>),
    Substring(AhoCorasick),
}

impl CompiledBytesList {
    fn build(name: &str, spec: &BytesListSpec) -> Self {
        match spec.mode {
            BytesListMode::Exact => {
                Self::Exact(spec.items.iter().map(|s| s.as_bytes().to_vec()).collect())
            }
            BytesListMode::Substring => {
                // Skip empty patterns: they would match every value.
                let patterns: Vec<&[u8]> = spec
                    .items
                    .iter()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.as_bytes())
                    .collect();
                if patterns.len() != spec.items.len() {
                    log::warn!(
                        "Substring list '{}': ignoring {} empty item(s)",
                        name,
                        spec.items.len() - patterns.len()
                    );
                }
                let ac = AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                    .unwrap_or_else(|e| {
                        log::error!(
                            "Substring list '{}': failed to build automaton: {}",
                            name,
                            e
                        );
                        let none: [&[u8]; 0] = [];
                        AhoCorasick::new(none).expect("empty automaton")
                    });
                Self::Substring(ac)
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

pub struct BytesListMatcher {
    raw: HashMap<String, BytesListSpec>,
    compiled: Arc<HashMap<String, CompiledBytesList>>,
}

impl BytesListMatcher {
    pub fn new() -> Self {
        Self {
            raw: HashMap::new(),
            compiled: Arc::new(HashMap::new()),
        }
    }

    /// Adds (or replaces) a list with the given matching mode.
    pub fn add_list(&mut self, name: &str, mode: BytesListMode, items: &[&str]) {
        self.raw.insert(
            name.to_string(),
            BytesListSpec {
                mode,
                items: items.iter().map(|s| s.to_string()).collect(),
            },
        );
        self.compiled = Arc::new(Self::compile(&self.raw));
    }

    fn compile(raw: &HashMap<String, BytesListSpec>) -> HashMap<String, CompiledBytesList> {
        raw.iter()
            .map(|(name, spec)| (name.clone(), CompiledBytesList::build(name, spec)))
            .collect()
    }
}

impl Clone for BytesListMatcher {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            compiled: Arc::clone(&self.compiled),
        }
    }
}

impl std::fmt::Debug for BytesListMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesListMatcher")
            .field("lists", &self.raw)
            .finish()
    }
}

impl PartialEq for BytesListMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Serialize for BytesListMatcher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BytesListMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: HashMap<String, BytesListSpec> = HashMap::deserialize(deserializer)?;
        let compiled = Arc::new(Self::compile(&raw));
        Ok(Self { raw, compiled })
    }
}

impl ListMatcher for BytesListMatcher {
    fn match_value(&self, list_name: &str, val: &LhsValue<'_>) -> bool {
        let Some(list) = self.compiled.get(list_name) else {
            return false;
        };
        let LhsValue::Bytes(bytes) = val else {
            return false;
        };
        list.matches(bytes)
    }

    fn clear(&mut self) {
        self.raw.clear();
        self.compiled = Arc::new(HashMap::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> LhsValue<'_> {
        LhsValue::Bytes(s.as_bytes().into())
    }

    #[test]
    fn exact_matches_whole_value_only() {
        let mut m = BytesListMatcher::new();
        m.add_list("ua", BytesListMode::Exact, &["sqlmap", "nikto"]);
        assert!(m.match_value("ua", &bytes("sqlmap")));
        assert!(m.match_value("ua", &bytes("nikto")));
        assert!(!m.match_value("ua", &bytes("sqlmap/1.0")));
        assert!(!m.match_value("ua", &bytes("SQLMAP")));
        assert!(!m.match_value("ua", &bytes("")));
    }

    #[test]
    fn substring_matches_anywhere() {
        let mut m = BytesListMatcher::new();
        m.add_list("ua", BytesListMode::Substring, &["sqlmap", "nikto"]);
        assert!(m.match_value("ua", &bytes("sqlmap")));
        assert!(m.match_value("ua", &bytes("Mozilla sqlmap/1.0")));
        assert!(m.match_value("ua", &bytes("xxniktoxx")));
        assert!(!m.match_value("ua", &bytes("curl/8.0")));
        assert!(!m.match_value("ua", &bytes("")));
    }

    #[test]
    fn substring_is_ascii_case_insensitive() {
        let mut m = BytesListMatcher::new();
        m.add_list("ua", BytesListMode::Substring, &["SqlMap"]);
        assert!(m.match_value("ua", &bytes("sqlmap/1.0")));
        assert!(m.match_value("ua", &bytes("Mozilla SQLMAP")));
        assert!(!m.match_value("ua", &bytes("sql map")));
    }

    #[test]
    fn substring_ignores_empty_patterns() {
        let mut m = BytesListMatcher::new();
        m.add_list("l", BytesListMode::Substring, &["", "abc"]);
        assert!(!m.match_value("l", &bytes("zzz")));
        assert!(m.match_value("l", &bytes("zabcz")));
    }

    #[test]
    fn empty_substring_list_never_matches() {
        let mut m = BytesListMatcher::new();
        m.add_list("l", BytesListMode::Substring, &[]);
        assert!(!m.match_value("l", &bytes("anything")));
    }

    #[test]
    fn works_on_non_utf8_bytes() {
        let mut m = BytesListMatcher::new();
        m.add_list("s", BytesListMode::Substring, &["abc"]);
        m.add_list("e", BytesListMode::Exact, &["abc"]);
        let raw: &[u8] = &[0xff, b'a', b'b', b'c', 0xfe];
        assert!(m.match_value("s", &LhsValue::Bytes(raw.into())));
        assert!(!m.match_value("e", &LhsValue::Bytes(raw.into())));
    }

    #[test]
    fn unknown_list_and_wrong_type_do_not_match() {
        let mut m = BytesListMatcher::new();
        m.add_list("l", BytesListMode::Exact, &["x"]);
        assert!(!m.match_value("missing", &bytes("x")));
        assert!(!m.match_value("l", &LhsValue::Int(1)));
    }

    #[test]
    fn serde_round_trip_preserves_modes() {
        let mut m = BytesListMatcher::new();
        m.add_list("exact", BytesListMode::Exact, &["a", "b"]);
        m.add_list("sub", BytesListMode::Substring, &["needle"]);
        let json = serde_json::to_string(&m).unwrap();
        let back: BytesListMatcher = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
        assert!(back.match_value("exact", &bytes("a")));
        assert!(!back.match_value("exact", &bytes("ab")));
        assert!(back.match_value("sub", &bytes("hay needle stack")));
    }

    #[test]
    fn clear_removes_everything() {
        let mut m = BytesListMatcher::new();
        m.add_list("l", BytesListMode::Substring, &["x"]);
        m.clear();
        assert!(!m.match_value("l", &bytes("x")));
    }
}
