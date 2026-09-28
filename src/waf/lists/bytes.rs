use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, MatchKind};
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

/// A set of phrases matched as case-insensitive substrings (ModSecurity `@pm`
/// semantics). The automaton is derived from `phrases`; only the phrases are
/// serialized, and the automaton is rebuilt on deserialization.
#[derive(Clone)]
struct PhraseSet {
    phrases: Vec<String>,
    ac: AhoCorasick,
}

impl PhraseSet {
    fn new(phrases: Vec<String>) -> Self {
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&phrases)
            .expect("aho-corasick build");
        Self { phrases, ac }
    }
}

/// Matcher for `Type::Bytes` lists, referenced as `x in $name`.
///
/// Holds two kinds of list, distinguished by name: `equality` lists match when
/// the whole value equals a member (`kind: bytes`/`string`), and `substring`
/// lists match when any phrase occurs anywhere in the value (`kind: phrases`,
/// ModSecurity `@pm`/`@pmFromFile`).
pub struct BytesListMatcher {
    equality: Arc<HashMap<String, HashSet<String>>>,
    substring: Arc<HashMap<String, PhraseSet>>,
}

impl Clone for BytesListMatcher {
    fn clone(&self) -> Self {
        Self {
            equality: Arc::clone(&self.equality),
            substring: Arc::clone(&self.substring),
        }
    }
}

impl std::fmt::Debug for BytesListMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesListMatcher")
            .field("equality", &self.equality.keys().collect::<Vec<_>>())
            .field("substring", &self.substring.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PartialEq for BytesListMatcher {
    fn eq(&self, other: &Self) -> bool {
        *self.equality == *other.equality
            && self.substring.len() == other.substring.len()
            && self
                .substring
                .iter()
                .all(|(k, v)| other.substring.get(k).is_some_and(|o| o.phrases == v.phrases))
    }
}

/// Serialized form: equality lists as-is, substring lists as their phrase
/// vectors (the automaton is rebuilt on load).
#[derive(Serialize, Deserialize)]
struct BytesListMatcherRepr {
    equality: HashMap<String, HashSet<String>>,
    #[serde(default)]
    substring: HashMap<String, Vec<String>>,
}

impl Serialize for BytesListMatcher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        BytesListMatcherRepr {
            equality: (*self.equality).clone(),
            substring: self
                .substring
                .iter()
                .map(|(k, v)| (k.clone(), v.phrases.clone()))
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BytesListMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = BytesListMatcherRepr::deserialize(deserializer)?;
        Ok(Self {
            equality: Arc::new(repr.equality),
            substring: Arc::new(
                repr.substring
                    .into_iter()
                    .map(|(k, phrases)| (k, PhraseSet::new(phrases)))
                    .collect(),
            ),
        })
    }
}

impl BytesListMatcher {
    pub fn new() -> Self {
        Self {
            equality: Arc::new(HashMap::new()),
            substring: Arc::new(HashMap::new()),
        }
    }

    /// Add an equality list: `x in $name` matches when `x` equals a member.
    pub fn add_list(&mut self, name: &str, items: &[&str]) {
        let set: HashSet<String> = items.iter().map(|s| s.to_string()).collect();
        let mut lists = (*self.equality).clone();
        lists.insert(name.to_string(), set);
        self.equality = Arc::new(lists);
    }

    /// Add a substring (phrases) list: `x in $name` matches when any phrase is
    /// a case-insensitive substring of `x`.
    pub fn add_phrase_list(&mut self, name: &str, items: &[&str]) {
        let set = PhraseSet::new(items.iter().map(|s| s.to_string()).collect());
        let mut lists = (*self.substring).clone();
        lists.insert(name.to_string(), set);
        self.substring = Arc::new(lists);
    }
}

impl ListMatcher for BytesListMatcher {
    fn match_value(&self, list_name: &str, val: &LhsValue<'_>) -> bool {
        let LhsValue::Bytes(bytes) = val else {
            return false;
        };
        // Substring lists match on raw bytes (no UTF-8 requirement).
        if let Some(phrases) = self.substring.get(list_name) {
            return phrases.ac.is_match(&bytes[..]);
        }
        if let Some(set) = self.equality.get(list_name) {
            return std::str::from_utf8(bytes).is_ok_and(|s| set.contains(s));
        }
        false
    }

    fn clear(&mut self) {
        self.equality = Arc::new(HashMap::new());
        self.substring = Arc::new(HashMap::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher() -> BytesListMatcher {
        let mut m = BytesListMatcher::new();
        m.add_list("exact", &["gzip", "br"]);
        m.add_phrase_list("scanners", &["sqlmap", "nikto"]);
        m
    }

    fn matches(m: &BytesListMatcher, list: &str, v: &[u8]) -> bool {
        m.match_value(list, &LhsValue::Bytes(v.to_vec().into()))
    }

    #[test]
    fn equality_list_needs_whole_value() {
        let m = matcher();
        assert!(matches(&m, "exact", b"gzip"));
        assert!(!matches(&m, "exact", b"gzip, br")); // not an exact member
    }

    #[test]
    fn phrase_list_matches_substring_case_insensitively() {
        let m = matcher();
        assert!(matches(&m, "scanners", b"Mozilla/5.0 sqlmap/1.5"));
        assert!(matches(&m, "scanners", b"NIKTO scanner")); // case-insensitive
        assert!(!matches(&m, "scanners", b"a normal user agent"));
    }

    #[test]
    fn phrase_list_works_on_non_utf8() {
        let m = matcher();
        let mut v = vec![0xff, 0xfe];
        v.extend_from_slice(b"sqlmap");
        assert!(matches(&m, "scanners", &v));
    }

    #[test]
    fn unknown_list_does_not_match() {
        assert!(!matches(&matcher(), "nope", b"anything"));
    }

    #[test]
    fn serde_round_trips_both_kinds() {
        let m = matcher();
        let json = serde_json::to_string(&m).unwrap();
        let back: BytesListMatcher = serde_json::from_str(&json).unwrap();
        assert!(matches(&back, "exact", b"gzip"));
        assert!(matches(&back, "scanners", b"x sqlmap y"));
        assert_eq!(m, back);
    }
}
