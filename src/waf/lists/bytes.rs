use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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

pub struct BytesListMatcher {
    lists: Arc<HashMap<String, HashSet<String>>>,
}

impl Clone for BytesListMatcher {
    fn clone(&self) -> Self {
        Self {
            lists: Arc::clone(&self.lists),
        }
    }
}

impl std::fmt::Debug for BytesListMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesListMatcher")
            .field("lists", &self.lists.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PartialEq for BytesListMatcher {
    fn eq(&self, other: &Self) -> bool {
        *self.lists == *other.lists
    }
}

impl Serialize for BytesListMatcher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.lists.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BytesListMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let lists: HashMap<String, HashSet<String>> = HashMap::deserialize(deserializer)?;
        Ok(Self {
            lists: Arc::new(lists),
        })
    }
}

impl BytesListMatcher {
    pub fn new() -> Self {
        Self {
            lists: Arc::new(HashMap::new()),
        }
    }

    pub fn add_list(&mut self, name: &str, items: &[&str]) {
        let set: HashSet<String> = items.iter().map(|s| s.to_string()).collect();
        let mut lists = (*self.lists).clone();
        lists.insert(name.to_string(), set);
        self.lists = Arc::new(lists);
    }
}

impl ListMatcher for BytesListMatcher {
    fn match_value(&self, list_name: &str, val: &LhsValue<'_>) -> bool {
        let Some(set) = self.lists.get(list_name) else {
            return false;
        };
        let LhsValue::Bytes(bytes) = val else {
            return false;
        };
        let Ok(s) = std::str::from_utf8(bytes) else {
            return false;
        };
        set.contains(s)
    }

    fn clear(&mut self) {
        self.lists = Arc::new(HashMap::new());
    }
}
