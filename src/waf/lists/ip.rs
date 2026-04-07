use std::collections::HashMap;
use std::sync::Arc;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use serde::{Deserialize, Serialize};
use wirefilter_engine::{LhsValue, ListDefinition, ListMatcher, Type};

#[derive(Debug)]
pub struct IpListDefinition;

impl ListDefinition for IpListDefinition {
    fn deserialize_matcher<'de>(
        &self,
        _ty: Type,
        deserializer: &mut dyn erased_serde::Deserializer<'de>,
    ) -> Result<Box<dyn ListMatcher>, erased_serde::Error> {
        let matcher = erased_serde::deserialize::<IpListMatcher>(deserializer)?;
        Ok(Box::new(matcher))
    }

    fn new_matcher(&self) -> Box<dyn ListMatcher> {
        Box::new(IpListMatcher::new())
    }
}

pub struct IpListMatcher {
    raw: HashMap<String, Vec<String>>,
    tables: Arc<HashMap<String, IpNetworkTable<()>>>,
}

impl IpListMatcher {
    pub fn new() -> Self {
        Self {
            raw: HashMap::new(),
            tables: Arc::new(HashMap::new()),
        }
    }

    pub fn add_list(&mut self, name: &str, cidrs: &[&str]) {
        let mut table = IpNetworkTable::new();
        for cidr in cidrs {
            match cidr.parse::<IpNetwork>() {
                Ok(network) => {
                    table.insert(network, ());
                }
                Err(e) => {
                    log::error!("IP list '{}': invalid CIDR '{}': {}", name, cidr, e);
                }
            }
        }
        self.raw.insert(
            name.to_string(),
            cidrs.iter().map(|s| s.to_string()).collect(),
        );
        // Rebuild the Arc'd tables map
        let mut tables = HashMap::new();
        for (n, raw_cidrs) in &self.raw {
            let mut t = IpNetworkTable::new();
            for cidr in raw_cidrs {
                if let Ok(network) = cidr.parse::<IpNetwork>() {
                    t.insert(network, ());
                }
            }
            tables.insert(n.clone(), t);
        }
        self.tables = Arc::new(tables);
    }
}

impl Clone for IpListMatcher {
    fn clone(&self) -> Self {
        // Arc clone for tables — O(1), no data copied
        // raw is only used during construction, not per-request
        Self {
            raw: self.raw.clone(),
            tables: Arc::clone(&self.tables),
        }
    }
}

impl std::fmt::Debug for IpListMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpListMatcher")
            .field("lists", &self.raw)
            .finish()
    }
}

impl PartialEq for IpListMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Serialize for IpListMatcher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IpListMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: HashMap<String, Vec<String>> = HashMap::deserialize(deserializer)?;
        let mut tables = HashMap::new();
        for (name, cidrs) in &raw {
            let mut table = IpNetworkTable::new();
            for cidr in cidrs {
                if let Ok(network) = cidr.parse::<IpNetwork>() {
                    table.insert(network, ());
                }
            }
            tables.insert(name.clone(), table);
        }
        Ok(Self {
            raw,
            tables: Arc::new(tables),
        })
    }
}

impl ListMatcher for IpListMatcher {
    fn match_value(&self, list_name: &str, val: &LhsValue<'_>) -> bool {
        let Some(table) = self.tables.get(list_name) else {
            return false;
        };
        let LhsValue::Ip(ip) = *val else {
            return false;
        };
        table.longest_match(ip).is_some()
    }

    fn clear(&mut self) {
        self.raw.clear();
        self.tables = Arc::new(HashMap::new());
    }
}
