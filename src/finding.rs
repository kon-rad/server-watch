use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Critical => "critical",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Warn => "🟠",
            Severity::Critical => "🔴",
        }
    }
}

/// One thing that needs attention. `id` is stable between runs so the same problem is one alert.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            detail: detail.into(),
        }
    }
}

/// Named sets of things that should not change without you knowing (ports, users, keys...).
/// entry key -> detail shown in the alert.
pub type Facts = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub ts: u64,
    pub pswpin: u64,
    pub pswpout: u64,
}

#[derive(Default)]
pub struct Snapshot {
    pub metrics: Map<String, Value>,
    pub findings: Vec<Finding>,
    pub facts: Facts,
    pub counters: Option<Counters>,
}

impl Snapshot {
    pub fn metric(&mut self, k: &str, v: impl Into<Value>) {
        self.metrics.insert(k.to_string(), v.into());
    }
    pub fn add(&mut self, f: Finding) {
        self.findings.push(f);
    }
    pub fn fact(&mut self, set: &str, key: impl Into<String>, detail: impl Into<String>) {
        self.facts
            .entry(set.to_string())
            .or_default()
            .insert(key.into(), detail.into());
    }
    /// Declare a fact set as collected even if it is empty, so removals and first-run baselines work.
    pub fn fact_set(&mut self, set: &str) {
        self.facts.entry(set.to_string()).or_default();
    }
}
