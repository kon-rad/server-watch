//! Append-only JSON-lines logs: events (findings opened, escalated, resolved, alerts sent)
//! and telemetry (one metrics row per run). Rotated at 5 MB, one old copy kept.

use crate::util::{iso, now};
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;

const MAX_BYTES: u64 = 5 * 1024 * 1024;

pub fn append(dir: &Path, file: &str, mut row: Value) {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(file);
    if std::fs::metadata(&path)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = std::fs::rename(&path, dir.join(format!("{file}.1")));
    }
    if let Some(o) = row.as_object_mut() {
        o.insert("ts".into(), json!(now()));
        o.insert("time".into(), json!(iso(now())));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{row}");
    }
}

pub fn event(dir: &Path, row: Value) {
    append(dir, "events.jsonl", row);
}

pub fn telemetry(dir: &Path, row: Value) {
    append(dir, "telemetry.jsonl", row);
}

pub fn tail(dir: &Path, file: &str, n: usize) -> Vec<String> {
    let s = std::fs::read_to_string(dir.join(file)).unwrap_or_default();
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_tail() {
        let d = std::env::temp_dir().join(format!("sw-test-{}", std::process::id()));
        for i in 0..5 {
            event(&d, json!({"event": "opened", "i": i}));
        }
        let t = tail(&d, "events.jsonl", 2);
        assert_eq!(t.len(), 2);
        assert!(t[1].contains("\"i\":4"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
