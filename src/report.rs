//! Plain-text messages for the terminal, Telegram and the daily digest.

use crate::finding::{Finding, Severity};
use crate::state::State;
use crate::util::iso;
use serde_json::Value;

fn m(metrics: &serde_json::Map<String, Value>, k: &str) -> String {
    match metrics.get(k) {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::String(s)) => s.clone(),
        _ => "?".into(),
    }
}

fn lines(findings: &[&Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            if f.detail.is_empty() {
                format!("{} {}", f.severity.icon(), f.title)
            } else {
                format!("{} {}\n    {}", f.severity.icon(), f.title, f.detail)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn summary(metrics: &serde_json::Map<String, Value>) -> String {
    format!(
        "load {} | RAM used {}% | swap {}% | disk max {}% | updates {} ({} security) | reboot required: {}",
        m(metrics, "load5"),
        m(metrics, "mem_used_pct"),
        m(metrics, "swap_used_pct"),
        m(metrics, "disk_max_pct"),
        m(metrics, "updates_total"),
        m(metrics, "updates_security"),
        m(metrics, "reboot_required"),
    )
}

pub fn alert(host: &str, now: u64, notify: &[Finding], resolved: &[Finding]) -> String {
    let top = notify
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let mut t = format!("{} server-watch on {host}, {}\n", top.icon(), iso(now));
    if !notify.is_empty() {
        let refs: Vec<&Finding> = notify.iter().collect();
        t.push_str(&format!("\n{}\n", lines(&refs)));
    }
    if !resolved.is_empty() {
        t.push_str("\nResolved:\n");
        for f in resolved {
            t.push_str(&format!("✅ {}\n", f.title));
        }
    }
    t
}

pub fn digest(host: &str, now: u64, st: &State) -> String {
    let mut all: Vec<&Finding> = st.findings.values().map(|t| &t.finding).collect();
    all.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    let worst = all.first().map(|f| f.severity);
    let head = match worst {
        Some(Severity::Critical) => "🔴 needs attention",
        Some(Severity::Warn) => "🟠 needs a look",
        _ => "🟢 all clear",
    };
    let mut t = format!(
        "{head}: server-watch daily digest for {host}, {}\n\n{}\n",
        iso(now),
        summary(&st.metrics)
    );
    let sessions = m(&st.metrics, "session_list");
    if sessions != "?" && !sessions.is_empty() {
        t.push_str(&format!("Logged in: {sessions}\n"));
    }
    if all.is_empty() {
        t.push_str("\nNo open findings.\n");
    } else {
        t.push_str(&format!(
            "\n{} open finding(s):\n{}\n",
            all.len(),
            lines(&all)
        ));
    }
    t.push_str(
        "\nThis daily message is the heartbeat: if it stops arriving, the watcher is down.\n",
    );
    t
}

/// Terminal output of `check` and `status`.
pub fn terminal(host: &str, now: u64, st: &State) -> String {
    let mut all: Vec<&Finding> = st.findings.values().map(|t| &t.finding).collect();
    all.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    let mut t = format!(
        "server-watch on {host}, {}\n{}\n\n",
        iso(now),
        summary(&st.metrics)
    );
    if all.is_empty() {
        t.push_str("OK: no findings.\n");
    } else {
        t.push_str(&format!("{} finding(s):\n{}\n", all.len(), lines(&all)));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_lists_findings_and_resolved() {
        let f = Finding::new(
            "a",
            Severity::Critical,
            "New listening port: tcp/4444/public",
            "nc on 0.0.0.0:4444",
        );
        let r = Finding::new("b", Severity::Warn, "Reboot required", "");
        let t = alert("box", 0, &[f], &[r]);
        assert!(t.contains("🔴 server-watch on box"));
        assert!(t.contains("nc on 0.0.0.0:4444"));
        assert!(t.contains("✅ Reboot required"));
    }

    #[test]
    fn digest_all_clear() {
        let t = digest("box", 0, &State::default());
        assert!(t.contains("all clear"));
        assert!(t.contains("heartbeat"));
    }
}
