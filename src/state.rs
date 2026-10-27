//! Saved state between runs: open findings, the known-good baseline, counters.
//! `reconcile` decides what is worth a message; it is pure so it can be tested.

use crate::config::NotifyCfg;
use crate::finding::{Counters, Facts, Finding, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tracked {
    pub finding: Finding,
    pub first_seen: u64,
    pub last_seen: u64,
    pub last_notified: u64,
    pub notified_sev: Option<Severity>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    pub last_run: u64,
    pub last_digest: u64,
    pub findings: BTreeMap<String, Tracked>,
    pub baseline: BTreeMap<String, BTreeSet<String>>,
    pub counters: Option<Counters>,
    pub metrics: Map<String, Value>,
}

pub fn load(dir: &Path) -> State {
    let p = dir.join("state.json");
    match std::fs::read_to_string(&p) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| {
            let _ = std::fs::rename(&p, dir.join("state.json.corrupt"));
            State::default()
        }),
        Err(_) => State::default(),
    }
}

pub fn save(dir: &Path, st: &State) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = dir.join("state.json.tmp");
    let body = serde_json::to_string_pretty(st).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    std::fs::rename(&tmp, dir.join("state.json")).map_err(|e| e.to_string())
}

#[derive(Default)]
pub struct Decision {
    pub notify: Vec<Finding>,
    pub resolved: Vec<Finding>,
    pub events: Vec<Value>,
}

/// Update tracked findings from the current run and decide what to tell the owner.
/// Notified timestamps are NOT set here; call `mark_notified` after a successful send.
pub fn reconcile(st: &mut State, current: Vec<Finding>, now: u64, cfg: &NotifyCfg) -> Decision {
    let mut d = Decision::default();
    let mut seen = BTreeSet::new();
    let min = cfg.immediate_min();
    for mut f in current {
        seen.insert(f.id.clone());
        let t = st.findings.entry(f.id.clone()).or_insert_with(|| {
            d.events
                .push(json!({"event":"opened","id":f.id,"severity":f.severity,"title":f.title}));
            Tracked {
                finding: f.clone(),
                first_seen: now,
                last_seen: now,
                last_notified: 0,
                notified_sev: None,
            }
        });
        let age = now.saturating_sub(t.first_seen);
        if f.severity == Severity::Warn && age >= cfg.escalate_after_hours * 3600 {
            f.severity = Severity::Critical;
            f.title = format!("{} (open {})", f.title, crate::util::human_age(age));
        }
        if f.severity > t.finding.severity {
            d.events
                .push(json!({"event":"escalated","id":f.id,"severity":f.severity,"title":f.title}));
        }
        t.finding = f.clone();
        t.last_seen = now;
        let worse = t.notified_sev.is_none_or(|n| f.severity > n);
        let remind = t.notified_sev.is_some()
            && now.saturating_sub(t.last_notified) >= cfg.reminder_hours * 3600;
        if f.severity >= min && (worse || remind) {
            d.notify.push(f);
        }
    }
    let gone: Vec<String> = st
        .findings
        .keys()
        .filter(|k| !seen.contains(*k))
        .cloned()
        .collect();
    for k in gone {
        if let Some(t) = st.findings.remove(&k) {
            d.events
                .push(json!({"event":"resolved","id":t.finding.id,"title":t.finding.title}));
            if cfg.resolved && t.notified_sev.is_some() {
                d.resolved.push(t.finding);
            }
        }
    }
    d
}

pub fn mark_notified(st: &mut State, sent: &[Finding], now: u64) {
    for f in sent {
        if let Some(t) = st.findings.get_mut(&f.id) {
            t.notified_sev = Some(f.severity);
            t.last_notified = now;
        }
    }
}

/// How a fact set turns into findings when something new appears.
fn policy(set: &str, key: &str) -> (&'static str, Severity, bool) {
    match set {
        "ports" if key.ends_with("/public") => ("listening port", Severity::Critical, false),
        "ports" => ("local listening port", Severity::Info, false),
        "users" => ("login user", Severity::Critical, false),
        "admins" => ("admin group member", Severity::Critical, false),
        "authkeys" => ("SSH authorized key", Severity::Critical, false),
        "suid" => ("setuid file", Severity::Critical, false),
        "cron" => ("cron entry", Severity::Warn, false),
        "units" => ("enabled systemd unit", Severity::Warn, false),
        // An event, not a state: alert once, then treat the source as known.
        "ssh_sources" => ("SSH login source", Severity::Warn, true),
        _ => ("item", Severity::Warn, false),
    }
}

/// Compare facts to the baseline. Returns findings for new entries and the names of
/// fact sets that were baselined silently for the first time.
pub fn diff_baseline(st: &mut State, facts: &Facts) -> (Vec<Finding>, Vec<String>) {
    let mut out = Vec::new();
    let mut created = Vec::new();
    for (set, entries) in facts {
        let Some(known) = st.baseline.get_mut(set) else {
            st.baseline
                .insert(set.clone(), entries.keys().cloned().collect());
            created.push(set.clone());
            continue;
        };
        for (key, detail) in entries {
            if known.contains(key) {
                continue;
            }
            let (label, sev, learn) = policy(set, key);
            out.push(Finding::new(
                format!("new:{set}:{key}"),
                sev,
                format!("New {label}: {key}"),
                detail.clone(),
            ));
            if learn {
                known.insert(key.clone());
            }
        }
    }
    (out, created)
}

/// Accept the current facts as known-good.
pub fn accept_baseline(st: &mut State, facts: &Facts) {
    for (set, entries) in facts {
        st.baseline
            .insert(set.clone(), entries.keys().cloned().collect());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NotifyCfg {
        NotifyCfg::default()
    }
    fn f(id: &str, s: Severity) -> Finding {
        Finding::new(id, s, id, "d")
    }

    #[test]
    fn critical_notifies_once_then_stays_quiet() {
        let mut st = State::default();
        let d = reconcile(&mut st, vec![f("a", Severity::Critical)], 1000, &cfg());
        assert_eq!(d.notify.len(), 1);
        mark_notified(&mut st, &d.notify, 1000);
        let d = reconcile(&mut st, vec![f("a", Severity::Critical)], 1600, &cfg());
        assert!(d.notify.is_empty());
    }

    #[test]
    fn reminder_after_hours() {
        let mut st = State::default();
        let d = reconcile(&mut st, vec![f("a", Severity::Critical)], 0, &cfg());
        mark_notified(&mut st, &d.notify, 0);
        let d = reconcile(&mut st, vec![f("a", Severity::Critical)], 24 * 3600, &cfg());
        assert_eq!(d.notify.len(), 1);
    }

    #[test]
    fn warn_waits_for_digest_then_escalates() {
        let mut st = State::default();
        let d = reconcile(&mut st, vec![f("w", Severity::Warn)], 0, &cfg());
        assert!(d.notify.is_empty());
        let d = reconcile(&mut st, vec![f("w", Severity::Warn)], 72 * 3600, &cfg());
        assert_eq!(d.notify.len(), 1);
        assert_eq!(d.notify[0].severity, Severity::Critical);
        assert!(d.notify[0].title.contains("open 3d"));
    }

    #[test]
    fn failed_send_retries() {
        let mut st = State::default();
        let d = reconcile(&mut st, vec![f("a", Severity::Critical)], 0, &cfg());
        assert_eq!(d.notify.len(), 1); // send "fails": mark_notified not called
        let d = reconcile(&mut st, vec![f("a", Severity::Critical)], 600, &cfg());
        assert_eq!(d.notify.len(), 1);
    }

    #[test]
    fn resolved_only_if_it_was_sent() {
        let mut st = State::default();
        let d = reconcile(
            &mut st,
            vec![f("a", Severity::Critical), f("b", Severity::Warn)],
            0,
            &cfg(),
        );
        mark_notified(&mut st, &d.notify, 0);
        let d = reconcile(&mut st, vec![], 60, &cfg());
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.resolved[0].id, "a");
        assert!(st.findings.is_empty());
    }

    #[test]
    fn baseline_first_run_is_silent_then_flags_new() {
        let mut st = State::default();
        let mut facts = Facts::new();
        facts
            .entry("ports".into())
            .or_default()
            .insert("tcp/22/public".into(), "sshd".into());
        let (found, created) = diff_baseline(&mut st, &facts);
        assert!(found.is_empty());
        assert_eq!(created, vec!["ports"]);
        facts
            .get_mut("ports")
            .unwrap()
            .insert("tcp/4444/public".into(), "nc".into());
        facts
            .get_mut("ports")
            .unwrap()
            .insert("tcp/631/local".into(), "cupsd".into());
        let (found, _) = diff_baseline(&mut st, &facts);
        assert_eq!(found.len(), 2);
        assert!(found
            .iter()
            .any(|x| x.severity == Severity::Critical && x.id == "new:ports:tcp/4444/public"));
        assert!(found.iter().any(|x| x.severity == Severity::Info));
        accept_baseline(&mut st, &facts);
        assert!(diff_baseline(&mut st, &facts).0.is_empty());
    }

    #[test]
    fn ssh_sources_learned_after_first_alert() {
        let mut st = State::default();
        let mut facts = Facts::new();
        facts.entry("ssh_sources".into()).or_default();
        diff_baseline(&mut st, &facts);
        facts
            .get_mut("ssh_sources")
            .unwrap()
            .insert("root@1.2.3.4".into(), "publickey".into());
        assert_eq!(diff_baseline(&mut st, &facts).0.len(), 1);
        assert_eq!(diff_baseline(&mut st, &facts).0.len(), 0);
    }
}
