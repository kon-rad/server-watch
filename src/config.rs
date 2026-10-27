//! Config (TOML, every field optional) and where files live.

use crate::finding::Severity;
use crate::util;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Thresholds {
    pub disk_warn: u64,
    pub disk_crit: u64,
    /// Percent of RAM still available.
    pub mem_avail_warn: u64,
    pub mem_avail_crit: u64,
    pub swap_used_warn: u64,
    /// Pages swapped out per second between two runs.
    pub swap_out_warn_pps: f64,
    /// load5 divided by cores.
    pub load_warn: f64,
    pub load_crit: f64,
    /// sshd failed-auth log lines per run window.
    pub failed_ssh_warn: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            disk_warn: 80,
            disk_crit: 90,
            mem_avail_warn: 15,
            mem_avail_crit: 8,
            swap_used_warn: 80,
            swap_out_warn_pps: 50.0,
            load_warn: 1.5,
            load_crit: 3.0,
            failed_ssh_warn: 500,
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct NotifyCfg {
    /// Lowest severity sent right away: "warn" or "critical". Everything else waits for the digest.
    pub immediate: String,
    /// Re-send an open alert after this many hours.
    pub reminder_hours: u64,
    /// A warn that stays open this long becomes critical.
    pub escalate_after_hours: u64,
    /// Tell me when an alert I was sent clears.
    pub resolved: bool,
    /// RAM, load and paging spikes must show in this many runs in a row before an alert.
    pub confirm_runs: u32,
}

impl Default for NotifyCfg {
    fn default() -> Self {
        Self {
            immediate: "critical".into(),
            reminder_hours: 24,
            escalate_after_hours: 72,
            resolved: true,
            confirm_runs: 2,
        }
    }
}

impl NotifyCfg {
    pub fn immediate_min(&self) -> Severity {
        if self.immediate.eq_ignore_ascii_case("warn") {
            Severity::Warn
        } else {
            Severity::Critical
        }
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Config {
    /// Name shown in alerts. Default: the hostname.
    pub name: String,
    pub thresholds: Thresholds,
    pub notify: NotifyCfg,
    /// Check names to skip, e.g. ["suid", "firewall"]. See README for the list.
    pub disable: Vec<String>,
    /// Mount points (prefix match) the disk check skips, e.g. read-only disk images.
    pub disk_ignore: Vec<String>,
}

impl Config {
    pub fn enabled(&self, check: &str) -> bool {
        !self.disable.iter().any(|d| d == check)
    }
}

pub struct Paths {
    pub config: PathBuf,
    pub env: PathBuf,
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
}

pub fn is_root() -> bool {
    util::out("id", &["-u"], 3)
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

pub fn paths(config_override: Option<PathBuf>) -> Paths {
    let (cfg_dir, state_dir, log_dir) = if let Ok(d) = std::env::var("SERVER_WATCH_DIR") {
        let d = PathBuf::from(d);
        (d.clone(), d.join("state"), d.join("log"))
    } else if is_root() {
        (
            PathBuf::from("/etc/server-watch"),
            PathBuf::from("/var/lib/server-watch"),
            PathBuf::from("/var/log/server-watch"),
        )
    } else {
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
        let state = home.join(".local/state/server-watch");
        (home.join(".config/server-watch"), state.clone(), state)
    };
    Paths {
        config: config_override.unwrap_or_else(|| cfg_dir.join("config.toml")),
        env: cfg_dir.join("env"),
        state_dir,
        log_dir,
    }
}

pub fn load(path: &PathBuf) -> Result<Config, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).map_err(|e| format!("{}: {e}", path.display())),
        Err(_) => Ok(Config::default()),
    }
}

/// Load KEY=VALUE lines from the env file without overriding variables already set.
pub fn load_env_file(path: &PathBuf) {
    let Ok(s) = std::fs::read_to_string(path) else {
        return;
    };
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if std::env::var_os(k.trim()).is_none() && !v.is_empty() {
                std::env::set_var(k.trim(), v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse_from_empty() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.thresholds.disk_crit, 90);
        assert!(c.enabled("suid"));
    }

    #[test]
    fn partial_override() {
        let c: Config = toml::from_str("disable=[\"suid\"]\n[notify]\nimmediate=\"warn\"").unwrap();
        assert!(!c.enabled("suid"));
        assert_eq!(c.notify.immediate_min(), Severity::Warn);
        assert_eq!(c.notify.reminder_hours, 24);
    }
}
