mod collect;
mod config;
mod finding;
mod install;
mod logs;
mod notify;
mod report;
mod state;
mod util;

use clap::{Parser, Subcommand};
use finding::{Finding, Severity};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "server-watch",
    version,
    about = "Watch a server for pending patches, low disk/RAM and signs of intrusion; alert on Telegram only when something is new or worse."
)]
struct Cli {
    /// Config file (default: /etc/server-watch/config.toml as root, ~/.config/server-watch/config.toml otherwise)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Collect facts, compare to the last run, alert on anything new or worse
    Check {
        /// Also run the slow checks (setuid scan, sshd config, firewall, blocker)
        #[arg(long)]
        deep: bool,
        /// Print machine-readable JSON (for agents and scripts)
        #[arg(long)]
        json: bool,
        /// Do not send alerts
        #[arg(long)]
        no_notify: bool,
        /// Exit 1 on warnings and 2 on criticals
        #[arg(long)]
        strict: bool,
    },
    /// Run a check, then send the daily digest (also the heartbeat)
    Digest {
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        no_notify: bool,
    },
    /// Show the result of the last run without collecting anything
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Accept the current ports, users, keys, cron, units and setuid files as known-good
    Baseline,
    /// Verify tools, config and Telegram are in place
    Doctor {
        /// Also call Telegram getMe to prove the token works
        #[arg(long)]
        online: bool,
    },
    /// Send a test message to every configured channel
    TestAlert,
    /// Show recent log lines (events by default)
    Log {
        #[arg(short, default_value_t = 20)]
        n: usize,
        /// Show telemetry rows instead of events
        #[arg(long)]
        telemetry: bool,
    },
    /// Set up unattended security upgrades with an automatic quiet-hour reboot (dry run unless --apply)
    Harden {
        #[arg(long)]
        apply: bool,
        /// Server-local time of the automatic reboot
        #[arg(long, default_value = "19:00")]
        reboot_time: String,
        /// Reboot even when someone is logged in
        #[arg(long)]
        with_users: bool,
    },
    /// Install the systemd timers (dry run unless --apply)
    Install {
        #[arg(long)]
        apply: bool,
        /// Minutes between checks
        #[arg(long, default_value_t = 10)]
        every: u32,
        /// UTC time of the daily digest
        #[arg(long, default_value = "21:30")]
        digest_at: String,
    },
}

struct App {
    cfg: config::Config,
    paths: config::Paths,
    host: String,
}

struct Outcome {
    st: state::State,
    findings: Vec<Finding>,
    sent: Vec<&'static str>,
    created: Vec<String>,
}

const DEEP_ONLY: [&str; 5] = [
    "sshd_root_login",
    "sshd_password_auth",
    "no_firewall",
    "no_blocker",
    "new:suid:",
];

fn check_once(app: &App, deep: bool, notify_on: bool) -> Result<Outcome, String> {
    let now = util::now();
    let mut st = state::load(&app.paths.state_dir);
    let since = if st.last_run > 0 && now - st.last_run < 6 * 3600 {
        st.last_run
    } else {
        now.saturating_sub(900)
    };
    let ctx = collect::Ctx {
        cfg: &app.cfg,
        deep,
        since,
        now,
        prev: st.counters.clone(),
    };
    let snap = collect::collect(&ctx);

    let (new_facts, created) = state::diff_baseline(&mut st, &snap.facts);
    let mut current = snap.findings;
    current.extend(new_facts);
    if !deep {
        // Slow checks did not run; keep their open findings instead of calling them resolved.
        for (id, t) in &st.findings {
            if DEEP_ONLY.iter().any(|p| id.starts_with(p)) {
                current.push(t.finding.clone());
            }
        }
    }
    let d = state::reconcile(&mut st, current, now, &app.cfg.notify);
    for e in &d.events {
        logs::event(&app.paths.log_dir, e.clone());
    }
    if !created.is_empty() {
        logs::event(
            &app.paths.log_dir,
            json!({"event": "baseline_created", "sets": created}),
        );
    }

    let mut sent = Vec::new();
    if notify_on && (!d.notify.is_empty() || !d.resolved.is_empty()) {
        let text = report::alert(&app.host, now, &d.notify, &d.resolved);
        let worst = d
            .notify
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        match notify::send_all(
            &app.host,
            worst.label(),
            &text,
            json!({"findings": d.notify}),
        ) {
            Ok(ch) => {
                state::mark_notified(&mut st, &d.notify, now);
                logs::event(
                    &app.paths.log_dir,
                    json!({"event": "alert_sent", "channels": ch, "findings": d.notify.iter().map(|f| &f.id).collect::<Vec<_>>(), "resolved": d.resolved.len()}),
                );
                sent = ch;
            }
            Err(e) => {
                logs::event(
                    &app.paths.log_dir,
                    json!({"event": "alert_failed", "error": e}),
                );
                eprintln!("server-watch: alert not delivered: {e}");
            }
        }
    }

    st.last_run = now;
    st.metrics = snap.metrics;
    if snap.counters.is_some() {
        st.counters = snap.counters;
    }
    let mut counts = json!({"critical": 0, "warn": 0, "info": 0});
    for t in st.findings.values() {
        counts[t.finding.severity.label()] =
            json!(counts[t.finding.severity.label()].as_u64().unwrap_or(0) + 1);
    }
    logs::telemetry(
        &app.paths.log_dir,
        json!({"host": app.host, "deep": deep, "metrics": st.metrics, "findings": counts}),
    );
    state::save(&app.paths.state_dir, &st)?;
    let findings = st.findings.values().map(|t| t.finding.clone()).collect();
    Ok(Outcome {
        st,
        findings,
        sent,
        created,
    })
}

fn worst(f: &[Finding]) -> Option<Severity> {
    f.iter().map(|f| f.severity).max()
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let paths = config::paths(cli.config.clone());
    config::load_env_file(&paths.env);
    let cfg = config::load(&paths.config)?;
    let host = if cfg.name.is_empty() {
        util::hostname()
    } else {
        cfg.name.clone()
    };
    let app = App { cfg, paths, host };

    match cli.cmd {
        Cmd::Check {
            deep,
            json,
            no_notify,
            strict,
        } => {
            let o = check_once(&app, deep, !no_notify)?;
            if json {
                let v = json!({
                    "host": app.host, "time": util::iso(util::now()), "deep": deep,
                    "metrics": o.st.metrics, "findings": o.findings,
                    "alerts_sent_via": o.sent, "baseline_created": o.created,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
                );
            } else {
                print!("{}", report::terminal(&app.host, util::now(), &o.st));
                if !o.created.is_empty() {
                    println!(
                        "Baseline recorded for: {}. Future runs alert on anything new.",
                        o.created.join(", ")
                    );
                }
            }
            if strict {
                return Ok(match worst(&o.findings) {
                    Some(Severity::Critical) => ExitCode::from(2),
                    Some(Severity::Warn) => ExitCode::from(1),
                    _ => ExitCode::SUCCESS,
                });
            }
        }
        Cmd::Digest { deep, no_notify } => {
            let mut o = check_once(&app, deep, !no_notify)?;
            let now = util::now();
            let text = report::digest(&app.host, now, &o.st);
            if no_notify {
                print!("{text}");
            } else {
                let sev = worst(&o.findings).unwrap_or(Severity::Info);
                match notify::send_all(
                    &app.host,
                    sev.label(),
                    &text,
                    json!({"findings": o.findings, "metrics": o.st.metrics}),
                ) {
                    Ok(ch) => {
                        o.st.last_digest = now;
                        state::save(&app.paths.state_dir, &o.st)?;
                        logs::event(
                            &app.paths.log_dir,
                            json!({"event": "digest_sent", "channels": ch}),
                        );
                        println!("digest sent via {}", ch.join(", "));
                    }
                    Err(e) => {
                        logs::event(
                            &app.paths.log_dir,
                            json!({"event": "digest_failed", "error": e}),
                        );
                        return Err(format!("digest not delivered: {e}"));
                    }
                }
            }
        }
        Cmd::Status { json } => {
            let st = state::load(&app.paths.state_dir);
            if st.last_run == 0 {
                return Err("no runs yet: run `server-watch check` first".into());
            }
            if json {
                let f: Vec<&Finding> = st.findings.values().map(|t| &t.finding).collect();
                let v = json!({"host": app.host, "last_run": util::iso(st.last_run), "age_seconds": util::now().saturating_sub(st.last_run), "metrics": st.metrics, "findings": f});
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
                );
            } else {
                print!("{}", report::terminal(&app.host, st.last_run, &st));
            }
        }
        Cmd::Baseline => {
            let now = util::now();
            let ctx = collect::Ctx {
                cfg: &app.cfg,
                deep: true,
                since: now,
                now,
                prev: None,
            };
            let snap = collect::collect(&ctx);
            let mut st = state::load(&app.paths.state_dir);
            state::accept_baseline(&mut st, &snap.facts);
            state::save(&app.paths.state_dir, &st)?;
            logs::event(&app.paths.log_dir, json!({"event": "baseline_accepted"}));
            for (set, e) in &snap.facts {
                println!("{set}: {} entries", e.len());
            }
            println!("Baseline saved. Open 'new ...' findings clear on the next check.");
        }
        Cmd::Doctor { online } => return doctor(&app, online),
        Cmd::TestAlert => {
            let text = format!(
                "✅ server-watch test alert from {} at {}. If you can read this, alerts work.",
                app.host,
                util::iso(util::now())
            );
            let ch = notify::send_all(&app.host, "info", &text, json!({"test": true}))?;
            println!("test alert sent via {}", ch.join(", "));
        }
        Cmd::Log { n, telemetry } => {
            let f = if telemetry {
                "telemetry.jsonl"
            } else {
                "events.jsonl"
            };
            for l in logs::tail(&app.paths.log_dir, f, n) {
                println!("{l}");
            }
        }
        Cmd::Harden {
            apply,
            reboot_time,
            with_users,
        } => install::harden(apply, &reboot_time, with_users)?,
        Cmd::Install {
            apply,
            every,
            digest_at,
        } => install::install(&app.paths, apply, every.max(1), &digest_at)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn doctor(app: &App, online: bool) -> Result<ExitCode, String> {
    let mut bad = 0;
    let mut line = |ok: bool, what: String, hint: &str| {
        println!(
            "{} {what}{}",
            if ok { "ok  " } else { "FAIL" },
            if ok || hint.is_empty() {
                String::new()
            } else {
                format!("  -> {hint}")
            }
        );
        if !ok {
            bad += 1;
        }
    };
    println!(
        "server-watch {} on {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        app.host,
        std::env::consts::OS
    );
    let root = config::is_root();
    if cfg!(target_os = "linux") {
        line(
            root,
            "running as root (needed for sshd config, journal, process and port owners)".into(),
            "run with sudo for full coverage",
        );
    }
    println!(
        "note {} config file {} (optional, defaults apply)",
        if app.paths.config.exists() {
            "found"
        } else {
            "none"
        },
        app.paths.config.display()
    );
    line(
        notify::telegram_configured(),
        "Telegram token and chat id set".into(),
        "set SERVER_WATCH_TELEGRAM_TOKEN and SERVER_WATCH_TELEGRAM_CHAT_ID in the env file",
    );
    if online && notify::telegram_configured() {
        match notify::get_me() {
            Ok(u) => line(true, format!("Telegram token valid (bot @{u})"), ""),
            Err(e) => line(false, "Telegram token valid".into(), &e),
        }
    }
    let dir_ok = std::fs::create_dir_all(&app.paths.state_dir).is_ok()
        && std::fs::create_dir_all(&app.paths.log_dir).is_ok();
    line(
        dir_ok,
        format!(
            "state dir {} and log dir {} writable",
            app.paths.state_dir.display(),
            app.paths.log_dir.display()
        ),
        "check permissions",
    );
    let st = state::load(&app.paths.state_dir);
    if st.last_run > 0 {
        let age = util::now().saturating_sub(st.last_run);
        line(
            age < 3600,
            format!("last run {} ago", util::human_age(age)),
            "the timer is not running; `systemctl status server-watch-check.timer`",
        );
    } else {
        line(
            false,
            "has run at least once".into(),
            "run `server-watch check`",
        );
    }
    println!("\nTools (missing ones just skip that check):");
    let tools: &[(&str, &str)] = if cfg!(target_os = "linux") {
        &[
            ("apt-get", "pending updates"),
            ("journalctl", "SSH logins"),
            ("ss", "listening ports"),
            ("systemctl", "units, failed services"),
            ("needrestart", "services on old libraries"),
            ("sshd", "sshd config"),
            ("ufw", "firewall"),
            ("crowdsec", "blocker"),
            ("fail2ban-client", "blocker"),
            ("lynis", "hardening score"),
            ("rkhunter", "rootkit scan"),
            ("aide", "file integrity"),
        ]
    } else {
        &[
            ("lsof", "listening ports"),
            ("softwareupdate", "OS updates"),
            ("vm_stat", "memory"),
        ]
    };
    for (t, why) in tools {
        println!(
            "  {} {t:16} {why}",
            if util::which(t) { "yes" } else { "no " }
        );
    }
    Ok(if bad == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("server-watch: {e}");
            ExitCode::from(1)
        }
    }
}
