//! The only code that changes the machine. Both commands print a plan and do nothing
//! unless run with --apply.

use crate::config::{self, Paths};
use crate::util::{out, run, which};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

const APT_FILE: &str = "/etc/apt/apt.conf.d/52server-watch-upgrades";

pub fn valid_hhmm(s: &str) -> bool {
    let Some((h, m)) = s.split_once(':') else {
        return false;
    };
    matches!((h.parse::<u32>(), m.parse::<u32>()), (Ok(h), Ok(m)) if h < 24 && m < 60 && m.to_string().len() <= 2 && h.to_string().len() <= 2)
}

pub fn apt_conf(reboot_time: &str, with_users: bool) -> String {
    format!(
        "// Written by server-watch harden. Remove this file to undo.\n\
         APT::Periodic::Update-Package-Lists \"1\";\n\
         APT::Periodic::Unattended-Upgrade \"1\";\n\
         Unattended-Upgrade::Automatic-Reboot \"true\";\n\
         Unattended-Upgrade::Automatic-Reboot-Time \"{reboot_time}\";\n\
         Unattended-Upgrade::Automatic-Reboot-WithUsers \"{with_users}\";\n"
    )
}

pub fn harden(apply: bool, reboot_time: &str, with_users: bool) -> Result<(), String> {
    if !valid_hhmm(reboot_time) {
        return Err(format!(
            "--reboot-time must be HH:MM (24h, server time), got {reboot_time:?}"
        ));
    }
    if !which("apt-get") {
        return Err(
            "harden supports apt-based systems (Ubuntu, Debian, Raspberry Pi OS) only".into(),
        );
    }
    let installed = out("dpkg", &["-s", "unattended-upgrades"], 10).is_some();
    let body = apt_conf(reboot_time, with_users);
    println!(
        "server-watch harden: {}\n",
        if apply {
            "applying"
        } else {
            "dry run, nothing will change (add --apply)"
        }
    );
    println!(
        "1. Package unattended-upgrades: {}",
        if installed {
            "installed"
        } else {
            "missing, would run: apt-get install -y unattended-upgrades"
        }
    );
    println!("2. Write {APT_FILE}:\n");
    for l in body.lines() {
        println!("     {l}");
    }
    println!(
        "\n   Effect: security updates install automatically; if one needs a reboot, the server reboots at {reboot_time} server time{}.",
        if with_users { ", even with users logged in" } else { ", but never while someone is logged in (pass --with-users to override)" }
    );
    if !apply {
        return Ok(());
    }
    if !config::is_root() {
        return Err("run as root: sudo server-watch harden --apply".into());
    }
    if !installed {
        let o = run(
            "apt-get",
            &["install", "-y", "unattended-upgrades"],
            Duration::from_secs(300),
        )
        .ok_or("apt-get install timed out")?;
        if !o.ok {
            return Err(format!("apt-get install failed: {}", o.stderr.trim()));
        }
    }
    std::fs::write(APT_FILE, &body).map_err(|e| format!("write {APT_FILE}: {e}"))?;
    let _ = out(
        "systemctl",
        &[
            "enable",
            "--now",
            "apt-daily.timer",
            "apt-daily-upgrade.timer",
        ],
        30,
    );
    let dump = out("apt-config", &["dump"], 10).unwrap_or_default();
    let ok = crate::collect::apt_cfg(&dump, "Unattended-Upgrade::Automatic-Reboot ").as_deref()
        == Some("true")
        && crate::collect::apt_cfg(&dump, "APT::Periodic::Unattended-Upgrade ").as_deref()
            == Some("1");
    if ok {
        println!("\nVerified with apt-config: unattended-upgrades on, automatic reboot on at {reboot_time}.");
        Ok(())
    } else {
        Err("wrote the file but apt-config does not show the settings; check for a later file in /etc/apt/apt.conf.d overriding them".into())
    }
}

fn service(bin: &str, sub: &str, desc: &str) -> String {
    format!(
        "[Unit]\nDescription={desc}\nAfter=network-online.target\n\n\
         [Service]\nType=oneshot\nExecStart={bin} {sub}\nNice=10\nIOSchedulingClass=idle\nTimeoutStartSec=600\n\
         NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\n\
         ReadWritePaths=/var/lib/server-watch /var/log/server-watch\n"
    )
}

fn timer(desc: &str, schedule: &str) -> String {
    format!("[Unit]\nDescription={desc}\n\n[Timer]\n{schedule}\nAccuracySec=30s\nRandomizedDelaySec=20s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")
}

pub const SAMPLE_CONFIG: &str = "# server-watch config. Every setting is optional; these are the defaults.\n\
# name = \"my-server\"          # shown in alerts, default is the hostname\n\
# disable = [\"suid\"]          # skip checks by name\n\
# disk_ignore = [\"/mnt/backup\"]  # mount points the disk check skips\n\
\n\
# [thresholds]\n\
# disk_warn = 80\n# disk_crit = 90\n# mem_avail_warn = 15\n# mem_avail_crit = 8\n\
# swap_used_warn = 80\n# swap_out_warn_pps = 50.0\n# load_warn = 1.5      # load5 per core\n# load_crit = 3.0\n# failed_ssh_warn = 500\n\
\n\
# [notify]\n\
# immediate = \"critical\"      # \"warn\" sends warnings right away too\n\
# reminder_hours = 24\n# escalate_after_hours = 72\n# resolved = true\n";

pub const ENV_TEMPLATE: &str = "# Secrets for server-watch. Keep this file mode 600.\n\
SERVER_WATCH_TELEGRAM_TOKEN=\nSERVER_WATCH_TELEGRAM_CHAT_ID=\n# SERVER_WATCH_WEBHOOK_URL=\n";

pub fn install(p: &Paths, apply: bool, every_min: u32, digest_at: &str) -> Result<(), String> {
    if !valid_hhmm(digest_at) {
        return Err(format!(
            "--digest-at must be HH:MM in UTC, got {digest_at:?}"
        ));
    }
    if !which("systemctl") {
        return Err("install writes systemd units; on macOS or without systemd, schedule `server-watch check` with launchd or cron (see README)".into());
    }
    let bin = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .to_string();
    let check_svc = service(&bin, "check", "server-watch check");
    let digest_svc = service(
        &bin,
        "digest --deep",
        "server-watch daily digest and deep checks",
    );
    let check_tmr = timer(
        "server-watch check every few minutes",
        &format!("OnBootSec=2min\nOnUnitActiveSec={every_min}min"),
    );
    let digest_tmr = timer(
        "server-watch daily digest",
        &format!("OnCalendar=*-*-* {digest_at}:00 UTC"),
    );
    let units = [
        ("server-watch-check.service", check_svc),
        ("server-watch-check.timer", check_tmr),
        ("server-watch-digest.service", digest_svc),
        ("server-watch-digest.timer", digest_tmr),
    ];
    println!(
        "server-watch install: {}\n",
        if apply {
            "applying"
        } else {
            "dry run, nothing will change (add --apply)"
        }
    );
    println!("binary:      {bin}");
    println!(
        "config:      {}   (written only if missing)",
        p.config.display()
    );
    println!(
        "secrets:     {}   (mode 600, written only if missing)",
        p.env.display()
    );
    println!(
        "state/logs:  {}, {}",
        p.state_dir.display(),
        p.log_dir.display()
    );
    println!(
        "schedule:    check every {every_min} min; digest + deep checks daily at {digest_at} UTC\n"
    );
    if !apply {
        for (n, b) in &units {
            println!("--- /etc/systemd/system/{n}\n{b}");
        }
        return Ok(());
    }
    if !config::is_root() {
        return Err("run as root: sudo server-watch install --apply".into());
    }
    for d in [&p.state_dir, &p.log_dir] {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
    }
    if let Some(dir) = p.config.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    if !p.config.exists() {
        std::fs::write(&p.config, SAMPLE_CONFIG).map_err(|e| e.to_string())?;
    }
    if !p.env.exists() {
        std::fs::write(&p.env, ENV_TEMPLATE).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&p.env, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    for (n, b) in &units {
        std::fs::write(format!("/etc/systemd/system/{n}"), b).map_err(|e| format!("{n}: {e}"))?;
    }
    let ctl = |args: &[&str]| -> Result<(), String> {
        let o = run("systemctl", args, Duration::from_secs(30)).ok_or("systemctl timed out")?;
        if o.ok {
            Ok(())
        } else {
            Err(format!("systemctl {}: {}", args.join(" "), o.stderr.trim()))
        }
    };
    ctl(&["daemon-reload"])?;
    ctl(&[
        "enable",
        "--now",
        "server-watch-check.timer",
        "server-watch-digest.timer",
    ])?;
    println!("Installed. Next: put the Telegram token and chat id in {}, then run `server-watch doctor --online`.", p.env.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hhmm_validation() {
        assert!(valid_hhmm("19:00"));
        assert!(valid_hhmm("4:05"));
        assert!(!valid_hhmm("24:00"));
        assert!(!valid_hhmm("19:60"));
        assert!(!valid_hhmm("1900"));
        assert!(!valid_hhmm("19:00; reboot"));
    }

    #[test]
    fn apt_conf_contents() {
        let c = apt_conf("19:00", false);
        assert!(c.contains("Automatic-Reboot \"true\""));
        assert!(c.contains("Automatic-Reboot-Time \"19:00\""));
        assert!(c.contains("WithUsers \"false\""));
    }
}
