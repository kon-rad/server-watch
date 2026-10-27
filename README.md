# server-watch

**A small, fast watchdog for your servers. It checks patches, disk, RAM and signs of intrusion every few minutes, and messages you on Telegram only when something is new or getting worse.**

One static Rust binary. No daemon, no database, no agent to babysit: a systemd timer runs it, it compares what it sees to the last run, writes a log, and exits. It runs on Ubuntu, Debian and Raspberry Pi OS servers, and (with fewer checks) on macOS.

```
$ server-watch check
server-watch on web-1, 2026-10-27 07:50 UTC
load 1.83 | RAM used 49% | swap 57% | disk max 38% | updates 63 (4 security) | reboot required: true

3 finding(s):
🔴 New listening port: tcp/4444/public
    nc on 0.0.0.0:4444
🟠 Reboot required to finish updates
    Packages: linux-image-6.8.0-110-generic
🟠 4 security update(s) pending (63 total)
    Including: libssl3, openssh-server, curl, tar. Run `apt upgrade`, or enable unattended-upgrades.
```

## Why this exists

Mature free tools already do the hard parts: unattended-upgrades patches, CrowdSec and fail2ban block, Lynis audits, rkhunter and AIDE look for rootkits and changed files. None of them gives you one status report or a message on your phone when something changes. server-watch is that missing layer. It does not replace those tools; it tells you when they are missing and reads what they leave behind.

Three design rules:

1. **Alert on change, not on state.** "63 updates pending" every morning teaches you to ignore it. server-watch alerts when a reboot becomes required, a new port opens, a new user or SSH key appears, or disk crosses a line. Everything else waits for the daily digest.
2. **The monitor should not share fate with what it monitors.** It is a timer, not a long-running process an attacker can kill quietly, and it has its own Telegram path with no dependency on your app or agent stack. A daily heartbeat message means silence says "broken", not "fine".
3. **Read-only by default.** It never installs, restarts or reboots anything unless you run `harden` or `install` with `--apply`, and both show a dry run first.

## What it looks for

Findings have a severity: `info`, `warn` or `critical`. Critical findings are sent right away; warnings go in the daily digest unless they stay open for 72 hours, when they escalate to critical.

| Check (name for `disable`) | Looks for | Severity |
|---|---|---|
| `reboot` | `/var/run/reboot-required` present, with the packages that need it | warn |
| `updates` | Pending security updates (`apt-get -s`, no root or lock needed); macOS updates in deep mode | warn |
| `unattended` | unattended-upgrades off, or automatic reboot off (so the reboot flag never clears) | warn |
| `needrestart` | Services still running old libraries (if `needrestart` is installed) | info |
| `disk` | Each real filesystem at 80% (warn) and 90% (critical) | warn / critical |
| `memory` | Available RAM under 15% (warn) or 8% (critical) | warn / critical |
| `swap` | Swap over 80% full, or actively paging out between runs, with the **top swap-using processes** named | warn |
| `load` | 5-minute load per core over 1.5 (warn) or 3.0 (critical) | warn / critical |
| `failed_units` | systemd units in a failed state | warn |
| `ports` | A **new listening port** compared with the baseline: public is critical, loopback-only is info | critical / info |
| `users` | A new account that can log in, or a new member of `sudo`, `admin` or `wheel` | critical |
| `authkeys` | A new or changed SSH `authorized_keys` entry for any user | critical |
| `ssh_logins` | A successful SSH login from a user and address never seen before; a spike of failed attempts | warn |
| `cron` | A new or modified crontab or `/etc/cron.*` file | warn |
| `units` | A newly enabled systemd unit or timer | warn |
| `processes` | A process whose executable lives in `/tmp`, `/dev/shm` or `/var/tmp` | critical |
| `suid` (deep) | A new setuid-root file anywhere on the root filesystem | critical |
| `sshd_config` (deep) | Root login or password login enabled | warn |
| `firewall` (deep) | No ufw or nftables rules found | info |
| `blocker` (deep) | Neither CrowdSec nor fail2ban running | info |

"New" means not in the **baseline**. The first run records the baseline silently. After that, anything new is a finding until you run `server-watch baseline` to accept it. Logins are events, not state: you get one alert for a new source and it is then treated as known.

**Deep checks** are slower (the setuid scan walks the whole filesystem). The daily digest runs them; the 10-minute check does not.

It also records a hardening score from Lynis if `/var/log/lynis-report.dat` exists.

## Install

Prebuilt binaries for Linux (x86_64, arm64 for Raspberry Pi) and macOS (Apple silicon and Intel):

```sh
curl -fsSL https://raw.githubusercontent.com/kon-rad/server-watch/main/install.sh | sh
```

The script verifies the release checksum before installing. Or from source:

```sh
cargo install server-watch
```

### Set up a server in four commands

```sh
sudo server-watch harden --apply      # unattended security upgrades + automatic reboot at 19:00 server time
sudo server-watch install --apply     # systemd timers: check every 10 min, digest + deep checks daily
sudoedit /etc/server-watch/env        # add your Telegram token and chat id (next section)
sudo server-watch doctor --online     # proves the token works and everything is in place
```

Run `harden` and `install` without `--apply` first to see exactly what they will write.

**Automatic reboot** is what clears the "restart required" flag that otherwise sits there for months. Choose a quiet hour with `--reboot-time HH:MM`. By default the server does not reboot while a user is logged in; pass `--with-users` if sessions are always open (for example a long-running agent session), otherwise the reboot would never happen.

## Telegram

server-watch only needs to *send* messages, so any Telegram bot works, including one you already have.

1. Make a bot with [@BotFather](https://t.me/BotFather) (or reuse one) and copy its token.
2. Send your bot any message, then find your chat id: `curl -s https://api.telegram.org/bot<TOKEN>/getUpdates` and read `message.chat.id`. For a group, add the bot to the group and use the group's id.
3. Put both in `/etc/server-watch/env` (mode 600; `install` creates it):

```sh
SERVER_WATCH_TELEGRAM_TOKEN=123456:ABC...
SERVER_WATCH_TELEGRAM_CHAT_ID=123456789
```

4. `server-watch test-alert` sends a test message.

Secrets are read from the environment or that env file, never from the config file, and error messages are scrubbed so the token never reaches the logs. Prefer a bot used only for alerts, so they still arrive if the rest of your stack is down.

**Webhook:** set `SERVER_WATCH_WEBHOOK_URL` and every alert is also POSTed as JSON (`host`, `severity`, `text`, `data`). Use it for Slack, ntfy, n8n or anything else.

## How it runs

```
systemd timer (every 10 min)
  -> server-watch check
       collect facts (disk, RAM, ports, users, keys, cron ...)
       compare with baseline + previous findings
       -> telemetry.jsonl   one metrics row per run
       -> events.jsonl      finding opened / escalated / resolved, alert sent
       -> Telegram / webhook only for new or worse critical findings

systemd timer (daily, 21:30 UTC)
  -> server-watch digest --deep
       deep checks, then one summary message: your heartbeat
```

Alert rules, in order:

- A **new critical** finding is sent immediately, once. It is repeated every 24 hours while it stays open.
- A **warn** appears in the daily digest. After 72 hours open it escalates to critical and is sent.
- When a finding you were alerted about clears, you get a short "resolved" line.
- If Telegram is unreachable, the alert is retried on the next run; nothing is marked as sent until it was.

State lives in `/var/lib/server-watch/state.json` (mode 600). Logs are in `/var/log/server-watch/`, rotated at 5 MB. Run as a normal user and everything goes under `~/.config/server-watch` and `~/.local/state/server-watch`.

The systemd units run with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only` and `PrivateTmp`, write only to their own state and log directories, and run at low CPU and IO priority.

## Logging and telemetry

Both files are JSON lines, easy to `jq`, tail or ship anywhere.

```sh
server-watch log -n 20                 # recent events
server-watch log --telemetry -n 20     # recent metrics rows
jq -r '[.time, .metrics.load5, .metrics.mem_used_pct, .metrics.swap_used_pct] | @tsv' /var/log/server-watch/telemetry.jsonl
```

Telemetry rows carry: load (1, 5, 15 minutes), cores, RAM and swap use, swap-out rate, disk use per mount, pending and security updates, reboot required, failed SSH events, logged-in sessions, public listening ports, and the count of open findings by severity.

## Use it from an agent

Every command has a machine-readable form, so an AI agent (Claude Code, Hermes, Codex, any tool that runs shell commands) can use it as its interface to the server:

```sh
server-watch status --json              # last result, no collection, instant
server-watch check --json --no-notify   # fresh check without sending an alert
server-watch check --strict             # exit code 0 ok, 1 warn, 2 critical, for scripts
```

[`agent/SKILL.md`](agent/SKILL.md) is a ready-made skill: copy it to `.claude/skills/server-watch/SKILL.md` (Claude Code) or your agent's skills folder. It tells the agent to run the check, read the findings in severity order, work out whether a "new" item was you before calling it an attack, and never change the machine, accept a baseline or print the token without your approval.

A good setup: the timer is the watcher (it works when the agent is down), the daily digest goes to Telegram, and the agent is for the follow-up ("why is swap at 57%?", "what is that new port?").

## Other machines

- **Raspberry Pi and other Debian-family boxes:** same binary (arm64 build), same checks, same install.
- **macOS (M-series and Intel Macs):** disk, RAM, swap, load, listening ports, SSH keys, logged-in users, and OS updates in deep mode. Linux-only checks are skipped. Schedule it with the launchd templates in [`contrib/`](contrib/): copy them to `~/Library/LaunchAgents/` and `launchctl bootstrap gui/$(id -u) <file>`. Put the Telegram variables in `~/.config/server-watch/env`.
- **Any machine, no scheduler:** `server-watch check` from cron works too.

## CLI

| Command | What it does |
|---|---|
| `check [--deep] [--json] [--no-notify] [--strict]` | Collect, compare, log, alert |
| `digest [--deep] [--no-notify]` | Run a check, then send the daily digest |
| `status [--json]` | Show the last result without collecting |
| `baseline` | Accept current ports, users, keys, cron, units and setuid files as known-good |
| `doctor [--online]` | Check tools, config, state and Telegram |
| `test-alert` | Send a test message |
| `log [-n N] [--telemetry]` | Tail the event or telemetry log |
| `harden [--apply] [--reboot-time HH:MM] [--with-users]` | unattended-upgrades and automatic reboot |
| `install [--apply] [--every MIN] [--digest-at HH:MM]` | systemd timers, config and env files |

Global: `--config <file>`.

## Configuration

Everything is optional. The file is `/etc/server-watch/config.toml` (or `~/.config/server-watch/config.toml`).

```toml
name = "web-1"                 # shown in alerts, default is the hostname
disable = ["suid"]             # skip checks by name (see the table above)
disk_ignore = ["/mnt/backup"]  # mount points the disk check skips

[thresholds]
disk_warn = 80
disk_crit = 90
mem_avail_warn = 15            # percent of RAM still available
mem_avail_crit = 8
swap_used_warn = 80
swap_out_warn_pps = 50.0       # pages per second swapped out between runs
load_warn = 1.5                # 5-minute load per core
load_crit = 3.0
failed_ssh_warn = 500          # failed SSH log events per run window

[notify]
immediate = "critical"         # "warn" sends warnings right away too
reminder_hours = 24
escalate_after_hours = 72
resolved = true
```

Set `SERVER_WATCH_DIR=/some/dir` to relocate config, state and logs (useful for testing).

## What it is not

It is not an intrusion prevention system, an antivirus or a replacement for patching discipline. It cannot see an attacker who is careful to leave no trace in what it checks, and it runs on the machine it watches, so a root-level compromise can tamper with it. Pair it with a blocker (CrowdSec or fail2ban), file integrity (AIDE), rootkit scans (rkhunter) and, for fleets of three or more machines, a full platform such as [Wazuh](https://wazuh.com). Think of server-watch as the smoke alarm: cheap, always on, and loud when something changes.

## Roadmap

- Adapters that read Lynis, rkhunter, AIDE and CrowdSec output when installed
- A `--remote user@host` mode to check a machine over SSH
- A launchd installer (`install` currently writes systemd units only)
- Optional ntfy and email channels

## Development

```sh
cargo test           # unit tests for every parser and the alert logic
cargo clippy --all-targets -- -D warnings
```

Collectors are small functions in `src/collect.rs` that read one thing and return metrics, findings or facts; parsers are pure functions with tests. Alert decisions live in `src/state.rs` and are pure too. Pull requests that add a collector should add a parser test with real command output.

## License

MIT. See [LICENSE](LICENSE).
