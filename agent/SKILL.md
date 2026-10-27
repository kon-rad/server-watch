---
name: server-watch
description: Check a server's health and security with the server-watch CLI, read the findings, explain them and propose fixes. Use when asked whether the server is healthy, patched, under attack, low on disk or RAM, or what the last alert meant.
---

# server-watch

`server-watch` is a small CLI installed on the machine. A systemd timer runs it every 10 minutes and a daily digest goes to Telegram. This skill is the interface for an agent: run it, read the result, explain it, propose fixes.

## Run it

- Current state without collecting: `server-watch status --json`
- Fresh check, no alert sent: `server-watch check --json --no-notify`
- Include the slow checks (setuid scan, sshd config, firewall, blocker): add `--deep`
- Recent history: `server-watch log -n 30` (events), `server-watch log --telemetry -n 30` (metrics rows)
- Setup problems: `server-watch doctor --online`

All JSON has `host`, `metrics` and `findings`. Each finding has `id`, `severity` (info, warn, critical), `title`, `detail`.

## Read it

1. Start with critical findings, then warn. Info is context.
2. A finding whose id starts with `new:` means something appeared that was not in the baseline: a listening port, a user, an SSH key, a cron entry, an enabled unit, a setuid file, an SSH login source. Find out whether the owner did it before calling it an attack. Check who is logged in (`metrics.session_list`) and the recent `log` events.
3. `swap_paging` and `swap_full` list the top swap users in `detail`.
4. Say what you ran and what the output was. Never claim a fix worked without re-running `check`.

## Act on it

Read-only by default. Do not change the machine unless the owner approves:

- Accept a known-good change: `server-watch baseline` (tell the owner what it accepts).
- Patch and auto-reboot setup: `server-watch harden` shows the plan; `--apply` needs the owner's yes because it enables an automatic reboot.
- Never reboot, kill processes or edit sshd config on your own.

## Never

- Never print the Telegram token or the env file (`/etc/server-watch/env`).
- Never run `baseline` to silence a finding you have not explained.
