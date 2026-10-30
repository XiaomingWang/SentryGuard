<p align="center">
  <img src="assets/logo.svg" alt="SentryGuard logo" width="128" height="128">
</p>
<h1 align="center">SentryGuard</h1>
<p align="center"><strong>Guard the gate. Stop brute-force attacks.</strong></p>

SentryGuard is a lightweight Linux tool that helps protect servers against brute-force password attacks. It monitors failed SSH logins and blocks IP addresses that exceed a configurable threshold, with support for both IPv4 and IPv6.

## Why SentryGuard?

Brute-force login attempts are a common security concern for anyone running a cloud server. Although established tools such as DenyHosts and Fail2ban already address this problem, I wanted something that felt simpler to configure and manage. That may reflect my own familiarity with those tools, but it led me to create SentryGuard: a small, standalone executable with a straightforward YAML configuration and command-line interface.

## How It Works

SentryGuard counts failed SSH password attempts from each IP within a configurable time window and records bans in SQLite. By default, it enforces bans through both an available firewall backend and its own entries in `/etc/hosts.deny`. Either strategy can also be enabled on its own.

The `/etc/hosts.deny` file applies only to services that use TCP Wrappers, and existing `hosts.allow` rules can take precedence. Modern SSH deployments generally require firewall enforcement for effective connection blocking. If firewall enforcement is selected but no backend is available, SentryGuard logs a warning and continues recording bans; it updates `hosts.deny` only if that strategy is enabled. Firewall command failures are reported explicitly.

## Enforcement Strategies

Set `enforcement` in `/etc/SentryGuard/config.yaml` to select the enforcement strategies:

Commands always load `/etc/SentryGuard/config.yaml` unless `--config PATH` is supplied. Editing `./config.yaml` does not change that default. To use a configuration in the current directory, run `sudo ./sentryguard ban 10.20.100.101 --config ./config.yaml`. With `enforcement: [hosts_deny]`, the firewall-unavailable warning is suppressed.

```yaml
# Both strategies (default, including when the key is omitted)
enforcement: [firewall, hosts_deny]
# Firewall only
# enforcement: [firewall]
# TCP Wrappers only
# enforcement: [hosts_deny]
```

Restart the service after changing this setting. Disabled strategies have their SentryGuard-managed rules removed, while ban records remain in SQLite. Cleanup requires the original firewall tool to be available; otherwise its tracked rules are retained for a later cleanup attempt. Other applications' rules and unmarked hosts.deny entries are preserved. An empty list or unknown strategy is rejected. Firewall selection remains automatic when enabled: active firewalld, active ufw, nftables, then iptables.

## Build

Requires Go 1.22 or newer. From this directory:

```sh
go mod download
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o sentryguard .
```

To build both install packages on an x86-64 or ARM64 Linux host, also install `dpkg-deb` and `rpmbuild`, then run `sh scripts/build-packages.sh`. The packages are written to `dist/`. RPM builds use the v4 RPM format and gzip payload for compatibility with older RPM-based distributions.

## Install packages

For a ZIP distribution without DEB/RPM, see the manual installation instructions below.

The packages install `/usr/bin/sentryguard`, `/etc/SentryGuard/config.yaml`, and `/usr/lib/systemd/system/sentryguard.service`. The SQLite database is created at runtime at `/etc/SentryGuard/sentryguard.db`; it is not shipped in the package. The configuration file is preserved across upgrades. The service is registered on install but is not started or enabled automatically.

If an earlier manual installation left `/usr/local/sbin/sentryguard` on the host, check `command -v sentryguard` after installing the package. Remove the old manual copy when ready so shell commands use `/usr/bin/sentryguard`; the packaged service always uses `/usr/bin/sentryguard`.

Ubuntu/Debian:

```sh
sudo apt install ./dist/sentryguard_0.12.0_amd64.deb
sudo systemctl enable --now sentryguard
sudo systemctl status sentryguard
```

CentOS/RHEL with systemd (7 or newer):

```sh
sudo dnf install ./dist/sentryguard-0.12.0-1.x86_64.rpm
sudo systemctl enable --now sentryguard
sudo systemctl status sentryguard
```

On a systemd host with the `service` wrapper installed, both command styles manage the same unit:

```sh
sudo service sentryguard start
sudo service sentryguard stop
sudo service sentryguard restart
sudo service sentryguard status
sudo systemctl start sentryguard
sudo systemctl stop sentryguard
sudo systemctl restart sentryguard
sudo systemctl status sentryguard
```

For CentOS/RHEL 7, use `yum install` instead of `dnf install`.

Install at least one supported firewall tool for effective connection blocking if none is present. For example:

```sh
sudo apt-get install nftables
# On CentOS/RHEL: sudo dnf install nftables
```

Run the service as root: it needs journal access, permission to update `/etc/hosts.deny`, and firewall administration. Keep the config and database writable only by root.

## Manual installation (ZIP)

The ZIP includes the Linux executable, `install.sh`, `uninstall.sh`, example YAML, systemd unit, README, and VERSION. It does not require Go on the destination host. Use the archive matching the host architecture; the provided build is for Linux amd64. The host needs systemd/journald for service management and login monitoring.

```sh
unzip dist/sentryguard-0.12.0-linux-amd64.zip
cd sentryguard-0.12.0-linux-amd64
sudo sh install.sh
sudo systemctl enable --now sentryguard
sudo systemctl status sentryguard
```

Manual installation uses `/usr/local/bin/sentryguard`, `/etc/systemd/system/sentryguard.service`, `/etc/SentryGuard/config.yaml`, and `/usr/local/share/sentryguard/`. Existing configuration and database are preserved. Installation registers the service without starting it; after upgrading, restart it with `sudo systemctl restart sentryguard`. The `service sentryguard start|stop|restart|status` wrapper can also be used on hosts that provide it. Remove a DEB/RPM installation with its package manager before switching to this method.

To uninstall, stop the service and optionally clear bans first. `reset` requires its normal explicit confirmation. Uninstall itself preserves the configuration, database, and existing firewall/hosts.deny bans, just as package removal does; retained bans will no longer expire automatically after uninstall.

```sh
sudo systemctl stop sentryguard
sudo sentryguard reset
sudo sh /usr/local/share/sentryguard/uninstall.sh
# Or: sudo sh uninstall.sh from the extracted archive
```

Build a new ZIP with `sh scripts/build-zip.sh` (requires Go and Python 3). The archive is written to `dist/`. For staging only, both installation scripts accept the `DESTDIR` environment variable; staging skips systemctl actions.

## Whitelist

Set `whitelist` in `/etc/SentryGuard/config.yaml` to a YAML list of IPv4/IPv6 addresses or CIDR networks, then restart the service:

```yaml
whitelist:
  - "192.0.2.10"
  - "192.168.0.0/24"
  - "2001:db8::10"
```

Whitelisted IPs, including every address within a listed CIDR network, are ignored during live counting and historical scans. `sentryguard ban IP` rejects a whitelisted address. On service restart, any existing bans and pending failures for those IPs are removed from SQLite, and SentryGuard removes its matching entries from `/etc/hosts.deny` and its managed firewall rules. IPv4-mapped IPv6 addresses are treated as the same IPv4 address. Invalid entries prevent the service from starting and show the offending value in the error. The whitelist affects only restrictions managed by SentryGuard; it does not override other firewall rules.

## Ban protocols

Set `ban_protocols` to a YAML list to choose which incoming connections banned IPs cannot make. The default is `[SSH]` (TCP 22); `SSHD` and `SFTP` are aliases. For example, `ban_protocols: [SSH, FTP]` blocks TCP ports 22 and 21, while `ban_protocols: [ALL]` blocks all incoming packets from banned IPs. `ALL` must be used alone. Other supported names are `FTPS` (990), `TELNET` (23), `RDP` (3389), `HTTP` (80), `HTTPS` (443), `SMTP` (25), `IMAP` (143), `POP3` (110), `MYSQL` (3306), and `POSTGRESQL` (5432). Restart the service after editing the config; existing bans then use the new rule set.

The setting controls enforcement only. Automatic detection and `scan` still read SSH password failures from the systemd journal. It does not parse FTP or other services' login logs. `/etc/hosts.deny` uses matching daemon names for SSH and FTP when relevant. The selected firewall backend enforces protocol-specific port rules. FTP data connections use additional ports; `[ALL]` blocks those too.

### Firewall backend selection

SentryGuard checks firewalld with `firewall-cmd --state` and ufw with `ufw status`; only active managers are selected. It then checks for `nft`, followed by `iptables` (and `ip6tables` for IPv6). This order avoids writing native rules alongside an active firewall manager. It never enables a firewall manager on its own. `ban_protocols` defaults to `[SSH]`, so bans block TCP port 22 unless configured otherwise.

For firewalld, SentryGuard uses its direct interface and writes both runtime and permanent rules. The direct interface is deprecated by firewalld but remains supported on older distributions; future firewalld releases may require a different integration. For ufw, it adds managed deny rules; for iptables it adds comment-marked INPUT rules. The SQLite `firewall_rules` table records those rules so unban, expiry, service restart, and backend changes can remove stale entries. iptables rules are checked and restored after reboot. nftables continues to use SentryGuard's own table and sets. A removed firewall executable can prevent immediate cleanup of rules previously created through it; SentryGuard retains their records for cleanup when that tool is available again. If `iptables` is selected for an IPv6 ban, `ip6tables` is required and a missing command produces a clear error.

## How failed logins are detected

SentryGuard does **not** call `lastb` or read `/var/log/btmp`. It polls the systemd journal with `journalctl --no-pager --quiet -o json -t sshd -t sshd-session` every `poll_interval` (10 seconds by default). On the first run of this version, including upgrades from older releases, it scans the previous 72 hours of available journal entries once. It then stores the journal cursor in SQLite and uses `--after-cursor` on later polls, including after a restart. A manual `ban --since ... [--until ...]` scans that journal time range separately and leaves the live cursor unchanged. See the [journalctl manual](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html) for the journal filters, JSON output, and cursor behavior.

For each journal entry, the program reads `SYSLOG_IDENTIFIER` and `MESSAGE`. It counts only SSH messages matching `Failed password for ... from IP port ...`, including the `Failed password for invalid user ...` form. The source IP must be a valid non-loopback IPv4 or IPv6 address. It does not currently count public-key failures, standalone `Invalid user` messages, or generic PAM authentication failures. A matching `Accepted password`, `Accepted publickey`, or `Accepted keyboard-interactive/pam` message clears that IP's failure count.

The SQLite `failure_events` table holds journal timestamps for each IP's recent failures. For each new failure, the program counts that IP's entries within the preceding `failure_window` (4 hours by default), using the time recorded in the journal. When the count reaches `threshold` (5 by default), the IP is added to `bans` and the configured enforcement files/rules are synchronized. A successful SSH login clears the IP's pending failures. The old `failures` table from earlier versions is no longer used; existing bans are preserved, and the one-time three-day scan rebuilds failure counts from available journal entries. Historical `ban --since` scans apply the same `failure_window` inside the selected period without altering live failure counters.

If an existing `/etc/SentryGuard/config.yaml` still says `failure_window: 10m`, that explicit value remains in effect after upgrading. Set it to `4h` and restart the service to use the new default window.

The SSH server must write these messages to the systemd journal. To check what SentryGuard can see on the target host, run `sudo journalctl --no-pager -o cat -t sshd -t sshd-session --since today` and look for `Failed password` lines. A host that logs SSH failures only to a text file, with no corresponding journal entries, will not be detected by this version.

## Use

```sh
sentryguard -h
sentryguard --version
sentryguard -v
sudo sentryguard list
sudo sentryguard list --limit 20
sudo sentryguard list --ip 203.0.113.7
sudo sentryguard list --ip '203.0.113.' --limit 20
sudo sentryguard export --format csv --output ./bans.csv
sudo sentryguard import --format csv --input ./bans.csv
sudo sentryguard reset
sudo sentryguard list --since '2026-10-29 00:00:00' --limit 20
sudo sentryguard scan
sudo sentryguard scan --since '2026-10-29 00:00:00' --until '2026-10-30 00:00:00' --limit 20
sudo sentryguard scan --count
sudo sentryguard scan --count --ip 203.0.113.4
sudo sentryguard list --since '2026-10-29 00:00:00'
sudo sentryguard list --until '2026-10-30 00:00:00'
sudo sentryguard list --since '2026-10-29 00:00:00' --until '2026-10-30 00:00:00'
sudo sentryguard ban 203.0.113.4
sudo sentryguard ban 203.0.113.4 --protocols SSH,FTP
sudo sentryguard unban 203.0.113.4 --protocols FTP
sudo sentryguard unban 203.0.113.4 --protocols ALL
sudo sentryguard ban 2001:db8::4 --duration 60d
sudo sentryguard ban --ip 203.0.113.4
sudo sentryguard ban --since '2026-10-29 00:00:00'
sudo sentryguard ban --since '2026-10-29 00:00:00' --until '2026-10-30 00:00:00'
sudo sentryguard ban --since 2026-10-29 --until 2026-10-30 --duration 60d
sudo sentryguard unban 203.0.113.4
sudo sentryguard run --config /path/to/config.yaml
```

The default config and database are `/etc/SentryGuard/config.yaml` and `/etc/SentryGuard/sentryguard.db`. A manual `ban` without `--duration` is permanent, even when `ban_duration` in YAML sets a finite duration for automatic bans. Permanent bans store the expiry as `9999-12-31T00:00:00Z`. Duration values accept Go units such as `10s`, `30m`, `24h`, plus whole days such as `60d`. On first start, the monitor scans the previous three days of available SSH journal entries; on restart it resumes from its saved journal cursor. A successful SSH login resets that IP's failure counter. The monitor checks for expired bans each poll. Changing the config requires restarting the service.

`list --since START [--until END]` filters current ban records by their `banned_at` time. Either bound may be used alone. Dates without an explicit offset use the configured timezone; date-only values mean midnight. Expired bans already removed by the monitor cannot be listed.

`list --limit N` shows the N most recent active ban records, ordered by ban time descending. It can be combined with `--since` and `--until`. Without `--limit`, records remain ordered by IP.

`ban` and `unban` accept `--protocols SSH,FTP` or `--protocols ALL`, with the same names and aliases as YAML. Omitting the option uses `ban_protocols` from the configuration. A manual ban adds selected protocols to an existing ban; the IP shares one expiry, which is updated by the latest ban command. Partial unban removes only selected protocols and keeps the remaining ban and expiry. `unban IP --protocols ALL` removes the entire ban. An ALL-traffic ban cannot be partially removed; use ALL to clear it first, then ban the desired protocols. Historical `ban --since ... --protocols ...` applies the selection to newly created bans; existing bans keep their settings.

`list --ip VALUE` filters the active ban list. A complete IPv4 or IPv6 address matches exactly, including IPv4-mapped IPv6 forms. An address fragment matches anywhere in the stored IP, case-insensitively; for example, `--ip '203.0.113.'` or `--ip '2001:DB8'`. The fragment is literal, so `%` and `_` are not wildcards. It can be combined with `--since`, `--until`, and `--limit`. If only the header is printed, no active ban matches.

`export --format csv --output PATH` writes current active bans to a CSV file with `ip`, `protocols`, `banned_at`, and `unban_at` columns. `--format csv` is optional because CSV is currently the default and only supported format. Timestamps use the configured timezone and include their UTC offset. The destination must not already exist; the file is created with mode `0600`. Export does not change bans.

`import --format csv --input PATH` adds or updates bans from a CSV file. CSV is the default format. The required header is `ip`; optional columns are `protocols` (also accepts `ban_protocols`), `banned_at`, and `unban_at`. For example:

```csv
ip,protocols
203.0.113.7,SSH
198.51.100.9,"SSH,FTP"
2001:db8::7,ALL
```

Multiple protocols belong in one quoted CSV field, separated by commas. Protocol names and aliases follow the YAML configuration. A missing or blank protocol field uses the configured default (SSH unless changed); explicitly supplied protocols are stored per IP and survive configuration changes. `list` shows the effective protocols. All firewall backends and hosts.deny respect these per-IP settings.

Imports accept the current exported CSV and older exports without a protocol column. Missing `banned_at` defaults to now; missing/blank `unban_at` or `permanent` means permanent. Timestamp fields accept the same formats and timezone rules as `--since`; expiry must be in the future. Existing IPs are updated to the imported times and protocols. Whitelisted IPs are skipped and reported. Invalid addresses, protocols, duplicate IPs, or malformed records abort the entire database transaction. After a successful commit, SentryGuard synchronizes enforcement rules; a synchronization failure is reported separately. Exported CSV files can therefore be imported to restore the IPs, protocols, and timestamps on another host.

`reset` clears every ban after an English warning and an exact `RESET` confirmation. Any other answer, including an empty answer, cancels without removing bans. The command removes SentryGuard's matching firewall and `hosts.deny` rules. It does not clear the journal cursor or unrelated pending failure counts; new failures can trigger new bans later. If firewall cleanup fails after the database is cleared, the command reports that partial failure so it can be investigated. Export a CSV first if you need a record of the current ban list.

`scan` reads failed SSH password messages directly from the systemd journal. Without time options, it scans the most recent `failure_window` (4 hours by default). With only `--until`, the window ends at that time; with only `--since`, it ends now. It prints source IP, account, log time in the configured timezone, protocol (`SSH`), and journal terminal (`-` when unavailable). `--limit N` shows the N newest matching failures. `--count` prints the number of failures per IP, highest first; `--ip ADDRESS` filters either scan mode to one IP, and `--limit N` with `--count` shows the top N IPs. Scan reads logs without changing bans or the live journal cursor. It depends on the requested journal history still being available.

Set `timezone: Local` (default), `timezone: UTC`, `timezone: CST` (China Standard Time, UTC+8), or an IANA name such as `Asia/Shanghai` in the YAML config. This controls `list` output and the interpretation of `--since`/`--until` timestamps that have no explicit offset. RFC3339 inputs with an offset retain their specified instant. SQLite continues to store ban timestamps in UTC so existing records and expiration comparisons remain consistent when this setting changes; the database itself does not have a timezone. Restart the service after editing the config.

`ban --since START [--until END]` scans SSH journal entries in that inclusive interval and bans IPs that reach the YAML `threshold` within `failure_window`. Without `--until`, the scan ends at the current time on the day the command runs. A successful login resets that IP's count within the scan. Dates without an explicit offset use the configured timezone; accepted formats are `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, and RFC3339 (for example `2026-10-29T00:00:00+08:00`). Quote timestamps containing spaces. Date-only values mean midnight. Existing active bans keep their current expiry, while newly found IPs use the optional `--duration` (permanent by default). The scan does not change the live monitor's journal cursor or failure counters; the requested period must still be present in the system journal.

All named options use the standard long form with two hyphens (`--config`, `--ip`, `--duration`, `--since`, `--until`, `--limit`). Help also accepts the short form `-h`. The former single-hyphen long forms produce a migration hint.

If journal entries are rotated away before the next poll, the saved cursor can become unavailable. In that case, check `journalctl -u sentryguard` and reset the `state` cursor in the SQLite database only after deciding how to handle the skipped period. Rules are restored from SQLite at each service start, including after a reboot.

Test on a spare host or console before relying on this for remote access. An administrator may lock out their own address after repeated failed passwords; use `sentryguard unban IP` from local console to recover.

## License

SentryGuard is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text. Third-party dependencies retain their respective licenses.

## Testing Scope and Feedback

**The author has tested SentryGuard only on the versions of Debian, Ubuntu, and CentOS that were the latest at the time of testing. Other distributions and versions have not been tested.** The source code is available, so you can make your own changes if you encounter problems, or report them to the author through the project's issue tracker or other contact channels for assistance.

<p align="center"><sub>This software was created with the assistance of vibe coding tools.</sub></p>
