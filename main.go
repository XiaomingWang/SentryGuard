package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

const forever = "9999-12-31T00:00:00Z"
const marker = " # SentryGuard"

//go:embed VERSION
var versionText string

func version() string { return "sentryguard " + strings.TrimSpace(versionText) }

var nftWarning sync.Once

type Config struct {
	Threshold     int      `yaml:"threshold"`
	FailureWindow string   `yaml:"failure_window"`
	BanDuration   string   `yaml:"ban_duration"`
	PollInterval  string   `yaml:"poll_interval"`
	DBPath        string   `yaml:"db_path"`
	HostsDenyPath string   `yaml:"hosts_deny_path"`
	Whitelist     []string `yaml:"whitelist"`
	Timezone      string   `yaml:"timezone"`
	BanProtocols  []string `yaml:"ban_protocols"`
	Enforcement   []string `yaml:"enforcement"`
}

func (c Config) usesEnforcement(name string) bool {
	if c.Enforcement == nil {
		return true
	}
	for _, value := range c.Enforcement {
		if value == name {
			return true
		}
	}
	return false
}

var protocolPorts = map[string]int{
	"SSH": 22, "FTP": 21, "FTPS": 990, "TELNET": 23, "RDP": 3389,
	"HTTP": 80, "HTTPS": 443, "SMTP": 25, "IMAP": 143, "POP3": 110,
	"MYSQL": 3306, "POSTGRESQL": 5432,
}

func (c Config) banPorts() []int {
	return portsForProtocols(c.BanProtocols)
}

func portsForProtocols(protocols []string) []int {
	if len(protocols) == 0 {
		return []int{22}
	}
	var ports []int
	for _, name := range protocols {
		if name == "ALL" {
			return nil
		}
		ports = append(ports, protocolPorts[name])
	}
	sort.Ints(ports)
	return ports
}

func normalizeProtocols(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("at least one protocol is required")
	}
	seen := make(map[string]bool)
	var protocols []string
	for _, entry := range raw {
		name := strings.ToUpper(strings.TrimSpace(entry))
		if name == "SSHD" || name == "SFTP" {
			name = "SSH"
		}
		if name != "ALL" {
			if _, ok := protocolPorts[name]; !ok {
				return nil, fmt.Errorf("invalid protocol %q; supported: SSH, FTP, FTPS, TELNET, RDP, HTTP, HTTPS, SMTP, IMAP, POP3, MYSQL, POSTGRESQL, ALL", entry)
			}
		}
		if !seen[name] {
			protocols = append(protocols, name)
			seen[name] = true
		}
	}
	if seen["ALL"] && len(protocols) != 1 {
		return nil, errors.New("ALL must be used alone")
	}
	return protocols, nil
}

func (c Config) isWhitelisted(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, allowed := range c.Whitelist {
		if prefix, err := netip.ParsePrefix(allowed); err == nil && prefix.Contains(addr) {
			return true
		}
		if allowed == addr.String() {
			return true
		}
	}
	return false
}

func (c Config) location() (*time.Location, error) {
	switch c.Timezone {
	case "", "Local":
		return time.Local, nil
	case "CST":
		return time.FixedZone("CST", 8*60*60), nil
	default:
		loc, err := time.LoadLocation(c.Timezone)
		if err != nil {
			return nil, fmt.Errorf("invalid timezone %q: use Local, UTC, CST (UTC+8), or an IANA name such as Asia/Shanghai: %w", c.Timezone, err)
		}
		return loc, nil
	}
}

func readConfig(path string) (Config, time.Duration, time.Duration, time.Duration, error) {
	c := Config{Threshold: 5, FailureWindow: "4h", BanDuration: "permanent", PollInterval: "10s", DBPath: "/etc/SentryGuard/sentryguard.db", HostsDenyPath: "/etc/hosts.deny", Timezone: "Local", BanProtocols: []string{"SSH"}}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, 0, 0, 0, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err = dec.Decode(&c); err != nil {
		return c, 0, 0, 0, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return c, 0, 0, 0, errors.New("configuration must contain one YAML document")
	}
	if c.Enforcement == nil {
		c.Enforcement = []string{"firewall", "hosts_deny"}
	}
	if len(c.Enforcement) == 0 {
		return c, 0, 0, 0, errors.New("enforcement must contain firewall, hosts_deny, or both")
	}
	for i, value := range c.Enforcement {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "firewall" && value != "hosts_deny" {
			return c, 0, 0, 0, fmt.Errorf("invalid enforcement strategy %q; use firewall or hosts_deny", value)
		}
		c.Enforcement[i] = value
	}
	if c.Threshold < 1 || c.DBPath == "" || c.HostsDenyPath == "" {
		return c, 0, 0, 0, errors.New("invalid threshold or path")
	}
	seen := make(map[string]struct{}, len(c.Whitelist))
	normalized := make([]string, 0, len(c.Whitelist))
	for _, entry := range c.Whitelist {
		ip := ""
		if addr, parseErr := netip.ParseAddr(entry); parseErr == nil && addr.Zone() == "" {
			ip = addr.Unmap().String()
		} else if prefix, parseErr := netip.ParsePrefix(entry); parseErr == nil && prefix.Addr().Zone() == "" {
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			ip = prefix.Masked().String()
		} else {
			return c, 0, 0, 0, fmt.Errorf("invalid whitelist IP or CIDR %q: use an IPv4/IPv6 address or network prefix", entry)
		}
		if _, exists := seen[ip]; !exists {
			normalized = append(normalized, ip)
			seen[ip] = struct{}{}
		}
	}
	c.Whitelist = normalized
	protocols, err := normalizeProtocols(c.BanProtocols)
	if err != nil {
		return c, 0, 0, 0, fmt.Errorf("ban_protocols: %w", err)
	}
	c.BanProtocols = protocols
	if _, err := c.location(); err != nil {
		return c, 0, 0, 0, err
	}
	window, err := parseDuration(c.FailureWindow)
	if err != nil || window <= 0 {
		return c, 0, 0, 0, errors.New("invalid failure_window")
	}
	poll, err := parseDuration(c.PollInterval)
	if err != nil || poll < time.Second {
		return c, 0, 0, 0, errors.New("poll_interval must be at least 1s")
	}
	ban := time.Duration(0)
	if c.BanDuration != "permanent" {
		ban, err = parseDuration(c.BanDuration)
		if err != nil || ban <= 0 {
			return c, 0, 0, 0, errors.New("invalid ban_duration")
		}
	}
	return c, window, poll, ban, nil
}

var days = regexp.MustCompile(`^([1-9][0-9]*)d$`)

func parseDuration(s string) (time.Duration, error) {
	if m := days.FindStringSubmatch(s); m != nil {
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || n > int64((1<<63-1)/int64(24*time.Hour)) {
			return 0, errors.New("duration too large")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func openDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, banned_at TEXT NOT NULL, unban_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS ban_protocol_overrides (ip TEXT PRIMARY KEY, protocols TEXT NOT NULL)`,
		`CREATE TRIGGER IF NOT EXISTS bans_cleanup_protocols AFTER DELETE ON bans BEGIN DELETE FROM ban_protocol_overrides WHERE ip=old.ip; END`,
		`CREATE TABLE IF NOT EXISTS failures (ip TEXT PRIMARY KEY, count INTEGER NOT NULL, last_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS failure_events (cursor TEXT PRIMARY KEY, ip TEXT NOT NULL, at_us INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS failure_events_ip_time ON failure_events(ip, at_us)`,
		`CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS firewall_rules (backend TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, PRIMARY KEY(backend,ip,port))`,
	} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func expiry(now time.Time, duration time.Duration) string {
	if duration == 0 {
		return forever
	}
	return now.Add(duration).UTC().Format(time.RFC3339)
}

func banDB(db *sql.DB, ip string, at time.Time, duration time.Duration) error {
	_, err := db.Exec(`INSERT INTO bans(ip,banned_at,unban_at) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET banned_at=excluded.banned_at,unban_at=excluded.unban_at`, ip, at.UTC().Format(time.RFC3339), expiry(at, duration))
	return err
}

func activeIPs(db *sql.DB, now time.Time) ([]string, error) {
	rows, err := db.Query(`SELECT ip FROM bans WHERE unban_at > ? ORDER BY ip`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

type banEntry struct {
	ip        string
	protocols []string
}

func activeBanEntries(db *sql.DB, now time.Time, c Config) ([]banEntry, error) {
	rows, err := db.Query(`SELECT b.ip, COALESCE(p.protocols,'') FROM bans b LEFT JOIN ban_protocol_overrides p ON p.ip=b.ip WHERE b.unban_at > ? ORDER BY b.ip`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []banEntry
	for rows.Next() {
		var ip, override string
		if err := rows.Scan(&ip, &override); err != nil {
			return nil, err
		}
		protocols := c.BanProtocols
		if len(protocols) == 0 {
			protocols = []string{"SSH"}
		}
		if override != "" {
			protocols, err = normalizeProtocols(strings.Split(override, ","))
			if err != nil {
				return nil, fmt.Errorf("stored protocols for %s: %w", ip, err)
			}
		}
		entries = append(entries, banEntry{ip: ip, protocols: protocols})
	}
	return entries, rows.Err()
}

func nft(args ...string) error {
	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func nftScript(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureFirewall() error {
	if err := nft("list", "table", "inet", "sentryguard"); err == nil {
		return nil
	}
	return nftScript("table inet sentryguard {\n set blocked4 { type ipv4_addr; }\n set blocked6 { type ipv6_addr; }\n chain input { type filter hook input priority -10; policy accept; }\n}\n")
}

func setName(ip string) string {
	if netip.MustParseAddr(ip).Is4() {
		return "blocked4"
	}
	return "blocked6"
}
func syncFirewall(ips []string, c Config) error {
	return syncFirewallEntries(defaultBanEntries(ips, c), c)
}

func defaultBanEntries(ips []string, c Config) []banEntry {
	protocols := c.BanProtocols
	if len(protocols) == 0 {
		protocols = []string{"SSH"}
	}
	entries := make([]banEntry, 0, len(ips))
	for _, ip := range ips {
		entries = append(entries, banEntry{ip: ip, protocols: protocols})
	}
	return entries
}

func samePorts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func syncFirewallEntries(entries []banEntry, c Config) error {
	if err := ensureFirewall(); err != nil {
		return err
	}
	var script strings.Builder
	script.WriteString("flush set inet sentryguard blocked4\nflush set inet sentryguard blocked6\n")
	script.WriteString("flush chain inet sentryguard input\n")
	ports := c.banPorts()
	for _, family := range []struct{ addr, set string }{{"ip", "blocked4"}, {"ip6", "blocked6"}} {
		if ports == nil {
			fmt.Fprintf(&script, "add rule inet sentryguard input %s saddr @%s drop\n", family.addr, family.set)
		} else {
			values := make([]string, len(ports))
			for i, port := range ports {
				values[i] = strconv.Itoa(port)
			}
			fmt.Fprintf(&script, "add rule inet sentryguard input %s saddr @%s tcp dport { %s } drop\n", family.addr, family.set, strings.Join(values, ", "))
		}
	}
	for _, entry := range entries {
		if samePorts(portsForProtocols(entry.protocols), ports) {
			fmt.Fprintf(&script, "add element inet sentryguard %s { %s }\n", setName(entry.ip), entry.ip)
			continue
		}
		family := "ip"
		if netip.MustParseAddr(entry.ip).Is6() {
			family = "ip6"
		}
		customPorts := portsForProtocols(entry.protocols)
		if customPorts == nil {
			fmt.Fprintf(&script, "add rule inet sentryguard input %s saddr %s drop\n", family, entry.ip)
		} else {
			values := make([]string, len(customPorts))
			for i, port := range customPorts {
				values[i] = strconv.Itoa(port)
			}
			fmt.Fprintf(&script, "add rule inet sentryguard input %s saddr %s tcp dport { %s } drop\n", family, entry.ip, strings.Join(values, ", "))
		}
	}
	return nftScript(script.String())
}

func syncHosts(path string, ips []string, c Config) error {
	return syncHostsEntries(path, defaultBanEntries(ips, c))
}

func syncHostsEntries(path string, entries []banEntry) error {
	var old []byte
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", path)
		}
		old, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	var lines []string
	if len(old) > 0 {
		for _, line := range strings.Split(strings.TrimSuffix(string(old), "\n"), "\n") {
			if !strings.HasSuffix(line, marker) {
				lines = append(lines, line)
			}
		}
	}
	for _, entry := range entries {
		services := []string{}
		if len(entry.protocols) == 1 && entry.protocols[0] == "ALL" {
			services = append(services, "ALL")
		} else {
			for _, name := range entry.protocols {
				switch name {
				case "SSH":
					services = append(services, "sshd")
				case "FTP", "FTPS":
					services = append(services, "ftpd", "vsftpd", "proftpd", "pure-ftpd")
				}
			}
		}
		if len(services) == 0 {
			continue
		}
		addr := entry.ip
		if netip.MustParseAddr(entry.ip).Is6() {
			addr = "[" + entry.ip + "]"
		}
		lines = append(lines, strings.Join(services, ", ")+": "+addr+marker)
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if bytes.Equal(old, []byte(content)) {
		return nil
	}
	mode := os.FileMode(0644)
	if info != nil {
		mode = info.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".sentryguard-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func reconcile(db *sql.DB, c Config) error {
	if len(c.Whitelist) > 0 {
		rows, err := db.Query(`SELECT ip FROM bans UNION SELECT ip FROM failure_events`)
		if err != nil {
			return fmt.Errorf("find whitelisted records: %w", err)
		}
		var remove []string
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				rows.Close()
				return err
			}
			if c.isWhitelisted(ip) {
				remove = append(remove, ip)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, ip := range remove {
			if _, err := db.Exec(`DELETE FROM bans WHERE ip=?`, ip); err != nil {
				return fmt.Errorf("remove whitelisted IP %s from bans: %w", ip, err)
			}
			if _, err := db.Exec(`DELETE FROM failure_events WHERE ip=?`, ip); err != nil {
				return fmt.Errorf("clear failures for whitelisted IP %s: %w", ip, err)
			}
		}
	}
	entries, err := activeBanEntries(db, time.Now(), c)
	if err != nil {
		return err
	}
	firewallErr := syncManagedFirewallEntries(db, entries, c)
	hostEntries := entries
	if !c.usesEnforcement("hosts_deny") {
		hostEntries = nil
		if _, err := os.Lstat(c.HostsDenyPath); os.IsNotExist(err) {
			return firewallErr
		}
	}
	hostsErr := syncHostsEntries(c.HostsDenyPath, hostEntries)
	return errors.Join(firewallErr, hostsErr)
}

func expire(db *sql.DB, c Config) error {
	now := time.Now().UTC().Format(time.RFC3339)
	r, err := db.Exec(`DELETE FROM bans WHERE unban_at <= ?`, now)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n > 0 {
		return reconcile(db, c)
	}
	return nil
}

var failed = regexp.MustCompile(`^Failed password for .+ from ([0-9A-Fa-f:.]+) port [0-9]+`)
var failedDetails = regexp.MustCompile(`^Failed password for (?:invalid user )?(.+?) from ([0-9A-Fa-f:.]+) port [0-9]+`)
var accepted = regexp.MustCompile(`^Accepted (?:password|publickey|keyboard-interactive/pam) for .+ from ([0-9A-Fa-f:.]+) port [0-9]+`)

type journalEvent struct {
	Cursor     string `json:"__CURSOR"`
	Message    string `json:"MESSAGE"`
	Identifier string `json:"SYSLOG_IDENTIFIER"`
	Timestamp  string `json:"__REALTIME_TIMESTAMP"`
	TTY        string `json:"_TTY"`
}

type scanRecord struct {
	ip, user, terminal string
	at                 time.Time
}

func scanJournal(c Config, start, end time.Time, limit int, count bool, filterIP string, out io.Writer) error {
	args := []string{"--no-pager", "--quiet", "-o", "json", "-t", "sshd", "-t", "sshd-session",
		"--since", start.Local().Format("2006-01-02 15:04:05"), "--until", end.Local().Format("2006-01-02 15:04:05")}
	counts := make(map[string]int)
	var records []scanRecord
	seen := 0
	err := walkJournal(args, func(ev journalEvent) error {
		if ev.Identifier != "sshd" && ev.Identifier != "sshd-session" {
			return nil
		}
		m := failedDetails.FindStringSubmatch(ev.Message)
		if m == nil {
			return nil
		}
		addr, err := netip.ParseAddr(m[2])
		if err != nil || addr.IsLoopback() || addr.IsUnspecified() {
			return nil
		}
		ip := addr.Unmap().String()
		if filterIP != "" && filterIP != ip {
			return nil
		}
		at, err := ev.eventTime()
		if err != nil {
			return err
		}
		if at.Before(start) || at.After(end) {
			return nil
		}
		if count {
			counts[ip]++
			return nil
		}
		terminal := ev.TTY
		if terminal == "" {
			terminal = "-"
		}
		record := scanRecord{ip: ip, user: m[1], terminal: terminal, at: at}
		if limit == 0 || len(records) < limit {
			records = append(records, record)
		} else {
			records[seen%limit] = record
		}
		seen++
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan SSH journal: %w", err)
	}
	if count {
		type pair struct {
			ip    string
			count int
		}
		pairs := make([]pair, 0, len(counts))
		for ip, n := range counts {
			pairs = append(pairs, pair{ip, n})
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].count == pairs[j].count {
				return pairs[i].ip < pairs[j].ip
			}
			return pairs[i].count > pairs[j].count
		})
		if limit > 0 && len(pairs) > limit {
			pairs = pairs[:limit]
		}
		fmt.Fprintln(out, "IP\tCOUNT")
		for _, p := range pairs {
			fmt.Fprintf(out, "%s\t%d\n", p.ip, p.count)
		}
		return nil
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].at.After(records[j].at) })
	loc, _ := c.location()
	fmt.Fprintf(out, "IP\tUSER\tTIME (%s)\tPROTOCOL\tTERMINAL\n", loc)
	for _, r := range records {
		user := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(r.user)
		terminal := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(r.terminal)
		fmt.Fprintf(out, "%s\t%s\t%s\tSSH\t%s\n", r.ip, user, r.at.In(loc).Format(time.RFC3339), terminal)
	}
	return nil
}

func (ev journalEvent) eventTime() (time.Time, error) {
	us, err := strconv.ParseInt(ev.Timestamp, 10, 64)
	if err != nil || us <= 0 {
		return time.Time{}, fmt.Errorf("invalid journal timestamp %q", ev.Timestamp)
	}
	return time.UnixMicro(us).UTC(), nil
}

func storeCursor(db *sql.DB, cursor string) error {
	_, err := db.Exec(`INSERT INTO state(key,value) VALUES('cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, cursor)
	return err
}

func prepareInitialBackfill(db *sql.DB) error {
	var done string
	err := db.QueryRow(`SELECT value FROM state WHERE key='three_day_backfill_done'`).Scan(&done)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	since := time.Now().Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM state WHERE key='cursor'`); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO state(key,value) VALUES('initial_backfill_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, since); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM failure_events`); err != nil {
		return err
	}
	return tx.Commit()
}

func processEvent(db *sql.DB, c Config, window, duration time.Duration, ev journalEvent) error {
	if ev.Identifier != "sshd" && ev.Identifier != "sshd-session" {
		return storeCursor(db, ev.Cursor)
	}
	if m := accepted.FindStringSubmatch(ev.Message); m != nil {
		if ip, err := netip.ParseAddr(m[1]); err == nil {
			_, err = db.Exec(`DELETE FROM failure_events WHERE ip=?`, ip.Unmap().String())
			if err != nil {
				return err
			}
		}
		return storeCursor(db, ev.Cursor)
	}
	m := failed.FindStringSubmatch(ev.Message)
	if m == nil {
		return storeCursor(db, ev.Cursor)
	}
	addr, err := netip.ParseAddr(m[1])
	if err != nil {
		return storeCursor(db, ev.Cursor)
	}
	ip := addr.Unmap().String()
	if addr.IsLoopback() || addr.IsUnspecified() {
		return storeCursor(db, ev.Cursor)
	}
	if c.isWhitelisted(ip) {
		return storeCursor(db, ev.Cursor)
	}
	eventTime, err := ev.eventTime()
	if err != nil {
		return err
	}
	var existing string
	err = db.QueryRow(`SELECT unban_at FROM bans WHERE ip=?`, ip).Scan(&existing)
	if err == nil && existing > time.Now().UTC().Format(time.RFC3339) {
		return storeCursor(db, ev.Cursor)
	}
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	cutoff := eventTime.Add(-window).UnixMicro()
	if _, err = db.Exec(`DELETE FROM failure_events WHERE ip=? AND at_us < ?`, ip, cutoff); err != nil {
		return err
	}
	if _, err = db.Exec(`INSERT OR IGNORE INTO failure_events(cursor,ip,at_us) VALUES(?,?,?)`, ev.Cursor, ip, eventTime.UnixMicro()); err != nil {
		return err
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM failure_events WHERE ip=? AND at_us>=? AND at_us<=?`, ip, cutoff, eventTime.UnixMicro()).Scan(&count); err != nil {
		return err
	}
	if count >= c.Threshold {
		if err = banDB(db, ip, time.Now(), duration); err != nil {
			return err
		}
		if _, err = db.Exec(`DELETE FROM failure_events WHERE ip=?`, ip); err != nil {
			return err
		}
		if err = reconcile(db, c); err != nil {
			return err
		}
		log.Printf("banned %s after %d failed passwords", ip, count)
	}
	return storeCursor(db, ev.Cursor)
}

func walkJournal(args []string, handle func(journalEvent) error) error {
	cmd := exec.Command("journalctl", args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var ev journalEvent
		if err = json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			break
		}
		err = handle(ev)
		if err != nil {
			break
		}
	}
	if err == nil {
		err = scanner.Err()
	}
	if err != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err != nil {
		return err
	}
	if waitErr != nil {
		return fmt.Errorf("journalctl: %w: %s", waitErr, stderr.String())
	}
	return nil
}

func pollJournal(db *sql.DB, c Config, window, duration time.Duration) error {
	var cursor string
	err := db.QueryRow(`SELECT value FROM state WHERE key='cursor'`).Scan(&cursor)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	args := []string{"--no-pager", "--quiet", "-o", "json", "-t", "sshd", "-t", "sshd-session"}
	if cursor == "" {
		var since string
		err = db.QueryRow(`SELECT value FROM state WHERE key='initial_backfill_at'`).Scan(&since)
		if err == sql.ErrNoRows {
			since = time.Now().Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
			_, err = db.Exec(`INSERT INTO state(key,value) VALUES('initial_backfill_at',?)`, since)
		}
		if err != nil {
			return err
		}
		args = append(args, "--since", since)
	} else {
		args = append(args, "--after-cursor", cursor)
	}
	err = walkJournal(args, func(ev journalEvent) error {
		if ev.Cursor == "" {
			return nil
		}
		return processEvent(db, c, window, duration, ev)
	})
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO state(key,value) VALUES('three_day_backfill_done','1') ON CONFLICT(key) DO UPDATE SET value='1'`)
	return err
}

type rangeCounter struct {
	counts    map[string][]int64
	matched   map[string]struct{}
	threshold int
	failures  int
	window    time.Duration
	whitelist []string
}

func (r *rangeCounter) add(ev journalEvent) error {
	if ev.Identifier != "sshd" && ev.Identifier != "sshd-session" {
		return nil
	}
	if m := accepted.FindStringSubmatch(ev.Message); m != nil {
		if addr, err := netip.ParseAddr(m[1]); err == nil {
			delete(r.counts, addr.Unmap().String())
		}
		return nil
	}
	m := failed.FindStringSubmatch(ev.Message)
	if m == nil {
		return nil
	}
	addr, err := netip.ParseAddr(m[1])
	if err != nil || addr.IsLoopback() || addr.IsUnspecified() {
		return nil
	}
	ip := addr.Unmap().String()
	if (Config{Whitelist: r.whitelist}).isWhitelisted(ip) {
		return nil
	}
	eventTime, err := ev.eventTime()
	if err != nil {
		return err
	}
	r.failures++
	if _, done := r.matched[ip]; done {
		return nil
	}
	cutoff := eventTime.Add(-r.window).UnixMicro()
	events := r.counts[ip]
	kept := events[:0]
	for _, us := range events {
		if us >= cutoff {
			kept = append(kept, us)
		}
	}
	kept = append(kept, eventTime.UnixMicro())
	if len(kept) >= r.threshold {
		r.matched[ip] = struct{}{}
		delete(r.counts, ip)
	} else {
		r.counts[ip] = kept
	}
	return nil
}

func banRange(db *sql.DB, c Config, start, end time.Time, window, duration time.Duration, protocols ...string) error {
	args := []string{"--no-pager", "--quiet", "-o", "json", "-t", "sshd", "-t", "sshd-session",
		"--since", start.Local().Format("2006-01-02 15:04:05"), "--until", end.Local().Format("2006-01-02 15:04:05")}
	counter := rangeCounter{counts: make(map[string][]int64), matched: make(map[string]struct{}), threshold: c.Threshold, window: window, whitelist: c.Whitelist}
	if err := walkJournal(args, counter.add); err != nil {
		return fmt.Errorf("scan SSH journal for %s to %s: %w", start.Format(time.RFC3339), end.Format(time.RFC3339), err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM bans WHERE unban_at <= ?`, now); err != nil {
		return err
	}
	newBans := 0
	for ip := range counter.matched {
		if c.isWhitelisted(ip) {
			continue
		}
		res, err := tx.Exec(`INSERT INTO bans(ip,banned_at,unban_at) VALUES(?,?,?) ON CONFLICT(ip) DO NOTHING`, ip, now, expiry(time.Now(), duration))
		if err != nil {
			return err
		}
		rows, _ := res.RowsAffected()
		newBans += int(rows)
		if rows > 0 && len(protocols) > 0 {
			if _, err := tx.Exec(`INSERT INTO ban_protocol_overrides(ip,protocols) VALUES(?,?)`, ip, strings.Join(protocols, ",")); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if err = reconcile(db, c); err != nil {
		return fmt.Errorf("%d new bans saved, but enforcement sync failed: %w", newBans, err)
	}
	fmt.Printf("Scanned %d failed passwords; %d IPs reached threshold %d; %d newly banned, %d already banned.\n", counter.failures, len(counter.matched), c.Threshold, newBans, len(counter.matched)-newBans)
	return nil
}

func list(db *sql.DB, ipFilter string, since, until time.Time, limit int, loc *time.Location, c Config, out io.Writer) error {
	query := `SELECT b.ip,COALESCE(p.protocols,''),b.banned_at,b.unban_at FROM bans b LEFT JOIN ban_protocol_overrides p ON p.ip=b.ip WHERE b.unban_at > ?`
	args := []any{time.Now().UTC().Format(time.RFC3339)}
	if ipFilter != "" {
		if addr, err := netip.ParseAddr(ipFilter); err == nil {
			if addr.Zone() != "" {
				return fmt.Errorf("list: IP zone is not supported in --ip %q", ipFilter)
			}
			query += ` AND b.ip = ?`
			args = append(args, addr.Unmap().String())
		} else {
			query += ` AND instr(lower(b.ip), lower(?)) > 0`
			args = append(args, ipFilter)
		}
	}
	if !since.IsZero() {
		query += ` AND b.banned_at >= ?`
		args = append(args, since.UTC().Format(time.RFC3339))
	}
	if !until.IsZero() {
		query += ` AND b.banned_at <= ?`
		args = append(args, until.UTC().Format(time.RFC3339))
	}
	if limit > 0 {
		query += ` ORDER BY b.banned_at DESC, b.ip ASC LIMIT ?`
		args = append(args, limit)
	} else {
		query += ` ORDER BY b.ip`
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintf(out, "IP\tPROTOCOLS\tBANNED_AT (%s)\tUNBAN_AT (%s)\n", loc, loc)
	for rows.Next() {
		var ip, protocols, at, until string
		if err = rows.Scan(&ip, &protocols, &at, &until); err != nil {
			return err
		}
		if protocols == "" {
			protocols = strings.Join(c.BanProtocols, ",")
			if protocols == "" {
				protocols = "SSH"
			}
		}
		bannedAt, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return fmt.Errorf("invalid stored banned_at for %s: %w", ip, err)
		}
		unbanAt, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return fmt.Errorf("invalid stored unban_at for %s: %w", ip, err)
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", ip, protocols, bannedAt.In(loc).Format(time.RFC3339), unbanAt.In(loc).Format(time.RFC3339))
	}
	return rows.Err()
}

type cliOptions struct {
	command   string
	config    string
	ip        string
	duration  string
	protocols []string
	format    string
	input     string
	output    string
	limit     int
	count     bool
	ranged    bool
	start     time.Time
	end       time.Time
	help      bool
	version   bool
}

func usage(w io.Writer) {
	fmt.Fprintln(w, version())
	fmt.Fprintln(w, `Usage:
  sentryguard [run] [--config PATH]
  sentryguard list [--ip ADDRESS_OR_PART] [--since START] [--until END] [--limit N] [--config PATH]
  sentryguard scan [--since START] [--until END] [--limit N] [--count] [--ip ADDRESS] [--config PATH]
  sentryguard ban IP [--protocols SSH,FTP|ALL] [--duration 60d|permanent] [--config PATH]
  sentryguard ban --since START [--until END] [--duration 60d|permanent] [--config PATH]
  sentryguard unban IP [--protocols SSH,FTP|ALL] [--config PATH]
  sentryguard reset [--config PATH]
  sentryguard export [--format csv] --output PATH [--config PATH]
  sentryguard import [--format csv] --input PATH [--config PATH]

Options:
  --config PATH     YAML config (default /etc/SentryGuard/config.yaml)
  --ip VALUE        IP for ban/unban; IP filter for list/scan (list accepts fragments)
  --since START     Start of journal scan or ban-time list filter
  --until END       End of journal scan or ban-time list filter
  --limit N         Show N most recent records (list/scan); top N with scan --count
  --count           Count SSH failures per IP (scan only)
  --duration VALUE  Manual ban duration (default permanent); examples: 60d, 24h
  --protocols LIST  Protocols for ban/unban (comma-separated; default from config)
  --format VALUE    Import/export format (csv; default csv)
  --input PATH      CSV file to import
  --output PATH     Destination file for export; must not already exist
  -h, --help        Show this help
  -v, --version     Show program version

Options may appear before or after the command and IP.`)
}

func parseDateTime(value string, loc *time.Location) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02"} {
		var t time.Time
		var err error
		if layout == time.RFC3339 {
			t, err = time.Parse(layout, value)
		} else {
			t, err = time.ParseInLocation(layout, value, loc)
		}
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid datetime %q; use YYYY-MM-DD HH:MM:SS (quote it), YYYY-MM-DD, or RFC3339", value)
}

func parseCLI(args []string, locations ...*time.Location) (cliOptions, error) {
	loc := time.Local
	if len(locations) > 0 {
		loc = locations[0]
	}
	o := cliOptions{command: "run", config: "/etc/SentryGuard/config.yaml"}
	var positional []string
	var hasIP, hasDuration bool
	var sinceText, untilText string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-v" || a == "--version" {
			o.version = true
			return o, nil
		}
		if a == "-h" || a == "--help" {
			o.help = true
			return o, nil
		}
		if a == "-command" || strings.HasPrefix(a, "-command=") {
			return o, errors.New("-command was removed; use 'sentryguard ban IP', 'unban IP', 'list', or 'run'")
		}
		name, value, inline := strings.Cut(a, "=")
		switch name {
		case "--count":
			if inline {
				return o, errors.New("--count does not take a value")
			}
			o.count = true
		case "--config", "--ip", "--duration", "--since", "--until", "--limit", "--format", "--input", "--output", "--protocols":
			if !inline {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					return o, fmt.Errorf("%s requires a value", name)
				}
				i++
				value = args[i]
			}
			if value == "" {
				return o, fmt.Errorf("%s requires a non-empty value", name)
			}
			switch name {
			case "--config":
				o.config = value
			case "--ip":
				o.ip = value
				hasIP = true
			case "--duration":
				o.duration = value
				hasDuration = true
			case "--protocols":
				var err error
				o.protocols, err = normalizeProtocols(strings.Split(value, ","))
				if err != nil {
					return o, fmt.Errorf("--protocols: %w", err)
				}
			case "--format":
				o.format = value
			case "--input":
				o.input = value
			case "--output":
				o.output = value
			case "--since":
				sinceText = value
			case "--until":
				untilText = value
			case "--limit":
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 {
					return o, fmt.Errorf("--limit requires a positive integer; got %q", value)
				}
				o.limit = n
			}
		case "-config", "-ip", "-duration":
			return o, fmt.Errorf("option %q was renamed to %q", name, "-"+name)
		case "ban", "unban", "list", "scan", "reset", "export", "import", "run":
			positional = append(positional, a)
		default:
			if strings.HasPrefix(a, "-") {
				return o, fmt.Errorf("unknown option %q; use -h for help", a)
			}
			positional = append(positional, a)
		}
	}
	if len(positional) > 0 {
		o.command = positional[0]
		if o.command != "run" && o.command != "list" && o.command != "scan" && o.command != "ban" && o.command != "unban" && o.command != "reset" && o.command != "export" && o.command != "import" {
			return o, fmt.Errorf("unknown command %q; expected run, list, scan, ban, unban, reset, export, or import", o.command)
		}
	}
	if o.command == "import" {
		if o.input == "" {
			return o, errors.New("import requires --input PATH; example: sentryguard import --format csv --input bans.csv")
		}
	} else if o.input != "" {
		return o, errors.New("--input is only valid with 'import'")
	}
	if o.command == "export" {
		if o.output == "" {
			return o, errors.New("export requires --output PATH; example: sentryguard export --format csv --output bans.csv")
		}
	} else if o.output != "" {
		return o, errors.New("--output is only valid with 'export'")
	}
	if o.command == "import" || o.command == "export" {
		if o.format == "" {
			o.format = "csv"
		}
		if o.format != "csv" {
			return o, fmt.Errorf("unsupported %s format %q; use csv", o.command, o.format)
		}
	} else if o.format != "" {
		return o, errors.New("--format is only valid with 'import' or 'export'")
	}
	if hasDuration && o.command != "ban" {
		return o, errors.New("--duration is only valid with 'ban IP' or 'ban --since START'")
	}
	if len(o.protocols) > 0 && o.command != "ban" && o.command != "unban" {
		return o, errors.New("--protocols is only valid with 'ban' or 'unban'")
	}
	if o.limit > 0 && o.command != "list" && o.command != "scan" {
		return o, errors.New("--limit is only valid with 'list' or 'scan'")
	}
	if o.count && o.command != "scan" {
		return o, errors.New("--count is only valid with 'scan'")
	}
	if hasIP && o.command != "ban" && o.command != "unban" && o.command != "scan" && o.command != "list" {
		return o, errors.New("--ip is only valid with 'ban', 'unban', 'list', or 'scan'")
	}
	if sinceText != "" && o.command != "ban" && o.command != "list" && o.command != "scan" {
		return o, errors.New("--since is only valid with 'ban', 'list', or 'scan'")
	}
	if untilText != "" && o.command != "ban" && o.command != "list" && o.command != "scan" {
		return o, errors.New("--until is only valid with 'ban', 'list', or 'scan'")
	}
	if untilText != "" && sinceText == "" && o.command == "ban" {
		return o, errors.New("--until requires --since")
	}
	if o.command == "list" || o.command == "scan" {
		var err error
		if sinceText != "" {
			o.start, err = parseDateTime(sinceText, loc)
			if err != nil {
				return o, fmt.Errorf("--since: %w", err)
			}
		}
		if untilText != "" {
			o.end, err = parseDateTime(untilText, loc)
			if err != nil {
				return o, fmt.Errorf("--until: %w", err)
			}
		}
		if !o.start.IsZero() && !o.end.IsZero() && o.end.Before(o.start) {
			return o, errors.New("--until must not be earlier than --since")
		}
	}
	if o.command == "scan" && o.ip != "" {
		addr, err := netip.ParseAddr(o.ip)
		if err != nil || addr.Zone() != "" {
			return o, fmt.Errorf("scan: invalid --ip address %q", o.ip)
		}
		o.ip = addr.Unmap().String()
	}
	if o.command == "ban" || o.command == "unban" {
		if o.command == "ban" && len(positional) > 1 && positional[1] == "from" {
			return o, errors.New("'ban from ... to ...' was replaced; use 'ban --since START [--until END]'")
		}
		if sinceText != "" {
			if hasIP || len(positional) > 1 {
				return o, errors.New("ban --since cannot be combined with an IP address or --ip")
			}
			var err error
			o.start, err = parseDateTime(sinceText, loc)
			if err != nil {
				return o, fmt.Errorf("--since: %w", err)
			}
			if untilText == "" {
				o.end = time.Now()
			} else {
				o.end, err = parseDateTime(untilText, loc)
				if err != nil {
					return o, fmt.Errorf("--until: %w", err)
				}
			}
			if !o.end.After(o.start) {
				return o, errors.New("--until must be later than --since")
			}
			o.ranged = true
			return o, nil
		}
		if len(positional) > 2 {
			return o, fmt.Errorf("%s accepts exactly one IP address; got %d extra arguments", o.command, len(positional)-1)
		}
		if len(positional) == 2 {
			if hasIP {
				return o, fmt.Errorf("%s: provide the IP either as a positional argument or with --ip, not both", o.command)
			}
			o.ip = positional[1]
		}
		if o.ip == "" {
			return o, fmt.Errorf("%s requires an IP address; example: sentryguard %s 203.0.113.4", o.command, o.command)
		}
	} else if len(positional) > 1 {
		return o, fmt.Errorf("%s takes no arguments; got %q", o.command, strings.Join(positional[1:], " "))
	}
	return o, nil
}

func run() error {
	o, err := parseCLI(os.Args[1:])
	if err != nil {
		return err
	}
	if o.version {
		fmt.Fprintln(os.Stdout, version())
		return nil
	}
	if o.help {
		usage(os.Stdout)
		return nil
	}
	c, window, poll, configuredDuration, err := readConfig(o.config)
	if err != nil {
		return fmt.Errorf("load config %q: %w", o.config, err)
	}
	loc, _ := c.location() // readConfig validates the timezone.
	o, err = parseCLI(os.Args[1:], loc)
	if err != nil {
		return err
	}
	if o.command == "scan" {
		end := o.end
		if end.IsZero() {
			end = time.Now()
		}
		start := o.start
		if start.IsZero() {
			start = end.Add(-window)
		}
		if end.Before(start) {
			return errors.New("scan: --until must not be earlier than --since")
		}
		return scanJournal(c, start, end, o.limit, o.count, o.ip, os.Stdout)
	}
	duration := configuredDuration
	if o.command == "ban" {
		duration = 0 // Manual bans default to permanent, independent of the automatic ban duration.
		if o.duration != "" && o.duration != "permanent" {
			duration, err = parseDuration(o.duration)
			if err != nil || duration <= 0 {
				return fmt.Errorf("invalid --duration %q; use 'permanent', '60d', '24h', or another positive duration", o.duration)
			}
		}
	}
	db, err := openDB(c.DBPath)
	if err != nil {
		return fmt.Errorf("open database %q: %w", c.DBPath, err)
	}
	defer db.Close()
	switch o.command {
	case "list":
		return list(db, o.ip, o.start, o.end, o.limit, loc, c, os.Stdout)
	case "export":
		return exportCSV(db, o.output, loc, c, os.Stdout)
	case "import":
		return importCSV(db, o.input, loc, c, os.Stdout)
	case "reset":
		return resetBans(db, c, os.Stdin, os.Stdout)
	case "ban", "unban":
		if o.ranged {
			return banRange(db, c, o.start, o.end, window, duration, o.protocols...)
		}
		addr, err := netip.ParseAddr(o.ip)
		if err != nil {
			return fmt.Errorf("%s: invalid IP address %q: %w", o.command, o.ip, err)
		}
		if addr.Zone() != "" {
			return errors.New("IP zone is not supported")
		}
		ip := addr.Unmap().String()
		if addr.IsLoopback() || addr.IsUnspecified() {
			return errors.New("cannot ban loopback or unspecified address")
		}
		if o.command == "ban" && c.isWhitelisted(ip) {
			if err := reconcile(db, c); err != nil {
				return err
			}
			return fmt.Errorf("IP %s is in whitelist; remove it from config to ban it", ip)
		}
		err = changeBanProtocols(db, c, ip, o.command == "ban", o.protocols, duration)
		if err != nil {
			return err
		}
		return reconcile(db, c)
	case "run":
		if err = expire(db, c); err != nil {
			return err
		}
		if err = reconcile(db, c); err != nil {
			return err
		}
		if err = prepareInitialBackfill(db); err != nil {
			return fmt.Errorf("prepare three-day journal scan: %w", err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			if err = pollJournal(db, c, window, duration); err != nil {
				log.Printf("poll: %v", err)
			}
			if err = expire(db, c); err != nil {
				log.Printf("expire: %v", err)
			}
			cutoff := time.Now().Add(-window).UnixMicro()
			if _, err = db.Exec(`DELETE FROM failure_events WHERE at_us < ?`, cutoff); err != nil {
				log.Printf("prune: %v", err)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sentryguard:", err)
		os.Exit(1)
	}
}
