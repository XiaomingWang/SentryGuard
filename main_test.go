package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFailedPasswordsAndSuccessReset(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{Threshold: 3}
	window := 10 * time.Minute
	failure := "Failed password for invalid user admin from 203.0.113.7 port 3456 ssh2"
	base := time.Now().Add(-time.Minute)
	for i, message := range []string{failure, failure, "Accepted publickey for admin from 203.0.113.7 port 3456 ssh2", failure} {
		if err := processEvent(db, c, window, 0, journalEvent{Cursor: string(rune('a' + i)), Identifier: "sshd", Message: message, Timestamp: strconv.FormatInt(base.Add(time.Duration(i)*time.Second).UnixMicro(), 10)}); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM failure_events WHERE ip='203.0.113.7'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	var cursor string
	if err := db.QueryRow(`SELECT value FROM state WHERE key='cursor'`).Scan(&cursor); err != nil || cursor != "d" {
		t.Fatalf("cursor = %q, err = %v", cursor, err)
	}
	var banned string
	if err := db.QueryRow(`SELECT ip FROM bans`).Scan(&banned); err != sql.ErrNoRows {
		t.Fatalf("unexpected ban: %q, %v", banned, err)
	}
}

func TestHostsDenyPreservesOtherRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.deny")
	if err := os.WriteFile(path, []byte("sshd: 192.0.2.1\nALL: 203.0.113.1 # SentryGuard\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := syncHosts(path, []string{"203.0.113.2", "2001:db8::1"}, Config{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"sshd: 192.0.2.1", "sshd: 203.0.113.2 # SentryGuard", "sshd: [2001:db8::1] # SentryGuard"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %q", want, s)
		}
	}
	if strings.Contains(s, "203.0.113.1") {
		t.Fatalf("stale ban remains: %q", s)
	}
}

func TestDuration(t *testing.T) {
	d, err := parseDuration("60d")
	if err != nil || d != 60*24*time.Hour {
		t.Fatalf("duration = %v, %v", d, err)
	}
	if _, err := parseDuration("999999999999999999d"); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestCLI(t *testing.T) {
	tests := []struct {
		args                                 []string
		command, ip, duration, errorContains string
		ranged, defaultUntil                 bool
	}{
		{args: []string{"ban", "180.20.33.44"}, command: "ban", ip: "180.20.33.44"},
		{args: []string{"ban", "180.20.33.44", "--duration", "60d"}, command: "ban", ip: "180.20.33.44", duration: "60d"},
		{args: []string{"--config", "/tmp/config.yaml", "unban", "--ip", "2001:db8::1"}, command: "unban", ip: "2001:db8::1"},
		{args: []string{"list"}, command: "list"},
		{args: []string{"list", "--since", "2026-10-29"}, command: "list"},
		{args: []string{"list", "--until", "2026-10-30"}, command: "list"},
		{args: []string{"list", "--since", "2026-10-29", "--until", "2026-10-30"}, command: "list"},
		{args: []string{"list", "--limit", "20"}, command: "list"},
		{args: []string{"list", "--ip", "203.0.113.7"}, command: "list", ip: "203.0.113.7"},
		{args: []string{"list", "--ip", "203.0.113"}, command: "list", ip: "203.0.113"},
		{args: []string{"list", "--ip=2001:db8"}, command: "list", ip: "2001:db8"},
		{args: []string{"reset"}, command: "reset"},
		{args: []string{"ban", "203.0.113.7", "--protocols", "SSH,FTP"}, command: "ban", ip: "203.0.113.7"},
		{args: []string{"unban", "203.0.113.7", "--protocols=ALL"}, command: "unban", ip: "203.0.113.7"},
		{args: []string{"ban", "203.0.113.7", "--protocols", "ALL,FTP"}, errorContains: "ALL must be used alone"},
		{args: []string{"list", "--protocols", "SSH"}, errorContains: "only valid with 'ban' or 'unban'"},
		{args: []string{"import", "--input", "/tmp/bans.csv"}, command: "import"},
		{args: []string{"import"}, errorContains: "requires --input PATH"},
		{args: []string{"export", "--output", "/tmp/bans.csv"}, command: "export"},
		{args: []string{"export", "--format", "csv", "--output", "/tmp/bans.csv"}, command: "export"},
		{args: []string{"export"}, errorContains: "requires --output PATH"},
		{args: []string{"export", "--format", "json", "--output", "/tmp/bans.json"}, errorContains: "unsupported export format"},
		{args: []string{"list", "--output", "/tmp/bans.csv"}, errorContains: "only valid with 'export'"},
		{args: []string{"reset", "--limit", "2"}, errorContains: "only valid with 'list'"},
		{args: []string{"scan", "--count", "--ip", "203.0.113.7", "--limit", "10"}, command: "scan", ip: "203.0.113.7"},
		{args: []string{"scan", "--since", "2026-10-29", "--until", "2026-10-30"}, command: "scan"},
		{args: []string{"list", "--count"}, errorContains: "only valid with 'scan'"},
		{args: []string{"list", "--limit", "0"}, errorContains: "positive integer"},
		{args: []string{"ban", "1.2.3.4", "--limit", "20"}, errorContains: "only valid with 'list'"},
		{args: []string{"ban", "--since", "2026-10-29"}, command: "ban", ranged: true, defaultUntil: true},
		{args: []string{"ban", "--since", "2026-10-29 12:00:00", "--until", "2026-10-30 13:00:00", "--duration", "60d"}, command: "ban", ranged: true, duration: "60d"},
		{args: []string{"ban", "--since=2026-10-29T00:00:00+08:00", "--until=2026-10-30T00:00:00+08:00"}, command: "ban", ranged: true},
		{args: []string{"ban"}, errorContains: "requires an IP address"},
		{args: []string{"ban", "from", "2026-10-29", "to", "2026-10-30"}, errorContains: "was replaced"},
		{args: []string{"ban", "--since", "2026-10-30", "--until", "2026-10-29"}, errorContains: "later than --since"},
		{args: []string{"ban", "--since", "bad", "--until", "2026-10-30"}, errorContains: "--since: invalid datetime"},
		{args: []string{"ban", "--until", "2026-10-30"}, errorContains: "requires --since"},
		{args: []string{"ban", "--since", "2026-10-29", "--ip", "1.2.3.4"}, errorContains: "cannot be combined"},
		{args: []string{"ban", "1.2.3.4", "--since", "2026-10-29"}, errorContains: "cannot be combined"},
		{args: []string{"list", "--since", "2026-10-30", "--until", "2026-10-29"}, errorContains: "earlier than --since"},
		{args: []string{"list", "extra"}, errorContains: "takes no arguments"},
		{args: []string{"ban", "1.2.3.4", "--ip", "1.2.3.4"}, errorContains: "not both"},
		{args: []string{"unban", "1.2.3.4", "--duration", "60d"}, errorContains: "only valid"},
		{args: []string{"-command", "ban"}, errorContains: "was removed"},
		{args: []string{"--ip"}, errorContains: "requires a value"},
		{args: []string{"-config", "/tmp/config.yaml"}, errorContains: "renamed to \"--config\""},
		{args: []string{"-ip=1.2.3.4", "ban"}, errorContains: "renamed to \"--ip\""},
		{args: []string{"ban", "1.2.3.4", "-duration", "60d"}, errorContains: "renamed to \"--duration\""},
	}
	for _, tt := range tests {
		before := time.Now()
		o, err := parseCLI(tt.args)
		after := time.Now()
		if tt.errorContains != "" {
			if err == nil || !strings.Contains(err.Error(), tt.errorContains) {
				t.Errorf("%q: error = %v, want %q", tt.args, err, tt.errorContains)
			}
			continue
		}
		if err != nil || o.command != tt.command || o.ip != tt.ip || o.duration != tt.duration || o.ranged != tt.ranged {
			t.Errorf("%q: options = %+v, error = %v", tt.args, o, err)
		}
		if tt.defaultUntil && (o.end.Before(before) || o.end.After(after)) {
			t.Errorf("%q: default until = %v, expected current time", tt.args, o.end)
		}
	}
}

func TestHostsOnlyBanDoesNotWarnAboutFirewall(t *testing.T) {
	t.Setenv("PATH", "")
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("enforcement: [hosts_deny]\ndb_path: %q\nhosts_deny_path: %q\n", filepath.Join(dir, "test.db"), filepath.Join(dir, "hosts.deny"))
	if err := os.WriteFile(config, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	oldArgs := os.Args
	os.Args = []string{"sentryguard", "ban", "10.20.100.101", "--config", config}
	defer func() { os.Args = oldArgs }()
	var logs bytes.Buffer
	oldLog := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldLog)
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Fatalf("hosts-only ban logged warning: %s", logs.String())
	}
	hosts, err := os.ReadFile(filepath.Join(dir, "hosts.deny"))
	if err != nil || !strings.Contains(string(hosts), "10.20.100.101") {
		t.Fatalf("hosts=%s err=%v", hosts, err)
	}
}

func TestEnforcementStrategySwitch(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tool := "#!/bin/sh\nif [ \"$1\" = list ]; then exit 0; fi\n/bin/cat > \"$SENTRY_STRATEGY_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(tool), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_STRATEGY_LOG", filepath.Join(dir, "nft.log"))
	c := Config{HostsDenyPath: filepath.Join(dir, "hosts.deny")}
	if err := banDB(db, "203.0.113.7", time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(db, c); err != nil {
		t.Fatal(err)
	}
	c.Enforcement = []string{"firewall"}
	if err := reconcile(db, c); err != nil {
		t.Fatal(err)
	}
	hosts, _ := os.ReadFile(c.HostsDenyPath)
	if strings.Contains(string(hosts), "203.0.113.7") {
		t.Fatal("disabled hosts strategy retained ban")
	}
	c.Enforcement = []string{"hosts_deny"}
	if err := reconcile(db, c); err != nil {
		t.Fatal(err)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "nft.log"))
	if strings.Contains(string(log), "add rule") || !strings.Contains(string(log), "flush chain") {
		t.Fatalf("disabled firewall script=%s", log)
	}
	hosts, _ = os.ReadFile(c.HostsDenyPath)
	if !strings.Contains(string(hosts), "203.0.113.7") {
		t.Fatal("hosts strategy missing ban")
	}
	if ips, err := activeIPs(db, time.Now()); err != nil || len(ips) != 1 {
		t.Fatalf("bans=%v err=%v", ips, err)
	}
}

func TestEnforcementConfigValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	for _, data := range []string{"{}", "enforcement: [firewall]", "enforcement: [hosts_deny]"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := readConfig(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, data := range []string{"enforcement: []", "enforcement: [unknown]"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := readConfig(path); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}

func TestBanProtocols(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	for _, tc := range []struct{ yaml, want string }{
		{"{}\n", "SSH"},
		{"ban_protocols: [sshd, ftp]\n", "FTP,SSH"},
		{"ban_protocols: [ALL]\n", "ALL"},
		{"ban_protocols: [ALL, SSH]\n", "error"},
		{"ban_protocols: [unknown]\n", "error"},
	} {
		if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
			t.Fatal(err)
		}
		c, _, _, _, err := readConfig(path)
		if tc.want == "error" {
			if err == nil {
				t.Errorf("%q accepted", tc.yaml)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(c.BanProtocols, ","); got != tc.want && !(tc.want == "FTP,SSH" && got == "SSH,FTP") {
			t.Errorf("%q => %q", tc.yaml, got)
		}
		if tc.want == "FTP,SSH" && !strings.Contains(fmt.Sprint(c.banPorts()), "21 22") {
			t.Errorf("ports = %v", c.banPorts())
		}
	}
}

func TestFirewallProtocolRules(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nft.log")
	script := "#!/bin/sh\nif [ \"$1\" = list ]; then exit 0; fi\n/bin/cat > \"$SENTRY_TEST_NFT_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_TEST_NFT_LOG", logPath)
	if err := syncFirewall([]string{"203.0.113.7"}, Config{BanProtocols: []string{"SSH", "FTP"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ip saddr @blocked4 tcp dport { 21, 22 } drop") || !strings.Contains(string(data), "ip6 saddr @blocked6 tcp dport { 21, 22 } drop") {
		t.Fatalf("port rules = %s", data)
	}
	if err := syncFirewall([]string{"203.0.113.7"}, Config{BanProtocols: []string{"ALL"}}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ip saddr @blocked4 drop") || strings.Contains(string(data), "tcp dport") {
		t.Fatalf("ALL rules = %s", data)
	}
	if err := syncFirewallEntries([]banEntry{{ip: "203.0.113.7", protocols: []string{"FTP"}}, {ip: "2001:db8::7", protocols: []string{"ALL"}}}, Config{BanProtocols: []string{"SSH"}}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ip saddr 203.0.113.7 tcp dport { 21 } drop") || !strings.Contains(string(data), "ip6 saddr 2001:db8::7 drop") {
		t.Fatalf("per-IP rules = %s", data)
	}
}

func TestIPTablesRuleLifecycle(t *testing.T) {
	dir := t.TempDir()
	tool := "#!/bin/sh\nfor arg in \"$@\"; do\n case \"$arg\" in\n -C) test -f \"$SENTRY_RULE_STATE\"; exit $? ;;\n -I) : > \"$SENTRY_RULE_STATE\"; printf 'add %s\\n' \"$*\" >> \"$SENTRY_RULE_LOG\"; exit 0 ;;\n -D) /bin/rm -f \"$SENTRY_RULE_STATE\"; printf 'delete %s\\n' \"$*\" >> \"$SENTRY_RULE_LOG\"; exit 0 ;;\n esac\ndone\n"
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(tool), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_RULE_STATE", filepath.Join(dir, "state"))
	t.Setenv("SENTRY_RULE_LOG", filepath.Join(dir, "rules.log"))
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{BanProtocols: []string{"SSH"}}
	if got := firewallBackend(); got != "iptables" {
		t.Fatalf("backend = %s", got)
	}
	if err := syncManagedFirewall(db, []string{"203.0.113.7"}, c); err != nil {
		t.Fatal(err)
	}
	if err := syncManagedFirewall(db, []string{"203.0.113.7"}, c); err != nil {
		t.Fatal(err)
	}
	if err := syncManagedFirewall(db, nil, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "rules.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "add ") != 1 || strings.Count(string(data), "delete ") != 1 || !strings.Contains(string(data), "--dport 22") {
		t.Fatalf("iptables lifecycle = %s", data)
	}
	rules, err := storedFirewallRules(db)
	if err != nil || len(rules) != 0 {
		t.Fatalf("stored rules = %v, err = %v", rules, err)
	}
}

func TestManagedFirewallBackendPreference(t *testing.T) {
	dir := t.TempDir()
	for name, script := range map[string]string{
		"iptables":     "#!/bin/sh\nexit 0\n",
		"nft":          "#!/bin/sh\nexit 0\n",
		"ufw":          "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'Status: active'; fi\n",
		"firewall-cmd": "#!/bin/sh\nif [ \"$1\" = --state ]; then echo running; fi\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	if got := firewallBackend(); got != "firewalld" {
		t.Fatalf("backend = %s", got)
	}
	if err := os.Remove(filepath.Join(dir, "firewall-cmd")); err != nil {
		t.Fatal(err)
	}
	if got := firewallBackend(); got != "ufw" {
		t.Fatalf("backend = %s", got)
	}
	if err := os.Remove(filepath.Join(dir, "ufw")); err != nil {
		t.Fatal(err)
	}
	if got := firewallBackend(); got != "nft" {
		t.Fatalf("backend = %s", got)
	}
	if err := os.Remove(filepath.Join(dir, "nft")); err != nil {
		t.Fatal(err)
	}
	if got := firewallBackend(); got != "iptables" {
		t.Fatalf("backend = %s", got)
	}
	if err := os.Remove(filepath.Join(dir, "iptables")); err != nil {
		t.Fatal(err)
	}
	if got := firewallBackend(); got != "none" {
		t.Fatalf("backend = %s", got)
	}
}

func TestUFWRuleLifecycle(t *testing.T) {
	dir := t.TempDir()
	tool := "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'Status: active'; exit 0; fi\nprintf '%s\\n' \"$*\" >> \"$SENTRY_UFW_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ufw"), []byte(tool), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_UFW_LOG", filepath.Join(dir, "ufw.log"))
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{BanProtocols: []string{"SSH", "FTP"}}
	if err := syncManagedFirewall(db, []string{"203.0.113.7"}, c); err != nil {
		t.Fatal(err)
	}
	if err := syncManagedFirewall(db, []string{"203.0.113.7"}, c); err != nil {
		t.Fatal(err)
	}
	if err := syncManagedFirewall(db, nil, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ufw.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "insert 1 deny") != 2 || strings.Count(string(data), "--force delete deny") != 2 || !strings.Contains(string(data), "port 22 proto tcp comment SentryGuard") || !strings.Contains(string(data), "port 21 proto tcp comment SentryGuard") {
		t.Fatalf("ufw lifecycle = %s", data)
	}
}

func TestFirewalldRuleLifecycle(t *testing.T) {
	dir := t.TempDir()
	tool := `#!/bin/sh
if [ "$1" = --state ]; then echo running; exit 0; fi
mode=runtime
action=
for arg in "$@"; do
  case "$arg" in
    --permanent) mode=permanent ;;
    --query-rule|--add-rule|--remove-rule) action="$arg" ;;
  esac
done
state="${SENTRY_FIREWALLD_STATE}_$mode"
case "$action" in
  --query-rule) test -f "$state" ;;
  --add-rule) : > "$state"; printf 'add %s\n' "$mode" >> "$SENTRY_FIREWALLD_LOG" ;;
  --remove-rule) /bin/rm -f "$state"; printf 'remove %s\n' "$mode" >> "$SENTRY_FIREWALLD_LOG" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "firewall-cmd"), []byte(tool), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_FIREWALLD_STATE", filepath.Join(dir, "state"))
	t.Setenv("SENTRY_FIREWALLD_LOG", filepath.Join(dir, "firewalld.log"))
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{BanProtocols: []string{"SSH"}}
	if err := syncManagedFirewall(db, []string{"203.0.113.7"}, c); err != nil {
		t.Fatal(err)
	}
	if err := syncManagedFirewall(db, nil, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "firewalld.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"add permanent", "add runtime", "remove permanent", "remove runtime"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s in %s", want, data)
		}
	}
}

func TestScanJournalDetailsAndCount(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	var lines []string
	for i, msg := range []string{
		"Failed password for invalid user alice from 203.0.113.7 port 2222 ssh2",
		"Failed password for root from 198.51.100.9 port 2222 ssh2",
		"Failed password for alice from 203.0.113.7 port 2222 ssh2",
	} {
		b, _ := json.Marshal(journalEvent{Identifier: "sshd", Message: msg, Timestamp: strconv.FormatInt(base.Add(time.Duration(i)*time.Minute).UnixMicro(), 10), TTY: "pts/1"})
		lines = append(lines, string(b))
	}
	journal := filepath.Join(dir, "journal.jsonl")
	if err := os.WriteFile(journal, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte("#!/bin/sh\n/bin/cat \"$SENTRY_TEST_JOURNAL\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_TEST_JOURNAL", journal)
	c := Config{Timezone: "UTC"}
	var out bytes.Buffer
	if err := scanJournal(c, base, base.Add(time.Hour), 2, false, "", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "198.51.100.9") == false || strings.Count(got, "203.0.113.7") != 1 || !strings.Contains(got, "alice\t2026-10-29T12:02:00Z\tSSH\tpts/1") {
		t.Fatalf("scan = %q", got)
	}
	out.Reset()
	if err := scanJournal(c, base, base.Add(time.Hour), 0, true, "203.0.113.7", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "203.0.113.7\t2") || strings.Contains(out.String(), "198.51.100.9") {
		t.Fatalf("count = %q", out.String())
	}
}

func TestBanRangeScansAndKeepsCursor(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := storeCursor(db, "live-cursor"); err != nil {
		t.Fatal(err)
	}
	var lines []byte
	base := time.Date(2026, 10, 29, 1, 0, 0, 0, time.Local)
	index := 0
	add := func(message string) {
		b, err := json.Marshal(journalEvent{Identifier: "sshd", Message: message, Timestamp: strconv.FormatInt(base.Add(time.Duration(index)*time.Minute).UnixMicro(), 10)})
		if err != nil {
			t.Fatal(err)
		}
		index++
		lines = append(lines, b...)
		lines = append(lines, '\n')
	}
	fail := func(ip string) string { return "Failed password for invalid user admin from " + ip + " port 1234 ssh2" }
	for i := 0; i < 3; i++ {
		add(fail("203.0.113.2"))
	}
	add(fail("203.0.113.3"))
	add(fail("203.0.113.3"))
	add("Accepted publickey for admin from 203.0.113.3 port 1234 ssh2")
	add(fail("203.0.113.3"))
	add(fail("203.0.113.3"))
	journal := filepath.Join(dir, "journal.jsonl")
	if err := os.WriteFile(journal, lines, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte("#!/bin/sh\n/bin/cat \"$SENTRY_TEST_JOURNAL\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_TEST_JOURNAL", journal)
	c := Config{Threshold: 3, HostsDenyPath: filepath.Join(dir, "hosts.deny")}
	start, _ := parseDateTime("2026-10-29", time.Local)
	end, _ := parseDateTime("2026-10-30", time.Local)
	if err := banRange(db, c, start, end, 4*time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	ips, err := activeIPs(db, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.2" {
		t.Fatalf("banned IPs = %v", ips)
	}
	var cursor string
	if err := db.QueryRow(`SELECT value FROM state WHERE key='cursor'`).Scan(&cursor); err != nil || cursor != "live-cursor" {
		t.Fatalf("cursor = %q, err = %v", cursor, err)
	}
	if err := banRange(db, c, start, end, 4*time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if ips, err = activeIPs(db, time.Now()); err != nil || len(ips) != 1 {
		t.Fatalf("repeat scan: IPs = %v, err = %v", ips, err)
	}
}

func TestHistoricalScanUsesWindow(t *testing.T) {
	r := rangeCounter{counts: make(map[string][]int64), matched: make(map[string]struct{}), threshold: 3, window: 4 * time.Hour}
	base := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, 3 * time.Hour, 4*time.Hour + time.Minute} {
		ev := journalEvent{Identifier: "sshd", Message: "Failed password for root from 203.0.113.10 port 2222 ssh2", Timestamp: strconv.FormatInt(base.Add(offset).UnixMicro(), 10)}
		if err := r.add(ev); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.matched) != 0 {
		t.Fatalf("matched outside four-hour window: %v", r.matched)
	}
	ev := journalEvent{Identifier: "sshd", Message: "Failed password for root from 203.0.113.10 port 2222 ssh2", Timestamp: strconv.FormatInt(base.Add(4*time.Hour+2*time.Minute).UnixMicro(), 10)}
	if err := r.add(ev); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.matched["203.0.113.10"]; !ok {
		t.Fatal("expected match inside four-hour window")
	}
}

func TestFourHourSlidingWindow(t *testing.T) {
	t.Setenv("PATH", "")
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{Threshold: 3, HostsDenyPath: filepath.Join(t.TempDir(), "hosts.deny")}
	base := time.Now().Add(-5 * time.Hour)
	for i, offset := range []time.Duration{0, 3 * time.Hour, 4*time.Hour + time.Minute, 4*time.Hour + 2*time.Minute} {
		ev := journalEvent{Cursor: fmt.Sprintf("event-%d", i), Identifier: "sshd",
			Message:   "Failed password for root from 203.0.113.8 port 2222 ssh2",
			Timestamp: strconv.FormatInt(base.Add(offset).UnixMicro(), 10)}
		if err := processEvent(db, c, 4*time.Hour, 0, ev); err != nil {
			t.Fatal(err)
		}
		ips, err := activeIPs(db, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if i < 3 && len(ips) != 0 {
			t.Fatalf("banned too early after event %d: %v", i, ips)
		}
		if i == 3 && (len(ips) != 1 || ips[0] != "203.0.113.8") {
			t.Fatalf("missing ban after event %d: %v", i, ips)
		}
	}
}

func TestFirstRunBackfillsThreeDays(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := storeCursor(db, "old-version-cursor"); err != nil {
		t.Fatal(err)
	}
	var lines []byte
	base := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		ev := journalEvent{Cursor: fmt.Sprintf("backfill-%d", i), Identifier: "sshd",
			Message:   "Failed password for root from 203.0.113.9 port 2222 ssh2",
			Timestamp: strconv.FormatInt(base.Add(time.Duration(i)*time.Hour).UnixMicro(), 10)}
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(append(lines, b...), '\n')
	}
	journal := filepath.Join(dir, "journal.jsonl")
	if err := os.WriteFile(journal, lines, 0600); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\n/bin/printf '%s\\n' \"$@\" > \"$SENTRY_TEST_ARGS\"\n/bin/cat \"$SENTRY_TEST_JOURNAL\"\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_TEST_JOURNAL", journal)
	t.Setenv("SENTRY_TEST_ARGS", argsPath)
	c := Config{Threshold: 3, HostsDenyPath: filepath.Join(dir, "hosts.deny")}
	if err := prepareInitialBackfill(db); err != nil {
		t.Fatal(err)
	}
	if err := pollJournal(db, c, 4*time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	ips, err := activeIPs(db, time.Now())
	if err != nil || len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("backfill bans = %v, err = %v", ips, err)
	}
	var since string
	if err := db.QueryRow(`SELECT value FROM state WHERE key='initial_backfill_at'`).Scan(&since); err != nil {
		t.Fatal(err)
	}
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", since, time.Local)
	if err != nil || time.Since(parsed) < 71*time.Hour || time.Since(parsed) > 73*time.Hour {
		t.Fatalf("backfill start = %q, err = %v", since, err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil || !strings.Contains(string(args), "--since\n"+since) {
		t.Fatalf("journal args = %q, err = %v", args, err)
	}
	var cursor string
	if err := db.QueryRow(`SELECT value FROM state WHERE key='cursor'`).Scan(&cursor); err != nil || cursor != "backfill-2" {
		t.Fatalf("new cursor = %q, err = %v", cursor, err)
	}
	if err := prepareInitialBackfill(db); err != nil {
		t.Fatal(err)
	}
	var unchanged string
	if err := db.QueryRow(`SELECT value FROM state WHERE key='cursor'`).Scan(&unchanged); err != nil || unchanged != cursor {
		t.Fatalf("cursor reset after completed backfill: %q, err = %v", unchanged, err)
	}
}

func TestListBanTimeFilters(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if err := banDB(db, ip, base.Add(time.Duration(i)*24*time.Hour), 0); err != nil {
			t.Fatal(err)
		}
	}
	middle := base.Add(24 * time.Hour)
	for _, tc := range []struct {
		since, until time.Time
		want         []string
		missing      []string
	}{
		{since: middle, want: []string{"203.0.113.2", "203.0.113.3"}, missing: []string{"203.0.113.1"}},
		{until: middle, want: []string{"203.0.113.1", "203.0.113.2"}, missing: []string{"203.0.113.3"}},
		{since: middle, until: middle, want: []string{"203.0.113.2"}, missing: []string{"203.0.113.1", "203.0.113.3"}},
	} {
		var out bytes.Buffer
		if err := list(db, "", tc.since, tc.until, 0, time.UTC, Config{}, &out); err != nil {
			t.Fatal(err)
		}
		for _, ip := range tc.want {
			if !strings.Contains(out.String(), ip) {
				t.Errorf("missing %s from %q", ip, out.String())
			}
		}
		for _, ip := range tc.missing {
			if strings.Contains(out.String(), ip) {
				t.Errorf("unexpected %s in %q", ip, out.String())
			}
		}
	}
}

func TestListRecentAndTimezone(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if err := banDB(db, ip, base.Add(time.Duration(i)*time.Hour), 0); err != nil {
			t.Fatal(err)
		}
	}
	loc := time.FixedZone("CST", 8*60*60)
	var out bytes.Buffer
	if err := list(db, "", time.Time{}, time.Time{}, 2, loc, Config{}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "203.0.113.3\t") || !strings.HasPrefix(lines[2], "203.0.113.2\t") || !strings.Contains(lines[1], "2026-10-20T10:00:00+08:00") {
		t.Fatalf("recent CST list = %q", out.String())
	}
	parsed, err := parseDateTime("2026-10-20 08:00:00", loc)
	if err != nil || !parsed.Equal(base) {
		t.Fatalf("CST input = %v, err = %v", parsed, err)
	}
	if _, err := parseCLI([]string{"list", "--since", "2026-10-20 08:00:00"}, loc); err != nil {
		t.Fatal(err)
	}
}

func TestListIPFilter(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Now().Add(-time.Hour)
	for i, ip := range []string{"203.0.113.7", "203.0.113.70", "198.51.100.9", "2001:db8::7"} {
		if err := banDB(db, ip, base.Add(time.Duration(i)*time.Minute), 0); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		filter string
		limit  int
		want   []string
	}{
		{"203.0.113.7", 0, []string{"203.0.113.7"}},
		{"203.0.113.", 0, []string{"203.0.113.7", "203.0.113.70"}},
		{"203.0.113.", 1, []string{"203.0.113.70"}},
		{"2001:DB8", 0, []string{"2001:db8::7"}},
		{"::ffff:203.0.113.7", 0, []string{"203.0.113.7"}},
		{"%", 0, nil},
		{"192.0.2", 0, nil},
	} {
		var out bytes.Buffer
		if err := list(db, tc.filter, time.Time{}, time.Time{}, tc.limit, time.UTC, Config{}, &out); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != len(tc.want)+1 {
			t.Errorf("filter %q, limit %d: %q", tc.filter, tc.limit, out.String())
			continue
		}
		for i, ip := range tc.want {
			if !strings.HasPrefix(lines[i+1], ip+"\t") {
				t.Errorf("filter %q, limit %d: row %d = %q, want %s", tc.filter, tc.limit, i, lines[i+1], ip)
			}
		}
	}
}

func TestReconcileWithoutNft(t *testing.T) {
	t.Setenv("PATH", "")
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hosts := filepath.Join(dir, "hosts.deny")
	c := Config{HostsDenyPath: hosts}
	if err := banDB(db, "203.0.113.4", time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(db, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(hosts)
	if err != nil || !strings.Contains(string(data), "sshd: 203.0.113.4 # SentryGuard") {
		t.Fatalf("hosts.deny = %q, error = %v", data, err)
	}
	if _, err := db.Exec(`DELETE FROM bans WHERE ip='203.0.113.4'`); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(db, c); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(hosts)
	if err != nil || strings.Contains(string(data), "203.0.113.4") {
		t.Fatalf("stale ban in hosts.deny = %q, error = %v", data, err)
	}
}

func TestWhitelistConfigValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	good := "whitelist:\n  - '203.0.113.7'\n  - '::ffff:203.0.113.7'\n  - '2001:db8::7'\n  - '192.168.0.42/24'\n  - '2001:db8:1::/64'\n"
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	c, _, _, _, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Whitelist) != 4 || !c.isWhitelisted("203.0.113.7") || !c.isWhitelisted("2001:db8::7") || !c.isWhitelisted("192.168.0.200") || !c.isWhitelisted("2001:db8:1::9") || c.isWhitelisted("192.168.1.1") {
		t.Fatalf("normalized whitelist = %v", c.Whitelist)
	}
	if c.Whitelist[2] != "192.168.0.0/24" {
		t.Fatalf("CIDR not masked: %v", c.Whitelist)
	}
	if err := os.WriteFile(path, []byte("whitelist:\n  - '203.0.113.0/99'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := readConfig(path); err == nil || !strings.Contains(err.Error(), "invalid whitelist IP or CIDR") {
		t.Fatalf("invalid CIDR error = %v", err)
	}
}

func TestWhitelistedFailuresAndHistoricalScan(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{Threshold: 2, Whitelist: []string{"203.0.113.0/24"}}
	for i := 0; i < 3; i++ {
		ev := journalEvent{Cursor: fmt.Sprintf("white-%d", i), Identifier: "sshd", Message: "Failed password for root from 203.0.113.7 port 2222 ssh2", Timestamp: strconv.FormatInt(time.Now().UnixMicro(), 10)}
		if err := processEvent(db, c, 4*time.Hour, 0, ev); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM failure_events WHERE ip='203.0.113.7'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("pending whitelist failures = %d, err = %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM bans WHERE ip='203.0.113.7'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("whitelist bans = %d, err = %v", n, err)
	}
	r := rangeCounter{counts: make(map[string][]int64), matched: make(map[string]struct{}), threshold: 2, window: 4 * time.Hour, whitelist: c.Whitelist}
	for i := 0; i < 3; i++ {
		if err := r.add(journalEvent{Identifier: "sshd", Message: "Failed password for root from 203.0.113.7 port 2222 ssh2", Timestamp: strconv.FormatInt(time.Now().UnixMicro(), 10)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.matched) != 0 {
		t.Fatalf("historical scan matched whitelisted IP: %v", r.matched)
	}
}

func TestWhitelistRemovesExistingBanFromRules(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, ip := range []string{"203.0.113.7", "2001:db8::7", "198.51.100.8"} {
		if err := banDB(db, ip, time.Now(), 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO failure_events(cursor,ip,at_us) VALUES('whitelist-pending','203.0.113.9',?)`, time.Now().UnixMicro()); err != nil {
		t.Fatal(err)
	}
	nftLog := filepath.Join(dir, "nft.log")
	script := "#!/bin/sh\nif [ \"$1\" = list ]; then exit 0; fi\n/bin/cat > \"$SENTRY_TEST_NFT_LOG\"\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SENTRY_TEST_NFT_LOG", nftLog)
	hosts := filepath.Join(dir, "hosts.deny")
	c := Config{HostsDenyPath: hosts, Whitelist: []string{"203.0.113.0/24", "2001:db8::/64"}}
	if err := reconcile(db, c); err != nil {
		t.Fatal(err)
	}
	ips, err := activeIPs(db, time.Now())
	if err != nil || len(ips) != 1 || ips[0] != "198.51.100.8" {
		t.Fatalf("remaining bans = %v, err = %v", ips, err)
	}
	var pending int
	if err := db.QueryRow(`SELECT count(*) FROM failure_events WHERE ip='203.0.113.9'`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending CIDR failure = %d, err = %v", pending, err)
	}
	for _, path := range []string{hosts, nftLog} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "203.0.113.7") || strings.Contains(string(data), "2001:db8::7") || !strings.Contains(string(data), "198.51.100.8") {
			t.Fatalf("wrong rules in %s: %s", path, data)
		}
	}
}

func TestManualBanRejectsWhitelist(t *testing.T) {
	t.Setenv("PATH", "")
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := banDB(db, "203.0.113.7", time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	db.Close()
	configPath := filepath.Join(dir, "config.yaml")
	yaml := fmt.Sprintf("db_path: %q\nhosts_deny_path: %q\nwhitelist:\n  - '203.0.113.0/24'\n", dbPath, filepath.Join(dir, "hosts.deny"))
	if err := os.WriteFile(configPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	oldArgs := os.Args
	os.Args = []string{"sentryguard", "ban", "203.0.113.7", "--config", configPath}
	defer func() { os.Args = oldArgs }()
	if err := run(); err == nil || !strings.Contains(err.Error(), "in whitelist") {
		t.Fatalf("manual ban error = %v", err)
	}
	db, err = openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM bans WHERE ip='203.0.113.7'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("whitelisted ban remains: %d, err = %v", n, err)
	}
}
