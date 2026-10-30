package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManualProtocolChanges(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{BanProtocols: []string{"SSH"}}
	ip := "203.0.113.7"
	for _, p := range [][]string{nil, {"FTP"}} {
		if err := changeBanProtocols(db, c, ip, true, p, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := changeBanProtocols(db, c, ip, false, nil, 0); err != nil {
		t.Fatal(err)
	}
	entries, err := activeBanEntries(db, time.Now(), c)
	if err != nil || len(entries) != 1 || strings.Join(entries[0].protocols, ",") != "FTP" {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	if err := changeBanProtocols(db, c, ip, true, []string{"ALL"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := changeBanProtocols(db, c, ip, false, []string{"SSH"}, 0); err == nil {
		t.Fatal("partial ALL unban accepted")
	}
	if err := changeBanProtocols(db, c, ip, false, []string{"ALL"}, 0); err != nil {
		t.Fatal(err)
	}
	entries, err = activeBanEntries(db, time.Now(), c)
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
}

func TestImportProtocolsRoundTripAndRollback(t *testing.T) {
	t.Setenv("PATH", "")
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{HostsDenyPath: filepath.Join(dir, "hosts.deny"), BanProtocols: []string{"SSH"}, Whitelist: []string{"192.0.2.0/24"}}
	path := filepath.Join(dir, "input.csv")
	data := "ip,protocols\n203.0.113.7,FTP\n198.51.100.9,ALL\n192.0.2.1,SSH\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := importCSV(db, path, time.UTC, c, &out); err != nil {
		t.Fatal(err)
	}
	entries, err := activeBanEntries(db, time.Now(), c)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	rules := desiredFirewallRulesEntries("iptables", entries)
	if len(rules) != 2 || rules[0].port != -1 || rules[1].port != 21 {
		t.Fatalf("rules=%v", rules)
	}
	hosts, _ := os.ReadFile(c.HostsDenyPath)
	if strings.Contains(string(hosts), "sshd: 203.0.113.7") || !strings.Contains(string(hosts), "ALL: 198.51.100.9") {
		t.Fatalf("hosts=%s", hosts)
	}
	exported := filepath.Join(dir, "export.csv")
	if err := exportCSV(db, exported, time.UTC, c, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM bans`); err != nil {
		t.Fatal(err)
	}
	if err := importCSV(db, exported, time.UTC, c, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ip,protocols\n203.0.113.50,SSH\ninvalid,FTP\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := importCSV(db, path, time.UTC, c, &out); err == nil {
		t.Fatal("invalid import accepted")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM bans WHERE ip='203.0.113.50'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial import count=%d err=%v", count, err)
	}
}

func TestResetNeedsExactConfirmationAndClearsRules(t *testing.T) {
	t.Setenv("PATH", "")
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := Config{HostsDenyPath: filepath.Join(dir, "hosts.deny")}
	if err := banDB(db, "203.0.113.7", time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(db, c); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := resetBans(db, c, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "This action cannot be undone") || !strings.Contains(out.String(), "Cancelled") {
		t.Fatalf("confirmation text = %q", out.String())
	}
	if ips, err := activeIPs(db, time.Now()); err != nil || len(ips) != 1 {
		t.Fatalf("cancelled reset changed bans: %v, %v", ips, err)
	}
	out.Reset()
	if err := resetBans(db, c, strings.NewReader("RESET\n"), &out); err != nil {
		t.Fatal(err)
	}
	if ips, err := activeIPs(db, time.Now()); err != nil || len(ips) != 0 {
		t.Fatalf("confirmed reset kept bans: %v, %v", ips, err)
	}
	hosts, err := os.ReadFile(c.HostsDenyPath)
	if err != nil || strings.Contains(string(hosts), "203.0.113.7") {
		t.Fatalf("reset hosts.deny = %q, %v", hosts, err)
	}
	if !strings.Contains(out.String(), "Removed 1 banned IP(s)") {
		t.Fatalf("reset result = %q", out.String())
	}
}

func TestExportCSVUsesConfiguredTimezoneAndDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := banDB(db, "203.0.113.7", base, 0); err != nil {
		t.Fatal(err)
	}
	if err := banDB(db, "198.51.100.9", base, time.Minute); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bans.csv")
	var out bytes.Buffer
	loc := time.FixedZone("CST", 8*60*60)
	if err := exportCSV(db, path, loc, Config{}, &out); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || strings.Join(records[0], ",") != "ip,protocols,banned_at,unban_at" || records[1][0] != "203.0.113.7" || records[1][2] != base.In(loc).Format(time.RFC3339) {
		t.Fatalf("CSV records = %v", records)
	}
	if err := exportCSV(db, path, loc, Config{}, &out); err == nil || !strings.Contains(err.Error(), "must not already exist") {
		t.Fatalf("overwrite error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("CSV mode = %v, %v", info, err)
	}
}
