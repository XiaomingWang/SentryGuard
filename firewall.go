package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// firewallRule is a rule owned by SentryGuard. Port -1 means all traffic.
type firewallRule struct {
	backend string
	ip      string
	port    int
}

var errFirewallToolMissing = errors.New("firewall command unavailable")

func commandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func installed(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func firewallBackend() string {
	if installed("firewall-cmd") {
		if out, err := commandOutput("firewall-cmd", "--state"); err == nil && strings.TrimSpace(out) == "running" {
			return "firewalld"
		}
	}
	if installed("ufw") {
		if out, err := commandOutput("ufw", "status"); err == nil && strings.HasPrefix(strings.ToLower(strings.TrimSpace(out)), "status: active") {
			return "ufw"
		}
	}
	if installed("nft") {
		return "nft"
	}
	if installed("iptables") {
		return "iptables"
	}
	return "none"
}

func desiredFirewallRules(backend string, ips []string, c Config) []firewallRule {
	return desiredFirewallRulesEntries(backend, defaultBanEntries(ips, c))
}

func desiredFirewallRulesEntries(backend string, entries []banEntry) []firewallRule {
	var rules []firewallRule
	for _, entry := range entries {
		ports := portsForProtocols(entry.protocols)
		if ports == nil {
			ports = []int{-1}
		}
		for _, port := range ports {
			rules = append(rules, firewallRule{backend: backend, ip: entry.ip, port: port})
		}
	}
	return rules
}

func storedFirewallRules(db *sql.DB) ([]firewallRule, error) {
	rows, err := db.Query(`SELECT backend,ip,port FROM firewall_rules ORDER BY backend,ip,port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []firewallRule
	for rows.Next() {
		var r firewallRule
		if err := rows.Scan(&r.backend, &r.ip, &r.port); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func iptablesArgs(r firewallRule) (string, []string, error) {
	addr, err := netip.ParseAddr(r.ip)
	if err != nil {
		return "", nil, err
	}
	name := "iptables"
	if addr.Is6() {
		name = "ip6tables"
	}
	args := []string{"-s", r.ip}
	if r.port != -1 {
		args = append(args, "-p", "tcp", "--dport", strconv.Itoa(r.port))
	}
	args = append(args, "-m", "comment", "--comment", "SentryGuard", "-j", "DROP")
	return name, args, nil
}

func firewalldArgs(r firewallRule, action string, permanent bool) ([]string, error) {
	addr, err := netip.ParseAddr(r.ip)
	if err != nil {
		return nil, err
	}
	family := "ipv4"
	if addr.Is6() {
		family = "ipv6"
	}
	args := []string{}
	if permanent {
		args = append(args, "--permanent")
	}
	args = append(args, "--direct", action, family, "filter", "INPUT", "0", "-s", r.ip)
	if r.port != -1 {
		args = append(args, "-p", "tcp", "--dport", strconv.Itoa(r.port))
	}
	args = append(args, "-m", "comment", "--comment", "SentryGuard", "-j", "DROP")
	return args, nil
}

func ufwArgs(r firewallRule, action string) []string {
	args := []string{}
	if action == "add" {
		args = append(args, "insert", "1")
	} else {
		args = append(args, "--force", "delete")
	}
	args = append(args, "deny", "from", r.ip, "to", "any")
	if r.port != -1 {
		args = append(args, "port", strconv.Itoa(r.port), "proto", "tcp")
	}
	args = append(args, "comment", "SentryGuard")
	return args
}

func ensureRule(r firewallRule) error {
	switch r.backend {
	case "iptables":
		name, match, err := iptablesArgs(r)
		if err != nil {
			return err
		}
		if !installed(name) {
			return fmt.Errorf("%s is needed to enforce ban for %s", name, r.ip)
		}
		if _, err := commandOutput(name, append([]string{"-w", "-C", "INPUT"}, match...)...); err == nil {
			return nil
		}
		_, err = commandOutput(name, append([]string{"-w", "-I", "INPUT", "1"}, match...)...)
		return err
	case "firewalld":
		for _, permanent := range []bool{true, false} {
			query, err := firewalldArgs(r, "--query-rule", permanent)
			if err != nil {
				return err
			}
			if _, err := commandOutput("firewall-cmd", query...); err == nil {
				continue
			}
			add, _ := firewalldArgs(r, "--add-rule", permanent)
			if _, err := commandOutput("firewall-cmd", add...); err != nil {
				return err
			}
		}
		return nil
	case "ufw":
		_, err := commandOutput("ufw", ufwArgs(r, "add")...)
		return err
	}
	return fmt.Errorf("unsupported firewall backend %q", r.backend)
}

func removeRule(r firewallRule) error {
	switch r.backend {
	case "iptables":
		name, match, err := iptablesArgs(r)
		if err != nil {
			return err
		}
		if !installed(name) {
			return fmt.Errorf("%w: %s", errFirewallToolMissing, name)
		}
		if _, err := commandOutput(name, append([]string{"-w", "-C", "INPUT"}, match...)...); err != nil {
			return nil
		}
		_, err = commandOutput(name, append([]string{"-w", "-D", "INPUT"}, match...)...)
		return err
	case "firewalld":
		if !installed("firewall-cmd") {
			return fmt.Errorf("%w: firewall-cmd", errFirewallToolMissing)
		}
		if out, err := commandOutput("firewall-cmd", "--state"); err != nil || strings.TrimSpace(out) != "running" {
			return fmt.Errorf("%w: firewalld is not running", errFirewallToolMissing)
		}
		for _, permanent := range []bool{true, false} {
			query, err := firewalldArgs(r, "--query-rule", permanent)
			if err != nil {
				return err
			}
			if _, err := commandOutput("firewall-cmd", query...); err != nil {
				continue
			}
			remove, _ := firewalldArgs(r, "--remove-rule", permanent)
			if _, err := commandOutput("firewall-cmd", remove...); err != nil {
				return err
			}
		}
		return nil
	case "ufw":
		if !installed("ufw") {
			return fmt.Errorf("%w: ufw", errFirewallToolMissing)
		}
		_, err := commandOutput("ufw", ufwArgs(r, "delete")...)
		return err
	}
	return fmt.Errorf("unknown stored firewall backend %q", r.backend)
}

func clearNftRules() error {
	if !installed("nft") {
		return nil
	}
	if err := nft("list", "table", "inet", "sentryguard"); err != nil {
		return nil
	}
	return nftScript("flush chain inet sentryguard input\nflush set inet sentryguard blocked4\nflush set inet sentryguard blocked6\n")
}

func syncManagedFirewall(db *sql.DB, ips []string, c Config) error {
	return syncManagedFirewallEntries(db, defaultBanEntries(ips, c), c)
}

func syncManagedFirewallEntries(db *sql.DB, entries []banEntry, c Config) error {
	backend := firewallBackend()
	previous, err := storedFirewallRules(db)
	if err != nil {
		return err
	}
	if backend != "nft" {
		if err := clearNftRules(); err != nil {
			return fmt.Errorf("remove old nft rules: %w", err)
		}
	}
	desired := []firewallRule{}
	if backend != "nft" && backend != "none" {
		desired = desiredFirewallRulesEntries(backend, entries)
	}
	want := make(map[firewallRule]bool, len(desired))
	for _, r := range desired {
		want[r] = true
	}
	known := make(map[firewallRule]bool, len(previous))
	for _, r := range previous {
		known[r] = true
		if want[r] {
			continue
		}
		if err := removeRule(r); err != nil {
			if errors.Is(err, errFirewallToolMissing) {
				log.Printf("warning: cannot remove prior %s rule for %s while its command is unavailable", r.backend, r.ip)
				continue
			}
			return fmt.Errorf("remove %s rule for %s: %w", r.backend, r.ip, err)
		}
		if _, err := db.Exec(`DELETE FROM firewall_rules WHERE backend=? AND ip=? AND port=?`, r.backend, r.ip, r.port); err != nil {
			return err
		}
	}
	if backend == "nft" {
		return syncFirewallEntries(entries, c)
	}
	if backend == "none" {
		nftWarning.Do(func() {
			log.Print("warning: no active firewalld/ufw or installed nftables/iptables; only hosts.deny will be updated (SSH may not be blocked)")
		})
		return nil
	}
	sort.Slice(desired, func(i, j int) bool {
		if desired[i].ip == desired[j].ip {
			return desired[i].port < desired[j].port
		}
		return desired[i].ip < desired[j].ip
	})
	for _, r := range desired {
		if r.backend == "ufw" && known[r] {
			continue // UFW persists rules and has no stable rule identity for a cheap existence check.
		}
		if err := ensureRule(r); err != nil {
			return fmt.Errorf("add %s rule for %s: %w", backend, r.ip, err)
		}
		if !known[r] {
			if _, err := db.Exec(`INSERT INTO firewall_rules(backend,ip,port) VALUES(?,?,?)`, r.backend, r.ip, r.port); err != nil {
				return err
			}
		}
	}
	return nil
}
