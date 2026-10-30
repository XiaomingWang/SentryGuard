package main

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"
)

func changeBanProtocols(db *sql.DB, c Config, ip string, ban bool, requested []string, duration time.Duration) error {
	if len(requested) == 0 {
		requested = c.BanProtocols
	}
	if len(requested) == 0 {
		requested = []string{"SSH"}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var override, until string
	err = tx.QueryRow(`SELECT COALESCE(p.protocols,''),b.unban_at FROM bans b LEFT JOIN ban_protocol_overrides p ON p.ip=b.ip WHERE b.ip=?`, ip).Scan(&override, &until)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	current := []string{}
	if err == nil && until > time.Now().UTC().Format(time.RFC3339) {
		current = c.BanProtocols
		if len(current) == 0 {
			current = []string{"SSH"}
		}
		if override != "" {
			current = strings.Split(override, ",")
		}
	}
	result := []string{}
	if ban {
		all := false
		seen := map[string]bool{}
		for _, name := range append(append([]string{}, current...), requested...) {
			if name == "ALL" {
				all = true
			}
			if !seen[name] {
				result = append(result, name)
				seen[name] = true
			}
		}
		if all {
			result = []string{"ALL"}
		}
		now := time.Now()
		if _, err := tx.Exec(`INSERT INTO bans(ip,banned_at,unban_at) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET banned_at=excluded.banned_at,unban_at=excluded.unban_at`, ip, now.UTC().Format(time.RFC3339), expiry(now, duration)); err != nil {
			return err
		}
	} else {
		removeAll := len(requested) == 1 && requested[0] == "ALL"
		if len(current) == 1 && current[0] == "ALL" && !removeAll {
			return fmt.Errorf("%s is banned for ALL traffic; partial unban is not supported for ALL bans; use 'unban %s --protocols ALL'", ip, ip)
		}
		for _, name := range current {
			remove := removeAll
			for _, r := range requested {
				if r == name {
					remove = true
				}
			}
			if !remove {
				result = append(result, name)
			}
		}
	}
	if len(result) == 0 {
		if _, err := tx.Exec(`DELETE FROM bans WHERE ip=?`, ip); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`INSERT INTO ban_protocol_overrides(ip,protocols) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET protocols=excluded.protocols`, ip, strings.Join(result, ",")); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func resetBans(db *sql.DB, c Config, in io.Reader, out io.Writer) error {
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM bans`).Scan(&count); err != nil {
		return fmt.Errorf("count bans before reset: %w", err)
	}
	if count == 0 {
		fmt.Fprintln(out, "No banned IPs to reset.")
		return nil
	}
	fmt.Fprintf(out, "WARNING: This will permanently remove all %d banned IPs and their SentryGuard firewall and hosts.deny rules. This action cannot be undone.\nType RESET to confirm: ", count)
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read reset confirmation: %w", err)
	}
	if strings.TrimSpace(answer) != "RESET" {
		fmt.Fprintln(out, "Cancelled. No bans were removed.")
		return nil
	}
	if _, err := db.Exec(`DELETE FROM bans`); err != nil {
		return fmt.Errorf("clear ban list: %w", err)
	}
	if err := reconcile(db, c); err != nil {
		return fmt.Errorf("ban list cleared, but firewall/hosts.deny cleanup failed: %w", err)
	}
	fmt.Fprintf(out, "Removed %d banned IP(s).\n", count)
	return nil
}

func exportCSV(db *sql.DB, path string, loc *time.Location, c Config, out io.Writer) error {
	rows, err := db.Query(`SELECT b.ip,COALESCE(p.protocols,''),b.banned_at,b.unban_at FROM bans b LEFT JOIN ban_protocol_overrides p ON p.ip=b.ip WHERE b.unban_at > ? ORDER BY b.ip`, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("read ban list for export: %w", err)
	}
	defer rows.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create export file %q (it must not already exist): %w", path, err)
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			os.Remove(path)
		}
	}()
	w := csv.NewWriter(f)
	if err := w.Write([]string{"ip", "protocols", "banned_at", "unban_at"}); err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var ip, protocols, bannedText, unbanText string
		if err := rows.Scan(&ip, &protocols, &bannedText, &unbanText); err != nil {
			return err
		}
		if protocols == "" {
			protocols = strings.Join(c.BanProtocols, ",")
			if protocols == "" {
				protocols = "SSH"
			}
		}
		bannedAt, err := time.Parse(time.RFC3339, bannedText)
		if err != nil {
			return fmt.Errorf("invalid stored banned_at for %s: %w", ip, err)
		}
		unbanAt, err := time.Parse(time.RFC3339, unbanText)
		if err != nil {
			return fmt.Errorf("invalid stored unban_at for %s: %w", ip, err)
		}
		if err := w.Write([]string{ip, protocols, bannedAt.In(loc).Format(time.RFC3339), unbanAt.In(loc).Format(time.RFC3339)}); err != nil {
			return err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	success = true
	fmt.Fprintf(out, "Exported %d active banned IPs to %s.\n", count, path)
	return nil
}

func importCSV(db *sql.DB, path string, loc *time.Location, c Config, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open import file %q: %w", path, err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read CSV header: %w", err)
	}
	columns := make(map[string]int, len(header))
	for i, name := range header {
		name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "\ufeff")))
		if name == "ban_protocols" {
			name = "protocols"
		}
		switch name {
		case "ip", "protocols", "banned_at", "unban_at":
		default:
			return fmt.Errorf("unknown CSV column %q", header[i])
		}
		if _, exists := columns[name]; exists {
			return fmt.Errorf("duplicate CSV column %q", name)
		}
		columns[name] = i
	}
	if _, ok := columns["ip"]; !ok {
		return errors.New("CSV must have an ip column")
	}
	value := func(row []string, name string) string {
		if i, ok := columns[name]; ok {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	seen := make(map[string]bool)
	imported, skipped := 0, 0
	for line := 2; ; line++ {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("CSV record %d: %w", line, err)
		}
		addr, err := netip.ParseAddr(value(row, "ip"))
		if err != nil || addr.Zone() != "" || addr.IsLoopback() || addr.IsUnspecified() {
			return fmt.Errorf("CSV record %d: invalid ban IP %q (use one non-loopback IPv4 or IPv6 address)", line, value(row, "ip"))
		}
		ip := addr.Unmap().String()
		if seen[ip] {
			return fmt.Errorf("CSV record %d: duplicate IP %s", line, ip)
		}
		seen[ip] = true
		protocolText := value(row, "protocols")
		if protocolText != "" {
			protocols, err := normalizeProtocols(strings.Split(protocolText, ","))
			if err != nil {
				return fmt.Errorf("CSV record %d, IP %s: %w", line, ip, err)
			}
			protocolText = strings.Join(protocols, ",")
		}
		bannedAt := now
		if input := value(row, "banned_at"); input != "" {
			bannedAt, err = parseDateTime(input, loc)
			if err != nil {
				return fmt.Errorf("CSV record %d, banned_at: %w", line, err)
			}
		}
		unbanAt := forever
		if input := value(row, "unban_at"); input != "" && !strings.EqualFold(input, "permanent") {
			parsed, err := parseDateTime(input, loc)
			if err != nil {
				return fmt.Errorf("CSV record %d, unban_at: %w", line, err)
			}
			if !parsed.After(now) || !parsed.After(bannedAt) {
				return fmt.Errorf("CSV record %d: unban_at must be later than now and banned_at", line)
			}
			unbanAt = parsed.UTC().Format(time.RFC3339)
		}
		if c.isWhitelisted(ip) {
			skipped++
			continue
		}
		if _, err := tx.Exec(`INSERT INTO bans(ip,banned_at,unban_at) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET banned_at=excluded.banned_at,unban_at=excluded.unban_at`, ip, bannedAt.UTC().Format(time.RFC3339), unbanAt); err != nil {
			return fmt.Errorf("CSV record %d: save ban: %w", line, err)
		}
		if protocolText == "" {
			if _, err := tx.Exec(`DELETE FROM ban_protocol_overrides WHERE ip=?`, ip); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`INSERT INTO ban_protocol_overrides(ip,protocols) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET protocols=excluded.protocols`, ip, protocolText); err != nil {
			return fmt.Errorf("CSV record %d: save protocols: %w", line, err)
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := reconcile(db, c); err != nil {
		return fmt.Errorf("%d IPs imported, but enforcement sync failed: %w", imported, err)
	}
	fmt.Fprintf(out, "Imported %d banned IPs; skipped %d whitelisted IPs.\n", imported, skipped)
	return nil
}
