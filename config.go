package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// rawConfig holds the parsed AmneziaWG / wg-quick style INI configuration.
//
// Keys are normalized to their lowercase alphanumeric form (e.g. both
// "PrivateKey" and "private_key" become "privatekey"), which mirrors the
// case-insensitive, separator-agnostic behaviour of wg-quick config files.
type rawConfig struct {
	iface map[string]string
	peers []map[string]string
}

// normalizeKey lowercases a config key and strips all non-alphanumeric
// characters so that "PrivateKey", "private_key" and "private-key" compare
// equal.
func normalizeKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseConfig reads an INI-style AmneziaWG configuration.
func parseConfig(r io.Reader) (*rawConfig, error) {
	cfg := &rawConfig{iface: make(map[string]string)}
	var cur *map[string]string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Strip inline comments. AmneziaWG values (base64 keys, hex byte
		// sequences, ranges) never contain '#' or ';', so this is safe.
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch name {
			case "interface":
				cur = &cfg.iface
			case "peer":
				cfg.peers = append(cfg.peers, make(map[string]string))
				cur = &cfg.peers[len(cfg.peers)-1]
			default:
				return nil, fmt.Errorf("unknown section %q", name)
			}
			continue
		}

		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("key %q appears outside of a section", line[:eq])
		}
		key := normalizeKey(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		(*cur)[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// keyToHex converts a base64-encoded key (as found in config files) into the
// hex encoding expected by the device's UAPI. It also accepts already-hex
// values, which some tools emit.
func keyToHex(value string) (string, error) {
	value = strings.TrimSpace(value)
	if decoded, err := hex.DecodeString(value); err == nil && len(value) == 64 {
		return strings.ToLower(hex.EncodeToString(decoded)), nil
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("key is neither base64 nor hex: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// ipcString renders the configuration into the UAPI "key=value\n..." format
// accepted by device.IpcSet.
func (c *rawConfig) ipcString() (string, error) {
	var b strings.Builder

	privateKey, err := keyToHex(c.iface["privatekey"])
	if err != nil {
		return "", fmt.Errorf("Interface.PrivateKey: %w", err)
	}
	b.WriteString("private_key=")
	b.WriteString(privateKey)

	// Device-level obfuscation, padding, header and timing parameters. Values
	// are passed through verbatim; the device validates them.
	for _, kv := range [][2]string{
		{"jc", "jc"},
		{"jmin", "jmin"},
		{"jmax", "jmax"},
		{"s1", "s1"},
		{"s2", "s2"},
		{"s3", "s3"},
		{"s4", "s4"},
		{"h1", "h1"},
		{"h2", "h2"},
		{"h3", "h3"},
		{"h4", "h4"},
		{"i1", "i1"},
		{"i2", "i2"},
		{"i3", "i3"},
		{"i4", "i4"},
		{"i5", "i5"},
		{"contentpaddingaddition", "content_padding_addition"},
		{"rekeyaftertime", "rekey_after_time"},
		{"rekeytimeout", "rekey_timeout"},
		{"rejectaftertime", "reject_after_time"},
		{"keepalivetimeout", "keepalive_timeout"},
		{"maxhandshakeattempts", "max_handshake_attempts"},
	} {
		if v, ok := c.iface[kv[0]]; ok && v != "" {
			b.WriteString("\n")
			b.WriteString(kv[1])
			b.WriteString("=")
			b.WriteString(v)
		}
	}

	// Boolean device flags use Amnezia's "on"/"off" convention in config files
	// but the device UAPI expects strconv.ParseBool-style values.
	for _, bv := range [][2]string{
		{"randomtrailers", "random_trailers"},
		{"disablecookies", "disable_cookies"},
	} {
		if v, ok := c.iface[bv[0]]; ok && v != "" {
			flag, err := parseBoolFlag(v)
			if err != nil {
				return "", fmt.Errorf("Interface.%s: %w", bv[0], err)
			}
			b.WriteString("\n")
			b.WriteString(bv[1])
			b.WriteString("=")
			b.WriteString(flag)
		}
	}

	if v, ok := c.iface["headerprotectionkey"]; ok && v != "" {
		h, err := keyToHex(v)
		if err != nil {
			return "", fmt.Errorf("Interface.HeaderProtectionKey: %w", err)
		}
		b.WriteString("\nheader_protection_key=")
		b.WriteString(h)
	}

	for i, peer := range c.peers {
		publicKey, err := keyToHex(peer["publickey"])
		if err != nil {
			return "", fmt.Errorf("Peer[%d].PublicKey: %w", i, err)
		}
		b.WriteString("\npublic_key=")
		b.WriteString(publicKey)

		if v, ok := peer["presharedkey"]; ok && v != "" {
			psk, err := keyToHex(v)
			if err != nil {
				return "", fmt.Errorf("Peer[%d].PresharedKey: %w", i, err)
			}
			b.WriteString("\npreshared_key=")
			b.WriteString(psk)
		}

		if v, ok := peer["endpoint"]; ok && v != "" {
			b.WriteString("\nendpoint=")
			b.WriteString(v)
		}

		for _, aip := range splitList(peer["allowedips"]) {
			b.WriteString("\nallowed_ip=")
			b.WriteString(aip)
		}

		if v, ok := peer["persistentkeepalive"]; ok && v != "" {
			b.WriteString("\npersistent_keepalive_interval=")
			b.WriteString(v)
		}
	}

	return b.String(), nil
}

// addresses returns the tunnel's local addresses from the Interface.Address
// field (comma-separated CIDRs or bare IPs).
func (c *rawConfig) addresses() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range splitList(c.iface["address"]) {
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p.Addr())
			continue
		}
		if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, a)
			continue
		}
		return nil, fmt.Errorf("invalid Interface.Address %q", part)
	}
	return out, nil
}

// dnsServers returns the DNS servers from the Interface.DNS field. Only IP
// addresses are supported (the netstack DNS resolver requires numeric servers).
func (c *rawConfig) dnsServers() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range splitList(c.iface["dns"]) {
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid Interface.DNS %q: %w", part, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// parseBoolFlag normalizes a boolean config value into the "true"/"false" form
// the device UAPI accepts. Amnezia configs use "on"/"off", but standard Go
// bool spellings are also tolerated.
func parseBoolFlag(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes":
		return "true", nil
	case "off", "false", "0", "no":
		return "false", nil
	}
	return "", fmt.Errorf("invalid boolean %q", v)
}

// mtu returns the configured MTU, or the supplied default if unset.
func (c *rawConfig) mtu(defaultMTU int) (int, error) {
	v, ok := c.iface["mtu"]
	if !ok || v == "" {
		return defaultMTU, nil
	}
	mtu, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid Interface.MTU %q: %w", v, err)
	}
	return mtu, nil
}

// splitList splits a comma-separated config value, trimming whitespace and
// dropping empty entries.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
