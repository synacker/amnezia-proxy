package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// AmneziaVPN's "Share / export" format is a vpn:// URI whose payload is the
// base64url encoding of a qCompress blob: a 4-byte big-endian uncompressed
// length followed by a zlib stream containing a JSON document. This file
// decodes that format into the wg-quick INI form parseConfig understands, so a
// single config path can point at either a plain INI file or a .vpn export.

// vpnExport mirrors the top-level fields of the decoded JSON we need.
type vpnExport struct {
	Containers []vpnContainer `json:"containers"`
	DNS1       string         `json:"dns1"`
	DNS2       string         `json:"dns2"`
}

// vpnContainer holds the AmneziaWG block (keyed "awg") of a container.
type vpnContainer struct {
	AWG json.RawMessage `json:"awg"`
}

// awgBlock is the per-container AmneziaWG configuration.
type awgBlock struct {
	LastConfig string `json:"last_config"`
}

// awgLastConfig is the JSON document (stored as a string inside "last_config")
// that holds the rendered wg-quick INI config and the MTU.
type awgLastConfig struct {
	Config string `json:"config"`
	MTU    string `json:"mtu"`
}

// loadConfig reads the config at path, transparently decoding an AmneziaVPN
// "vpn://" export into INI form. Plain INI files pass through unchanged.
func loadConfig(path string) (io.Reader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if bytes.HasPrefix(data, []byte("vpn://")) {
		ini, err := vpnToINI(string(data))
		if err != nil {
			return nil, fmt.Errorf("decode vpn:// config: %w", err)
		}
		return strings.NewReader(ini), nil
	}
	return bytes.NewReader(data), nil
}

// vpnToINI decodes a "vpn://..." export into an equivalent wg-quick INI config.
func vpnToINI(s string) (string, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "vpn://")

	raw, err := decodeVPNAuth(s)
	if err != nil {
		return "", err
	}

	// qCompress layout: 4-byte big-endian length, then a zlib stream.
	if len(raw) < 4 {
		return "", fmt.Errorf("vpn:// payload too short")
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		return "", fmt.Errorf("open zlib stream: %w", err)
	}
	jsonData, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		return "", fmt.Errorf("decompress vpn:// payload: %w", err)
	}

	var exp vpnExport
	if err := json.Unmarshal(jsonData, &exp); err != nil {
		return "", fmt.Errorf("parse vpn:// json: %w", err)
	}

	// Locate the AmneziaWG container block.
	var awg awgBlock
	found := false
	for _, c := range exp.Containers {
		if len(c.AWG) == 0 {
			continue
		}
		if err := json.Unmarshal(c.AWG, &awg); err != nil {
			return "", fmt.Errorf("parse awg container: %w", err)
		}
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("no AmneziaWG container in vpn:// export")
	}

	var last awgLastConfig
	if err := json.Unmarshal([]byte(awg.LastConfig), &last); err != nil {
		return "", fmt.Errorf("parse awg last_config: %w", err)
	}
	if last.Config == "" {
		return "", fmt.Errorf("vpn:// export contains no config")
	}

	ini := last.Config

	dns1, dns2 := exp.DNS1, exp.DNS2
	if dns1 == "" {
		dns1 = "1.1.1.1"
	}
	if dns2 == "" {
		dns2 = "1.0.0.1"
	}
	ini = strings.ReplaceAll(ini, "$PRIMARY_DNS", dns1)
	ini = strings.ReplaceAll(ini, "$SECONDARY_DNS", dns2)

	if last.MTU != "" && !hasConfigKey(ini, "mtu") {
		ini = insertMTU(ini, last.MTU)
	}

	return ini, nil
}

// decodeVPNAuth base64url-decodes the vpn:// payload, tolerating optional
// '=' padding.
func decodeVPNAuth(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 in vpn:// payload")
}

// hasConfigKey reports whether the INI text contains a line setting key.
func hasConfigKey(ini, key string) bool {
	for _, line := range strings.Split(ini, "\n") {
		line = strings.TrimSpace(line)
		if eq := strings.IndexByte(line, '='); eq > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:eq]), key) {
				return true
			}
		}
	}
	return false
}

// insertMTU inserts an "MTU = ..." line into the [Interface] section, right
// after the DNS line (or after [Interface] if there is no DNS line).
func insertMTU(ini, mtu string) string {
	lines := strings.Split(ini, "\n")
	out := make([]string, 0, len(lines)+1)
	inserted := false
	for _, line := range lines {
		out = append(out, line)
		if !inserted && strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "dns") {
			out = append(out, "MTU = "+mtu)
			inserted = true
		}
	}
	if inserted {
		return strings.Join(out, "\n")
	}

	// No DNS line: place it right after [Interface].
	out = make([]string, 0, len(lines)+1)
	for _, line := range lines {
		out = append(out, line)
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "[interface]") {
			out = append(out, "MTU = "+mtu)
		}
	}
	return strings.Join(out, "\n")
}
