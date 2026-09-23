package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeVPNURI wraps a JSON document in the AmneziaVPN vpn:// encoding
// (base64url of a qCompress-style blob: 4-byte length + zlib stream).
func makeVPNURI(t *testing.T, jsonData string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(jsonData)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	payload := make([]byte, 4, 4+buf.Len())
	binary.BigEndian.PutUint32(payload, uint32(len(jsonData)))
	payload = append(payload, buf.Bytes()...)
	return "vpn://" + base64.RawURLEncoding.EncodeToString(payload)
}

func TestVPNToINI(t *testing.T) {
	last := awgLastConfig{
		Config: "[Interface]\nAddress = 10.8.1.8/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nPrivateKey = <priv>\nJc = 5\n\n[Peer]\nPublicKey = <pub>\nPresharedKey = <psk>\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\nPersistentKeepalive = 25\n",
		MTU:    "1376",
	}
	lastBytes, err := json.Marshal(last)
	if err != nil {
		t.Fatalf("marshal last_config: %v", err)
	}
	awgBytes, err := json.Marshal(awgBlock{LastConfig: string(lastBytes)})
	if err != nil {
		t.Fatalf("marshal awg: %v", err)
	}
	exp := vpnExport{
		Containers: []vpnContainer{{AWG: awgBytes}},
		DNS1:       "1.1.1.1",
		DNS2:       "1.0.0.1",
	}
	expBytes, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	ini, err := vpnToINI(makeVPNURI(t, string(expBytes)))
	if err != nil {
		t.Fatalf("vpnToINI: %v", err)
	}

	for _, want := range []string{
		"Address = 10.8.1.8/32",
		"DNS = 1.1.1.1, 1.0.0.1",
		"MTU = 1376",
		"PrivateKey = <priv>",
		"PublicKey = <pub>",
		"PresharedKey = <psk>",
		"Endpoint = 1.2.3.4:51820",
	} {
		if !strings.Contains(ini, want) {
			t.Errorf("decoded ini missing %q\n---\n%s", want, ini)
		}
	}

	if strings.Contains(ini, "$PRIMARY_DNS") || strings.Contains(ini, "$SECONDARY_DNS") {
		t.Errorf("DNS placeholders not substituted:\n%s", ini)
	}
}

func TestLoadConfigVPN(t *testing.T) {
	last := awgLastConfig{
		Config: "[Interface]\nPrivateKey = " + testKey(t) + "\nAddress = 10.8.1.8/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\n\n[Peer]\nPublicKey = " + testKey(t) + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n",
	}
	lastBytes, _ := json.Marshal(last)
	awgBytes, _ := json.Marshal(awgBlock{LastConfig: string(lastBytes)})
	exp, _ := json.Marshal(vpnExport{
		Containers: []vpnContainer{{AWG: awgBytes}},
		DNS1:       "1.1.1.1",
		DNS2:       "1.0.0.1",
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "config.vpn")
	if err := os.WriteFile(path, []byte(makeVPNURI(t, string(exp))), 0o644); err != nil {
		t.Fatalf("write vpn file: %v", err)
	}

	r, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	cfg, err := parseConfig(r)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if _, err := cfg.ipcString(); err != nil {
		t.Fatalf("ipcString: %v", err)
	}
}

func TestLoadConfigPlainINI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	ini := "[Interface]\nPrivateKey = " + testKey(t) + "\nAddress = 10.8.1.8/32\n\n[Peer]\nPublicKey = " + testKey(t) + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n"
	if err := os.WriteFile(path, []byte(ini), 0o644); err != nil {
		t.Fatalf("write ini: %v", err)
	}

	r, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	cfg, err := parseConfig(r)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if _, err := cfg.ipcString(); err != nil {
		t.Fatalf("ipcString: %v", err)
	}
}
