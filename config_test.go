package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func testKey(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestParseConfigAndIPC(t *testing.T) {
	priv := testKey(t)
	pub := testKey(t)
	psk := testKey(t)

	conf := `
# a comment
[Interface]
PrivateKey = ` + priv + `
Address = 10.66.66.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 25
H1 = 123
ContentPaddingAddition = 16-32
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = ` + pub + `
PresharedKey = ` + psk + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`

	cfg, err := parseConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	ipc, err := cfg.ipcString()
	if err != nil {
		t.Fatalf("ipcString: %v", err)
	}

	privHex := hexOfBase64(t, priv)
	pubHex := hexOfBase64(t, pub)
	pskHex := hexOfBase64(t, psk)

	for _, want := range []string{
		"private_key=" + privHex,
		"jc=4",
		"jmin=40",
		"jmax=70",
		"s1=15",
		"s2=25",
		"h1=123",
		"content_padding_addition=16-32",
		"random_trailers=true",
		"disable_cookies=true",
		"public_key=" + pubHex,
		"preshared_key=" + pskHex,
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"endpoint=vpn.example.com:51820",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(ipc, want) {
			t.Errorf("ipc output missing %q\n---\n%s", want, ipc)
		}
	}
}

func TestAddressesDNSMTU(t *testing.T) {
	conf := `
[Interface]
PrivateKey = ` + testKey(t) + `
Address = 10.66.66.2/24, fd00::2
DNS = 1.1.1.1
MTU = 1300
`
	cfg, err := parseConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	addrs, err := cfg.addresses()
	if err != nil {
		t.Fatalf("addresses: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
	if got := addrs[0].String(); got != "10.66.66.2" {
		t.Errorf("address[0] = %q", got)
	}
	if got := addrs[1].String(); got != "fd00::2" {
		t.Errorf("address[1] = %q", got)
	}

	dns, err := cfg.dnsServers()
	if err != nil {
		t.Fatalf("dnsServers: %v", err)
	}
	if len(dns) != 1 || dns[0].String() != "1.1.1.1" {
		t.Errorf("dns = %v", dns)
	}

	mtu, err := cfg.mtu(1420)
	if err != nil {
		t.Fatalf("mtu: %v", err)
	}
	if mtu != 1300 {
		t.Errorf("mtu = %d, want 1300", mtu)
	}
}

func TestMTUDefault(t *testing.T) {
	cfg, err := parseConfig(strings.NewReader("[Interface]\nPrivateKey = " + testKey(t) + "\n"))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	mtu, err := cfg.mtu(1420)
	if err != nil {
		t.Fatalf("mtu: %v", err)
	}
	if mtu != 1420 {
		t.Errorf("mtu = %d, want 1420", mtu)
	}
}

func hexOfBase64(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return hex.EncodeToString(raw)
}
