package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// startHTTPProxy starts the httpProxy handler on an ephemeral loopback port
// and returns its address. The provided dial function is used for upstream
// connections.
func startHTTPProxy(t *testing.T, dial dialFunc) string {
	t.Helper()
	p := &httpProxy{dial: dial}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func directDial(ctx context.Context, network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func TestHTTPProxyPlainForwarding(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello-http")
	}))
	defer origin.Close()

	proxyAddr := startHTTPProxy(t, directDial)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-http" {
		t.Errorf("body = %q, want %q", body, "hello-http")
	}
}

func TestHTTPProxyConnect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello-https")
	}))
	defer origin.Close()

	proxyAddr := startHTTPProxy(t, directDial)

	// origin.Client() already trusts the test TLS certificate.
	client := origin.Client()
	client.Timeout = 5 * time.Second
	client.Transport.(*http.Transport).Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET via CONNECT proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-https" {
		t.Errorf("body = %q, want %q", body, "hello-https")
	}
}
