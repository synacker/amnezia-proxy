package main

import (
	"testing"
)

func TestEnsurePort(t *testing.T) {
	if got := ensurePort("example.com:443", "443"); got != "example.com:443" {
		t.Errorf("ensurePort = %q", got)
	}
	if got := ensurePort("example.com", "443"); got != "example.com:443" {
		t.Errorf("ensurePort = %q", got)
	}
	if got := ensurePort("[::1]:8080", "443"); got != "[::1]:8080" {
		t.Errorf("ensurePort = %q", got)
	}
	if got := ensurePort("::1", "443"); got != "[::1]:443" {
		t.Errorf("ensurePort = %q", got)
	}
}
