package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// This is a minimal SOCKS5 server (RFC 1928) that supports CONNECT over TCP,
// which is sufficient for routing HTTP/HTTPS and most TCP traffic through the
// AmneziaWG tunnel. BIND and UDP ASSOCIATE are not implemented.

const (
	socksVersion = 0x05

	authNone         = 0x00
	authNoAcceptable = 0xff

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded            = 0x00
	repGeneralFailure       = 0x01
	repConnectionNotAllowed = 0x02
	repHostUnreachable      = 0x04
	repCommandNotSupported  = 0x07
	repAddrTypeNotSupported = 0x08
)

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type socksServer struct {
	listen  string
	dial    dialFunc
	timeout time.Duration
}

// ListenAndServe runs the SOCKS5 server until ctx is canceled.
func (s *socksServer) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *socksServer) handleConn(conn net.Conn) {
	defer conn.Close()

	if err := s.negotiate(conn); err != nil {
		return
	}

	cmd, host, port, err := s.readRequest(conn)
	if err != nil {
		_ = writeReply(conn, repGeneralFailure, netip.AddrPort{})
		return
	}

	switch cmd {
	case cmdConnect:
		// supported below
	default:
		_ = writeReply(conn, repCommandNotSupported, netip.AddrPort{})
		return
	}

	dialCtx := context.Background()
	if s.timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(dialCtx, s.timeout)
		defer cancel()
	}

	target := net.JoinHostPort(host, port)
	upstream, err := s.dial(dialCtx, "tcp", target)
	if err != nil {
		_ = writeReply(conn, repHostUnreachable, netip.AddrPort{})
		return
	}
	defer upstream.Close()

	if err := writeReply(conn, repSucceeded, addrPortFromNetAddr(upstream.LocalAddr())); err != nil {
		return
	}

	relay(conn, upstream)
}

func (s *socksServer) negotiate(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != socksVersion {
		return errors.New("unsupported SOCKS version")
	}

	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Only unauthenticated (no-auth) connections are supported.
	chosen := byte(authNoAcceptable)
	for _, m := range methods {
		if m == authNone {
			chosen = m
			break
		}
	}

	if _, err := conn.Write([]byte{socksVersion, chosen}); err != nil {
		return err
	}
	if chosen == authNoAcceptable {
		return errors.New("no acceptable authentication method")
	}
	return nil
}

// readRequest parses a SOCKS5 request, returning the command, destination host
// and destination port.
func (s *socksServer) readRequest(conn net.Conn) (cmd byte, host string, port string, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return 0, "", "", err
	}
	if hdr[0] != socksVersion {
		return 0, "", "", errors.New("unsupported SOCKS version")
	}

	cmd = hdr[1]
	switch hdr[3] {
	case atypIPv4:
		var b [4]byte
		if _, err = io.ReadFull(conn, b[:]); err != nil {
			return 0, "", "", err
		}
		host = net.IP(b[:]).String()
	case atypIPv6:
		var b [16]byte
		if _, err = io.ReadFull(conn, b[:]); err != nil {
			return 0, "", "", err
		}
		host = net.IP(b[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err != nil {
			return 0, "", "", err
		}
		name := make([]byte, int(l[0]))
		if _, err = io.ReadFull(conn, name); err != nil {
			return 0, "", "", err
		}
		host = string(name)
	default:
		return 0, "", "", errors.New("unsupported address type")
	}

	var pb [2]byte
	if _, err = io.ReadFull(conn, pb[:]); err != nil {
		return 0, "", "", err
	}
	port = strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))

	return cmd, host, port, nil
}

func writeReply(conn net.Conn, rep byte, bound netip.AddrPort) error {
	if !bound.IsValid() {
		bound = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}

	addr := bound.Addr().Unmap()
	var resp []byte
	if addr.Is4() {
		resp = make([]byte, 0, 10)
		resp = append(resp, socksVersion, rep, 0x00, atypIPv4)
		a4 := addr.As4()
		resp = append(resp, a4[:]...)
		resp = binary.BigEndian.AppendUint16(resp, bound.Port())
	} else {
		resp = make([]byte, 0, 22)
		resp = append(resp, socksVersion, rep, 0x00, atypIPv6)
		a16 := addr.As16()
		resp = append(resp, a16[:]...)
		resp = binary.BigEndian.AppendUint16(resp, bound.Port())
	}

	_, err := conn.Write(resp)
	return err
}

func addrPortFromNetAddr(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}

// relay copies data bidirectionally between the client and the upstream
// connection, preserving half-close semantics where supported.
func relay(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}
