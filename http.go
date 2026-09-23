package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// httpProxy is a minimal HTTP/1.x forward proxy. It supports CONNECT
// (tunneling for HTTPS and arbitrary TCP) and plain HTTP forwarding for
// absolute-form requests.
type httpProxy struct {
	listen  string
	dial    dialFunc
	timeout time.Duration
}

// ListenAndServe runs the HTTP proxy until ctx is canceled.
func (p *httpProxy) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.listen)
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
		go p.handleConn(conn)
	}
}

func (p *httpProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, br, req)
		return
	}

	p.forward(conn, req)
}

func (p *httpProxy) handleConnect(client net.Conn, br *bufio.Reader, req *http.Request) {
	target := req.Host
	if target == "" {
		target = req.URL.Host
	}
	target = ensurePort(target, "443")

	ctx, cancel := p.dialContext()
	defer cancel()

	upstream, err := p.dial(ctx, "tcp", target)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// br may hold bytes read beyond the CONNECT headers (e.g. the first TLS
	// ClientHello); relay through it so nothing is lost.
	tunnel(client, br, upstream)
}

// forward handles a plain (non-CONNECT) HTTP request. One request/response is
// relayed per client connection; keep-alive between the client and the proxy
// is not maintained for plain HTTP.
func (p *httpProxy) forward(client net.Conn, req *http.Request) {
	host := req.URL.Hostname()
	if host == "" {
		host = req.Host
	}
	if host == "" {
		io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}

	port := req.URL.Port()
	if port == "" {
		port = "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
	}

	ctx, cancel := p.dialContext()
	defer cancel()

	upstream, err := p.dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()

	// Strip proxy-specific headers and force a single-shot exchange.
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "close")

	if err := req.Write(upstream); err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()

	resp.Header.Set("Connection", "close")
	_ = resp.Write(client)
}

func (p *httpProxy) dialContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	if p.timeout > 0 {
		return context.WithTimeout(ctx, p.timeout)
	}
	return ctx, func() {}
}

// tunnel relays bytes between the client and the upstream connection. The
// client side is read through br (which may already have buffered bytes beyond
// the CONNECT headers), while writes go straight to the client connection.
func tunnel(client net.Conn, br *bufio.Reader, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, br)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
}

func ensurePort(hostport, defaultPort string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, defaultPort)
}
