package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

const defaultMTU = 1420

func main() {
	var (
		configPath  = flag.String("config", envOr("AWG_CONFIG", ""), "path to the config file (.conf INI or AmneziaVPN .vpn export)")
		listen      = flag.String("socks-listen", envOr("PROXY_LISTEN", "127.0.0.1:1080"), "SOCKS5 listen address (empty to disable)")
		httpListen  = flag.String("http-listen", envOr("HTTP_PROXY_LISTEN", "127.0.0.1:8080"), "HTTP proxy listen address (empty to disable)")
		verbose     = flag.Bool("verbose", false, "enable verbose (debug) logging")
		dialTimeout = flag.Duration("dial-timeout", 30*time.Second, "timeout for establishing tunnel connections")
	)
	flag.Parse()

	if *configPath == "" {
		log.Fatal("no config file specified: use -config or set AWG_CONFIG")
	}

	logLevel := device.LogLevelError
	if *verbose {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, "awg-proxy: ")

	cfgReader, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg, err := parseConfig(cfgReader)
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}

	ipc, err := cfg.ipcString()
	if err != nil {
		log.Fatalf("build config: %v", err)
	}

	localAddrs, err := cfg.addresses()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if len(localAddrs) == 0 {
		log.Fatal("config: Interface.Address is required")
	}

	dns, err := cfg.dnsServers()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	mtu, err := cfg.mtu(defaultMTU)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Create a userspace network stack instead of a real TUN device, so the
	// container needs no TUN device or NET_ADMIN capability.
	tun, tnet, err := netstack.CreateNetTUN(localAddrs, dns, mtu)
	if err != nil {
		log.Fatalf("create netstack: %v", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(ipc); err != nil {
		log.Fatalf("configure device: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("start device: %v", err)
	}
	defer dev.Close()

	logger.Verbosef("AmneziaWG device up (mtu=%d)", mtu)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *listen != "" {
		server := &socksServer{
			listen:  *listen,
			dial:    tnet.DialContext,
			timeout: *dialTimeout,
		}
		go func() {
			log.Printf("SOCKS5 proxy listening on %s", *listen)
			if err := server.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
				log.Fatalf("SOCKS5 server: %v", err)
			}
		}()
	}

	if *httpListen != "" {
		hp := &httpProxy{
			listen:  *httpListen,
			dial:    tnet.DialContext,
			timeout: *dialTimeout,
		}
		go func() {
			log.Printf("HTTP proxy listening on %s", *httpListen)
			if err := hp.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
				log.Fatalf("HTTP proxy server: %v", err)
			}
		}()
	}

	<-ctx.Done()
	log.Printf("shutting down")
}

// envOr returns the value of the environment variable key, or def if unset.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
