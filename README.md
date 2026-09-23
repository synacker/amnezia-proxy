# amnezia-proxy

A standalone, single-binary AmneziaWG client that exposes **SOCKS5** and **HTTP**
proxies. Run AmneziaVPN on a host and share the tunnel with other apps or
machines — no TUN device, no kernel module, no `NET_ADMIN` capability required.

It is built on top of
[`amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go)'s `tun/netstack`
package (gVisor), which runs the entire network stack in userspace. It is the
"wireproxy" pattern adapted for AmneziaWG's DPI-resistant obfuscation.

## Features

- **SOCKS5 proxy** (`:1080`) — TCP `CONNECT`.
- **HTTP proxy** (`:8080`) — HTTPS via `CONNECT` (full tunnel) and plain HTTP
  forwarding.
- **AmneziaWG obfuscation** — junk packets, message padding, header ranges, and
  custom signature packets are all supported.
- **User-space proxy** — runs without needing root privileges or a separate `tun0` interface.

## Architecture

```
client ──SOCKS5 (1080)──▶
        ──HTTP  (8080)──▶  amnezia-proxy ──AmneziaWG (obfuscated UDP)──▶ VPN server ──▶ internet
```

```
 1. Read an AmneziaWG .conf (wg-quick INI + AmneziaWG extras)
 2. Bring up an in-process AmneziaWG device over a userspace netstack
 3. Listen on SOCKS5 + HTTP and route every connection through the tunnel
```

## Quick start

```sh
# build
go build -o awg-proxy .

# run (with your config)
./awg-proxy -config ./config.vpn

# verify
curl --socks5 127.0.0.1:1080 https://ifconfig.me
curl -x http://127.0.0.1:8080 https://ifconfig.me
```

The public IP reported by `ifconfig.me` should be the VPN server's, not your
own.

## Configuration

`amnezia-proxy` accepts two config formats (detected automatically from the
file contents):

1. **AmneziaVPN export** — the `vpn://...` file produced by the app's
   **Share** button (a `.vpn` file). Point `-config` at it directly; it's
decoded to INI on the fly.
2. **wg-quick INI** — a `.conf` with the standard `[Interface]`/`[Peer]`
   sections plus AmneziaWG obfuscation extras. See
   [`example.conf`](example.conf) for a copy.

```ini
[Interface]
PrivateKey = <base64 private key>
Address    = 10.66.66.2/32
DNS        = 1.1.1.1, 8.8.8.8
Jc         = 4
Jmin       = 40
Jmax       = 70
S1         = 15
S2         = 25
H1         = 123
H2         = 456
H3         = 789
H4         = 1011

[Peer]
PublicKey           = <base64 server public key>
PresharedKey        = <base64 preshared key>
AllowedIPs          = 0.0.0.0/0
Endpoint            = vpn.example.com:51820
PersistentKeepalive = 25
```

`PrivateKey`/`PublicKey`/`PresharedKey` are base64 (as exported); the parser
converts them to the hex form the device expects.

### AmneziaWG parameters

| Key                     | Type             | Side     | Description                                             |
| ----------------------- | ---------------- | -------- | ------------------------------------------------------- |
| `Jc`                    | int              | client   | Junk packets sent before each handshake (4–12 typical)  |
| `Jmin`, `Jmax`          | int              | client   | Random junk packet size range (`Jmin <= Jmax`)          |
| `S1`–`S4`               | int              | server   | Padding for init / response / cookie / transport msgs   |
| `H1`–`H4`               | uint32 range     | server   | Message header (type) overrides                        |
| `I1`–`I5`               | tag string       | client   | Custom signature packets (see below)                    |
| `HeaderProtectionKey`   | base64/hex key   | server   | Header protection key (needs `S1`–`S4` >= 12)           |
| `RandomTrailers`        | bool (`on`/`off`)| server   | Add and accept random-length trailers (must match)      |
| `DisableCookies`        | bool (`on`/`off`)| server   | Disable cookie-reply DoS mitigation (must match)        |
| `ContentPaddingAddition`| uint32 range     | client   | Extra content padding                                   |
| `RekeyAfterTime`        | uint32 range (s) | client   | Time before client rekeys                               |
| `RekeyTimeout`          | uint32 range (s) | client   | Handshake retry timeout                                 |
| `RejectAfterTime`       | uint32 range (s) | client   | Force handshake / reject data after this long           |
| `KeepaliveTimeout`      | uint32 range (s) | client   | Idle keepalive interval                                 |
| `MaxHandshakeAttempts`  | uint32 range     | client   | Max handshake attempts                                  |
| `PersistentKeepalive`   | uint32 range (s) | client   | Peer keepalive interval                                 |

> **Server-side** values (`S1`–`S4`, `H1`–`H4`, `HeaderProtectionKey`,
> `RandomTrailers`, `DisableCookies`) must match the server exactly or the
> handshake will fail. **Client-side** values can be set freely.

`I1`–`I5` are custom signature packets sent before each handshake, built from
tags: `<b 0xHEX>` (static bytes), `<r N>` (random bytes), `<rd N>` (random
digits), `<rc N>` (random letters), and `<t>` (4-byte timestamp). Example:

```
I1 = <b 0x0123456789abcdef><r 16><t>
```

## Flags / environment

| Flag            | Env                 | Default        | Description                                          |
| --------------- | ------------------- | -------------- | ---------------------------------------------------- |
| `-config`       | `AWG_CONFIG`        | *(required)*   | Path to the config file (`.conf` INI or `.vpn` export) |
| `-socks-listen` | `PROXY_LISTEN`      | `127.0.0.1:1080` | SOCKS5 listen address (empty disables)               |
| `-http-listen`  | `HTTP_PROXY_LISTEN` | `127.0.0.1:8080` | HTTP proxy listen address (empty disables)           |
| `-dial-timeout` |                     | `30s`          | Tunnel dial timeout                                  |
| `-verbose`      |                     | `false`        | Verbose device logging                               |

Set `-socks-listen ""` or `-http-listen ""` to disable the corresponding proxy.

## systemd

Build, install, and run the proxy as a systemd **user** service (no root
required) with the Makefile:

```sh
make build
make install
make deploy CONFIG="$HOME/.vpn/amnezia-proxy.vpn"
```

`deploy` builds and installs the binary to `~/.local/bin`, writes a user unit
pointing at `CONFIG`, enables + starts the service, and enables lingering so it
survives logout/reboot.

### Targets

| Target          | Description                                              |
| --------------- | -------------------------------------------------------- |
| `make build`    | Build the binary to `./amnezia-proxy`                    |
| `make install`  | Install the binary to `~/.local/bin/amnezia-proxy`       |
| `make deploy`   | Install + write/start the systemd user unit (needs `CONFIG`) |
| `make clean`    | Stop and remove the unit and the binary                  |

`deploy` variables:

| Variable     | Default      | Description                                       |
| ------------ | ------------ | ------------------------------------------------- |
| `CONFIG`     | *(required)* | Path to your AmneziaWG config (`.vpn` or `.conf`) |
| `SOCKS_PORT` | `1080`       | SOCKS5 proxy port                                 |
| `HTTP_PORT`  | `8080`       | HTTP proxy port                                   |

Example with custom ports:

```sh
make deploy CONFIG="$HOME/.vpn/amnezia-proxy.vpn" \
  SOCKS_PORT=11080 HTTP_PORT=18080
```

Verify:

```sh
systemctl --user status amnezia-proxy
curl --socks5 127.0.0.1:1080 https://ifconfig.me
curl -x http://127.0.0.1:8080 https://ifconfig.me
```

Remove everything:

```sh
make clean
```

### Manual install

A reference unit is at [`deploy/amnezia-proxy.service`](deploy/amnezia-proxy.service).
You can install it by hand instead of using `make`:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o ~/.local/bin/amnezia-proxy .
mkdir -p ~/.config/systemd/user
install -m 0644 deploy/amnezia-proxy.service ~/.config/systemd/user/
# edit the unit so -config points at your config file
systemctl --user daemon-reload
systemctl --user enable --now amnezia-proxy
loginctl enable-linger "$USER"   # keep running after logout / across reboots
```

For a **system service** (starts at boot before login, needs root), copy the
unit to `/etc/systemd/system/`, replace `%h` with the absolute home path, add a
`User=` line, then run `systemctl daemon-reload && systemctl enable --now
amnezia-proxy`.

## Troubleshooting

**`Handshake did not complete after 5 seconds, retrying`** — the tunnel is up
but the VPN server isn't answering the AmneziaWG handshake. Check that:

1. the server is running and reachable on UDP `Endpoint`,
2. your `PublicKey`/`PrivateKey` are still authorized,
3. the server-side params (`S1`–`S4`, `H1`–`H4`, `HeaderProtectionKey`) match
   the server.

**`bind: address already in use`** — the proxy port is taken by another process.
Pick a different one with `-socks-listen`/`-http-listen`.

**Requests hang / `host unreachable`** — usually the handshake hasn't completed
(see above). Run with `-verbose` to watch handshake progress.

**DNS fails** — the `DNS` entries in the config must be numeric IPs; hostnames
aren't supported by the netstack resolver.

## Limitations

- **TCP only** — SOCKS5 `CONNECT`, HTTP `CONNECT` (HTTPS), and plain HTTP
  forwarding. No `BIND`, UDP-over-SOCKS, or UDP tunneling.
- Plain HTTP forwarding is not keep-alive optimized (one request/response per
  proxy connection); HTTPS `CONNECT` and SOCKS5 are long-lived tunnels.
- DNS in the config must be numeric IPs.
- Split-tunnel via `AllowedIPs` is possible, but the netstack installs a default
  route, so traffic outside `AllowedIPs` is dropped rather than leaked.

## Layout

```
Software/
├── amnezia-proxy/     # this module (standalone Go module)
└── amneziawg-go/      # dependency (local checkout, via go.mod replace)
```

Requires Go and fetches `amneziawg-go` from GitHub.
