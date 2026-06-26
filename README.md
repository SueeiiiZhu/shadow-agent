# shadow-agent

**shadow-agent** is the data-plane / node-core binary of **Shadow Panel**, a
lightweight rewrite of trojan-panel-core. It runs on every proxy node, where it:

1. generates the config file for the chosen proxy kernel (Xray / Hysteria2 /
   sing-box / NaiveProxy),
2. (re)starts / stops the kernel process via `os/exec`,
3. reports node state and traffic back to the control plane.

The control plane (`shadow-panel`) drives it over **HTTPS REST** secured by a
**per-agent bearer token**.

- **module**: `github.com/SueeiiiZhu/shadow-agent`
- **Go**: 1.25
- **dependencies**: standard library only. No third-party packages — TLS, JSON,
  HTTP and process control are all stdlib.

## Why a rewrite — what changed vs trojan-panel-core

The old core had three structural limits that shadow-panel exists to fix:

| | trojan-panel-core (old) | shadow-agent (new) |
|---|---|---|
| Outbound | **hard-coded** `[{"protocol":"freedom"}]`; DTO has **no** outbound field | `NodeSpec.outbound` first-class: `freedom / socks / http / vless / vmess / trojan / shadowsocks` |
| Upstream chaining | none | **dialer-proxy chains** via `streamSettings.sockopt.dialerProxy` |
| Transport | no-TLS gRPC + shared MySQL | **HTTPS REST + per-agent bearer token**, self-signed cert fallback |
| Dependencies | heavy | stdlib only, single binary |

The headline new capability: each node can route user traffic through an
**upstream socks5 / http(s) proxy** (e.g. an IP-proxy vendor endpoint) and even
through a **multi-hop dialer chain**.

## Build

```sh
go build ./...
go vet ./...
go test ./...
```

Build the binary:

```sh
go build -o shadow-agent ./cmd/shadow-agent
```

## Run

```sh
# With a config file:
./shadow-agent -config /etc/shadow-agent/config.json

# Or purely from environment variables (no -config):
SHADOW_AGENT_TOKEN=... SHADOW_AGENT_LISTEN=:8443 ./shadow-agent
```

If no TLS cert/key is configured the agent **self-signs an in-memory
certificate** at startup, so HTTPS always works out of the box (use a real cert
in production, or terminate TLS at Caddy and point the panel at it).

### Configuration

`config.example.json`:

```json
{
  "listen": ":8443",
  "token": "change-me-to-a-long-random-per-agent-token",
  "tlsCertFile": "",
  "tlsKeyFile": "",
  "kernelBinDir": "/usr/local/bin",
  "dataDir": "/var/lib/shadow-agent"
}
```

Every field can be overridden by env var:
`SHADOW_AGENT_LISTEN`, `SHADOW_AGENT_TOKEN`, `SHADOW_AGENT_TLS_CERT`,
`SHADOW_AGENT_TLS_KEY`, `SHADOW_AGENT_KERNEL_BIN_DIR`, `SHADOW_AGENT_DATA_DIR`.

> If `token` is empty, all authenticated endpoints return `401` by default to
> avoid an open control plane. `/healthz` is always unauthenticated.

Kernel binaries are resolved as `<kernelBinDir>/<kernel>` (e.g.
`/usr/local/bin/xray`). If a binary is missing, the agent **still writes the
generated config** and reports `running:false, error:"binary not found"` instead
of crashing — handy for offline validation.

## REST API

All endpoints except `/healthz` require `Authorization: Bearer <agent-token>`.

| Method & path | Body | Response |
|---|---|---|
| `GET /healthz` | — | `{"ok":true,"version":"..."}` |
| `GET /api/v1/server/state` | — | `{cpuPercent,memUsedMB,memTotalMB,uptimeSec,kernels:{...}}` |
| `POST /api/v1/nodes` | `NodeSpec` | `NodeState` (generates config + (re)starts process) |
| `GET /api/v1/nodes` | — | `[NodeState]` |
| `DELETE /api/v1/nodes/{tag}` | — | `{"ok":true}` (stop + delete) |
| `GET /api/v1/nodes/{tag}/state` | — | `NodeState` |
| `GET /api/v1/traffic` | — | `[{tag,uplinkBytes,downlinkBytes}]` (delta since last pull; 0 with no kernel) |

### NodeSpec

```jsonc
{
  "tag": "node-1",                       // unique id
  "kernel": "xray|hysteria2|singbox|naive",
  "protocol": "vless|vmess|trojan|shadowsocks|hysteria2|naive",
  "listen": "0.0.0.0",
  "port": 443,
  "apiPort": 0,                          // 0 => port + 30000
  "users": [{"id":"uuid","password":"","email":"","level":0}],
  "stream": {
    "network": "tcp|ws|grpc",
    "security": "none|tls|reality",
    "tls": {"sni":"","alpn":["h2","http/1.1"],"certFile":"","keyFile":"","allowInsecure":false},
    "reality": {"dest":"","serverNames":[],"privateKey":"","shortIds":[]},
    "ws": {"path":"/","host":""}
  },
  "outbound": {                          // nil => freedom direct
    "protocol": "freedom|socks|http|vless|vmess|trojan|shadowsocks",
    "address": "", "port": 0, "user": "", "pass": "", "uuid": "", "security": "",
    "tag": "proxy",
    "dialerProxyTag": ""                 // dial this outbound's TCP via tag
  },
  "dialerChain": [ /* OutboundSpec, ... */ ]   // optional multi-hop chain
}
```

`NodeState`:

```json
{"tag":"","running":true,"pid":1234,"kernel":"xray","port":443,
 "configPath":"","error":"","uplinkBytes":0,"downlinkBytes":0}
```

## dialer-proxy: upstream proxy & chains (the crux)

shadow-agent translates `outbound` + `dialerChain` into Xray `outbounds` and
wires the chain with `streamSettings.sockopt.dialerProxy`, which references the
**next hop's tag**.

### Direct (default)

No `outbound`, empty `dialerChain`:

```json
"outbounds": [{"protocol":"freedom","tag":"direct"}]
```

### Single upstream proxy

`outbound` pointing at a socks/http endpoint becomes the main outbound (tag
defaults to `proxy`), and routing sends user traffic to it:

```json
"outbound": {"protocol":"socks","address":"1.2.3.4","port":1080,"user":"u","pass":"p"}
```

```json
"outbounds": [{
  "protocol":"socks","tag":"proxy",
  "settings":{"servers":[{"address":"1.2.3.4","port":1080,
    "users":[{"user":"u","pass":"p"}]}]}
}]
```

(Credentials are omitted when `user`/`pass` are empty.)

### Multi-hop chain

`dialerChain: [hop1, hop2, ...]` makes user traffic exit through the main
outbound, which dials **through hop1**, which dials through hop2, … and the last
hop dials directly:

```
user traffic → main(proxy) ──dialerProxy──▶ hop1 ──dialerProxy──▶ hop2 ─▶ direct
```

```json
"outbounds": [
  {"protocol":"socks","tag":"proxy","settings":{...},
   "streamSettings":{"sockopt":{"dialerProxy":"hop1"}}},
  {"protocol":"socks","tag":"hop1","settings":{...},
   "streamSettings":{"sockopt":{"dialerProxy":"hop2"}}},
  {"protocol":"http","tag":"hop2","settings":{...}}
]
```

Every hop is appended to `outbounds` with a unique tag; the main outbound's
`sockopt.dialerProxy` equals the first hop's tag, each hop points to the next,
and the final hop has no `dialerProxy` (it dials directly). If `outbound` is
omitted but `dialerChain` is present, the **first hop becomes the main
outbound**.

The same chaining concept is mapped onto **sing-box** via the `detour` field.
The proof of correctness lives in
[`internal/kernel/xray_test.go`](internal/kernel/xray_test.go)
(`TestXraySocksUpstreamWithDialerChain`), which asserts the main outbound's
`dialerProxy == hop1.tag`, the chained hop tags, and the socks server
address/port/credentials.

## Layout

```
cmd/shadow-agent/main.go     flag parsing, config load, HTTPS server bootstrap
internal/config              AgentConfig load (JSON + env), self-signed cert fallback
internal/api                 http.Server, bearer-token middleware, routes, sysstat
internal/kernel              NodeSpec/OutboundSpec/... + per-kernel generators + registry
  xray.go                    ★ core: inbounds/outbounds/dialer-proxy/routing
  hysteria2.go singbox.go naive.go   other kernels
internal/process             supervisor: write config, exec start/stop, track pid/state
internal/traffic             per-tag uplink/downlink deltas (0 without a kernel)
deploy/shadow-agent.service  systemd unit
config.example.json          sample config
```

## Kernels

- **Xray-core** v26.x — primary; full inbound/outbound/dialer-proxy support.
- **Hysteria2** — YAML/JSON server config with userpass auth, socks/http outbound.
- **sing-box** — JSON inbound/outbound with `detour`-based chaining.
- **NaiveProxy** — Caddyfile with the `forward_proxy` directive.

The legacy, EOL Trojan-Go kernel is intentionally dropped (use Xray's `trojan`
inbound or sing-box instead).
