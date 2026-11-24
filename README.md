<p align="center">
  <img src="assets/logo.svg" alt="iroh-proxy logo" width="120" height="120">
</p>

<h1 align="center">iroh-proxy</h1>

<p align="center">
  Expose local TCP and UDP services over <a href="https://iroh.computer/">iroh</a> peer-to-peer QUIC connections to an allowlist of peers.
</p>

You run a server on the machine that can reach your services, grant access with one-time invite codes or public keys, and run a client on your laptop or phone. Iroh punches through NAT for direct UDP connections and falls back to relays when direct paths are blocked.

For the Android client, VPN hostname mode, and APK builds, see [android/README.md](android/README.md).

## Why this instead of Tailscale

Tailscale builds a full Layer 3 mesh network across your devices. That is great when you want every machine on one private network, and overkill when you just want to share a few services with yourself or family.

| | iroh-proxy | Tailscale |
| --- | --- | --- |
| Account and control plane | None. Identity is a local 32-byte keypair. | Account, tailnet, and a coordination server like Tailscale or Headscale. |
| Giving someone access | Run `iroh-proxy invite` and text them a one-time code. | Create or invite an account, approve the device, manage ACLs or node shares. |
| Privileges on desktop | Normal user process. No root, no TUN interface, no system VPN. | Background daemon with root privileges and a TUN interface. |
| Connection direction | Strictly one-way, client to server, only for listed services. | Bidirectional IP mesh unless locked down with ACLs. |
| Multiple servers | One client connects to any number of independent servers at once. | One tailnet at a time without switching accounts. |
| Running alongside a VPN | Works next to Tailscale, WireGuard, or a work VPN on desktop. | Competes for the OS VPN slot and routing table. |
| App embedding | Available as a Rust crate with `Client` and `forward_in_background`. | Requires the Tailscale daemon or tsnet in Go. |

The tradeoffs go both ways. Tailscale is the better pick if you want machines to talk freely across arbitrary ports, need subnet routing or exit nodes, want MagicDNS and Tailscale SSH, or need packaged apps for iOS and macOS. `iroh-proxy` only forwards named services, has a CLI and an Android app, and carries UDP as QUIC datagrams, which top out around 1160 bytes over a relay.

## Build

Requires a Rust toolchain with edition 2024 support.

```sh
cargo build --release
# binary at target/release/iroh-proxy
```

Run unit tests offline with `cargo test --lib`, or run the full suite including end-to-end relay tests with `cargo test`, which needs internet access.

## Quick start

### 1. Start the server

Create `server.toml`:

```toml
key_file = "server.key"
name = "Home"

[services]
jellyfin = "127.0.0.1:8096"
ssh = "127.0.0.1:22"
```

Start serving:

```sh
iroh-proxy serve server.toml
```

On first run, this creates `server.key` with mode `0600` and prints the server's public ID.

### 2. Invite a client

Generate a one-time invite code:

```sh
iroh-proxy invite server.toml laptop
```

This writes a token to `state_dir/invites` and prints a code in the form `<server-id>.<token>`, plus `@<relay>` if the server has a custom relay configured.

On the client machine, create `client.toml`:

```toml
key_file = "client.key"
```

Redeem the invite:

```sh
iroh-proxy join client.toml <invite-code>
```

The server validates the token, deletes it so it cannot be reused, and appends the client's public ID to `state_dir/allowed`. No server restart is needed. If the invite included a relay and `client.toml` has no `relay` set, `join` adds it to `client.toml`.

### 3. Connect

Add the server ID printed by `join` to `client.toml`:

```toml
key_file = "client.key"
servers = ["<server-id>"]
```

Then connect:

```sh
iroh-proxy connect client.toml
```

The client asks each server for its service list and binds every advertised service on `127.0.0.1:<target-port>`, falling back to a random free port if that port is taken or below 1024.

### Manual allowlisting without invites

To allow a client ahead of time, print its public ID and add it to `allowed` in `server.toml`:

```sh
iroh-proxy id client.key
```

## CLI reference

```sh
iroh-proxy serve <server.toml>
iroh-proxy invite <server.toml> [label]
iroh-proxy join <client.toml> <invite>
iroh-proxy connect <client.toml>
iroh-proxy id <key_file>
```

## Server config

In TOML, top-level keys must come before any `[table]` section.

```toml
key_file = "server.key"
name = "Home"
relay = "https://relay.example.com"   # optional; host alone also works
state_dir = "./state"                 # optional; defaults to key_file's directory
allowed = [                           # optional; combined with state_dir/allowed
  "0123456789abcdef...",
]
dns = "adguard"                       # optional; TCP service offered as client DNS

[services]
proxy = "192.168.1.10:443"
jellyfin = "127.0.0.1:8096"
adguard = "127.0.0.1:53"

[udp_services]
proxy = "192.168.1.10:443"            # optional; enables HTTP/3 alongside TCP proxy

[hostnames]
proxy = ["*.example.com", "home.lan"] # exact names, or *.suffix for any subdomain
```

Adding a peer to `state_dir/allowed` takes effect on its next connection without a restart. Removing a peer that the server already loaded into memory requires a server restart.

## Client config

```toml
key_file = "client.key"
relay = "relay.example.com"           # optional
servers = [                           # or single `server = "..."`
  "0123456789abcdef...",
]
dns = "127.0.0.1:5353"                # optional; local UDP+TCP DNS server
upstream_dns = ["192.168.1.1", "1.1.1.1:53"] # optional; defaults to /etc/resolv.conf

[forwards]
jellyfin = "127.0.0.1:18096"          # optional per-service local address override

[udp_forwards]
proxy = "127.0.0.1:8443"
```

All servers listed in `server` and `servers` share the same client endpoint and client ID, and service discovery runs in parallel with a 20-second timeout per server so an offline server does not block the rest.

## DNS and hostnames

If a server defines `[hostnames]` for a reverse proxy or offers a TCP DNS server via `dns = "..."`, setting `dns = "127.0.0.1:53"` in `client.toml` starts a local UDP and TCP DNS resolver:

1. Queries matching an advertised hostname return an `A` record pointing to the local forward's IP with a 30-second TTL, and an empty `NOERROR` response for `AAAA` so clients do not bypass the forward over IPv6. Exact matches beat wildcards, and longer wildcard suffixes beat shorter ones.
2. All other queries go through the tunnel to the first server advertising a `dns` service, using one TCP stream per query.
3. If the tunnel DNS times out after 4 seconds or fails, queries fall back to `upstream_dns` or `/etc/resolv.conf`.

On desktop, if a hostname service listens on a privileged port such as `443`, either run `iroh-proxy connect` with permission to bind that port or map `[forwards]` to match what your browser connects to. On Android, the app handles hostname routing on `198.18.0.0/16` through a local VPN without root; see [android/README.md](android/README.md).

## Custom relay and fallback

By default, iroh uses n0's public relays for discovery and fallback traffic. If you set `relay` to your own `iroh-relay` instance, `iroh-proxy` uses it first.

If your relay stays unreachable for 20 seconds, `iroh-proxy` adds n0's public relays so connections stay up. While on n0, it checks your relay again after 1 minute, doubling the interval up to 30 minutes, and leaves n0's relays once your relay is reachable again.

Relayed traffic goes through the dialed endpoint's relay, so setting `relay` on the server is enough on its own. Invites automatically append `@<relay-host>` so new clients pick it up too.

## UDP behavior

UDP services travel as QUIC datagrams, with one flow ID per client source address and a 30-second idle timeout. Either side drops packets larger than the path's maximum datagram size, just like regular UDP over a small MTU. Direct paths carry normal MTU packets, while relayed paths cap datagrams at about 1160 bytes, so HTTP/3 falls back to TCP when relayed.

## Library and wire protocol

The crate exports `serve`, `Client`, `bind`, `forward_in_background`, `create_invite`, `parse_invite`, and the `dns` module for embedding inside other Rust apps.

The protocol runs on ALPN `iroh-proxy/0`:

- **TCP stream.** One QUIC bidirectional stream per connection, prefixed with `u8 len` and the UTF-8 service name, followed by raw bytes in both directions.
- **Discovery.** A stream with length `0` returns `tcp|udp <port> <name>`, `host <pattern> <name>`, `dns <name>`, and `name <server name>` lines until EOF.
- **Invite redemption.** An unallowlisted peer has 10 seconds to open one stream named `!invite <token>`. The server replies `ok` or `invalid` and closes the connection.
- **UDP datagram.** Client to server frames are `u32 flow` + `u8 len` + service name + payload. Server to client frames are `u32 flow` + payload.
