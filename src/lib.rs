//! Expose named TCP services from one iroh endpoint to an allowlist of peers.
//!
//! TCP: per QUIC bi-stream, `u8 len` + service name, then raw bytes both ways.
//! Discovery: a bi-stream with an empty name gets back one `tcp|udp <port> <name>\n` line per
//! service, where port is the target's port (a suggested local port), then one
//! `host <pattern> <name>\n` line per hostname a service answers for (see [`Service::hostnames`]),
//! then `dns <name>\n` if a TCP service is offered as clients' DNS server (see [`Service::dns`]),
//! then `name <server name>\n` if the server has one, then EOF.
//! Invites: a client that isn't allowed yet may open one bi-stream named `!invite <token>`; the
//! server answers `ok` (and allows it from then on) or `invalid`, then closes the connection.
//! UDP: one QUIC datagram per UDP packet. Client -> server: `u32 flow` + `u8 len` + service name +
//! payload; server -> client: `u32 flow` + payload. A flow is one client-side source address.

use std::{
    collections::{HashMap, HashSet},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
pub use iroh::Endpoint;

pub mod dns;
use iroh::{
    EndpointId, RelayMode, SecretKey, TransportAddr,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_future::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, join},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
    time::timeout,
};

pub use iroh::{EndpointId as PeerId, RelayUrl, SecretKey as Key};

pub const ALPN: &[u8] = b"iroh-proxy/0";

/// A UDP flow is dropped after this long idle (server: no reply from the target; client: nothing
/// sent), like a NAT mapping. Short so per-query flows (DNS) don't pile up sockets.
const UDP_IDLE: Duration = Duration::from_secs(30);

/// A service the server offers, as returned by [`Client::services`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub udp: bool,
    /// The target's port on the server side; used as the default local port.
    pub port: u16,
    /// DNS names (exact, or `*.example.com` for any subdomain) that VPN-mode clients resolve to
    /// this service, so it is reachable by its usual name on [`Service::port`].
    pub hostnames: Vec<String>,
    /// A DNS server (over TCP) that VPN-mode clients should use for names they don't answer
    /// themselves, e.g. a filtering resolver like AdGuard Home. See [`Client::dns_query`].
    pub dns: bool,
}

fn listing(cfg: &ServerConfig) -> String {
    let (tcp, udp, hosts, dns) = (&cfg.services, &cfg.udp_services, &cfg.hostnames, cfg.dns.as_deref());
    let port = |t: &String| t.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(0);
    let mut lines: Vec<String> = (tcp.iter().map(|(n, t)| format!("tcp {} {n}\n", port(t))))
        .chain(udp.iter().map(|(n, t)| format!("udp {} {n}\n", port(t))))
        .collect();
    lines.sort();
    let mut host_lines: Vec<String> = hosts.iter().flat_map(|(n, hs)| hs.iter().map(move |h| format!("host {h} {n}\n"))).collect();
    host_lines.sort();
    lines.extend(host_lines);
    lines.extend(dns.map(|d| format!("dns {d}\n")));
    lines.extend(cfg.name.as_ref().map(|n| format!("name {n}\n")));
    lines.concat()
}

/// Parses the discovery listing format (see the crate docs); skips malformed lines.
pub fn parse_services(s: &str) -> Vec<Service> {
    let mut services = Vec::new();
    let mut hosts = Vec::new();
    let mut dns = None;
    for l in s.lines() {
        if let Some(name) = l.strip_prefix("dns ") {
            dns = Some(name);
            continue;
        }
        let mut it = l.splitn(3, ' ');
        let (Some(kind), Some(arg), Some(name)) = (it.next(), it.next(), it.next()) else { continue };
        match kind {
            "tcp" | "udp" => {
                let Ok(port) = arg.parse() else { continue };
                services.push(Service { name: name.to_owned(), udp: kind == "udp", port, hostnames: vec![], dns: false });
            }
            "host" => hosts.push((arg.to_owned(), name)),
            _ => {}
        }
    }
    for (host, name) in hosts {
        for svc in services.iter_mut().filter(|s| s.name == name) {
            svc.hostnames.push(host.clone());
        }
    }
    if let Some(svc) = services.iter_mut().find(|s| !s.udp && Some(s.name.as_str()) == dns) {
        svc.dns = true;
    }
    services
}

/// The server's name from a listing, if it has one.
pub fn parse_server_name(listing: &str) -> Option<String> {
    listing.lines().find_map(|l| l.strip_prefix("name ")).map(str::to_owned)
}

/// The listing lines describing `svc`; the inverse of [`parse_services`].
pub fn service_lines(svc: &Service) -> String {
    let proto = if svc.udp { "udp" } else { "tcp" };
    let mut out = format!("{proto} {} {}\n", svc.port, svc.name);
    for h in &svc.hostnames {
        out += &format!("host {h} {}\n", svc.name);
    }
    if svc.dns {
        out += &format!("dns {}\n", svc.name);
    }
    out
}

/// Loads a 32-byte secret key from `path`, creating it (mode 0600) if missing.
pub fn load_or_create_key(path: impl AsRef<Path>) -> Result<SecretKey> {
    let path = path.as_ref();
    match std::fs::read(path) {
        Ok(b) => {
            let b: [u8; 32] = b.try_into().map_err(|_| anyhow::anyhow!("{path:?}: not a 32-byte key"))?;
            Ok(SecretKey::from_bytes(&b))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            std::io::Write::write_all(&mut opts.open(path)?, &key.to_bytes())?;
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading key {path:?}")),
    }
}

/// Binds an iroh endpoint with `key`, for [`Client::with_endpoint`].
///
/// `relay`: your own iroh-relay instead of n0's public ones. Relayed traffic goes through the
/// *dialed* endpoint's relay, so setting it on the server alone is enough; a client left on n0
/// still gets QUIC address discovery from n0 for hole punching.
pub async fn bind(key: SecretKey, relay: Option<RelayUrl>) -> Result<Endpoint> {
    let mut b = Endpoint::builder(presets::N0).secret_key(key);
    if let Some(url) = relay {
        b = b.relay_mode(RelayMode::Custom(url.into()));
    }
    Ok(b.bind().await?)
}

/// Logs the connection's selected path (direct UDP or relay) each time it changes.
fn log_paths(conn: Connection) {
    tokio::spawn(async move {
        let peer = conn.remote_id().fmt_short();
        let mut last = String::new();
        let mut paths = conn.paths_stream();
        while let Some(list) = paths.next().await {
            let Some(p) = list.iter().find(|p| p.is_selected()) else { continue };
            let now = format!("{} ({})", if p.is_relay() { "relayed" } else { "direct" }, p.remote_addr());
            if now != last {
                eprintln!("{peer}: {now} (rtt {:?})", p.rtt());
                last = now;
            }
        }
    });
}

// ---------- server ----------

/// What a server serves and to whom: `iroh-proxy serve`'s config file, minus key and relay.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ServerConfig {
    /// name -> "host:port" on the server's side.
    #[serde(default)]
    pub services: HashMap<String, String>,
    #[serde(default)]
    pub udp_services: HashMap<String, String>,
    /// service name -> DNS names (exact, or "*.example.com") VPN-mode clients resolve to it.
    #[serde(default)]
    pub hostnames: HashMap<String, Vec<String>>,
    /// A TCP service (e.g. AdGuard Home on port 53) VPN-mode clients use as their DNS server.
    pub dns: Option<String>,
    /// Client ids allowed to connect, besides those that redeemed an invite.
    #[serde(default)]
    pub allowed: HashSet<EndpointId>,
    /// Shown to clients as this server's name.
    pub name: Option<String>,
    /// Where invites and the clients that redeemed them are kept (`invites`, `allowed`).
    pub state_dir: Option<PathBuf>,
}

/// Creates a one-time invite for a client to be known as `label`; returns the token. Stored in
/// `state_dir`, where a running server finds it.
pub fn create_invite(state_dir: &Path, label: &str) -> Result<String> {
    std::fs::create_dir_all(state_dir)?;
    let token: String = rand::random::<[u8; 16]>().iter().map(|b| format!("{b:02x}")).collect();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(state_dir.join("invites"))?;
    writeln!(f, "{token} {}", label.trim())?;
    Ok(token)
}

/// [`Client::redeem`]'s error when the server refused the invite (as opposed to being unreachable).
#[derive(Debug)]
pub struct InviteRejected;

impl std::fmt::Display for InviteRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server didn't accept this invite (already used, or not valid)")
    }
}

impl std::error::Error for InviteRejected {}

/// What a client pastes: the server's id and the token.
pub fn invite_code(server: EndpointId, token: &str) -> String {
    format!("{server}.{token}")
}

/// The server and token of an invite code found anywhere in `text` (e.g. a pasted message).
pub fn parse_invite(text: &str) -> Option<(EndpointId, String)> {
    let hex = |s: &str, n| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '.').find_map(|word| {
        let (server, token) = word.split_once('.')?;
        (hex(server, 64) && hex(token, 32)).then_some(())?;
        Some((server.to_ascii_lowercase().parse().ok()?, token.to_ascii_lowercase()))
    })
}

/// Removes `token` from the invites in `state_dir`; its label if it was there.
fn take_invite(state_dir: &Path, token: &str) -> Result<Option<String>> {
    let path = state_dir.join("invites");
    let Ok(all) = std::fs::read_to_string(&path) else { return Ok(None) };
    let (mine, rest): (Vec<&str>, Vec<&str>) = all.lines().partition(|l| l.split(' ').next() == Some(token));
    let Some(line) = mine.first() else { return Ok(None) };
    std::fs::write(&path, rest.iter().map(|l| format!("{l}\n")).collect::<String>())?;
    Ok(Some(line.split_once(' ').map_or("", |(_, label)| label).to_owned()))
}

/// Who may connect: the config's `allowed`, plus `state_dir/allowed` (`<id> <label>` lines,
/// re-read whenever an unknown client connects, so edits apply without a restart).
#[derive(Debug)]
struct Allowed {
    fixed: HashSet<EndpointId>,
    file: Option<PathBuf>,
    invited: std::sync::Mutex<HashMap<EndpointId, String>>,
}

impl Allowed {
    fn new(fixed: HashSet<EndpointId>, state_dir: Option<&Path>) -> Self {
        let this = Self { fixed, file: state_dir.map(|d| d.join("allowed")), invited: Default::default() };
        this.reload();
        this
    }

    fn reload(&self) {
        let Some(text) = self.file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()) else { return };
        *self.invited.lock().unwrap() = text
            .lines()
            .filter_map(|l| {
                let (id, label) = l.split_once(' ').unwrap_or((l, ""));
                Some((id.trim().parse().ok()?, label.trim().to_owned()))
            })
            .collect();
    }

    /// The client's label ("" if it has none) if it may connect.
    fn check(&self, id: &EndpointId) -> Option<String> {
        if self.fixed.contains(id) {
            return Some(String::new());
        }
        if let Some(label) = self.invited.lock().unwrap().get(id) {
            return Some(label.clone());
        }
        self.reload();
        self.invited.lock().unwrap().get(id).cloned()
    }

    fn add(&self, id: EndpointId, label: &str) -> Result<()> {
        let file = self.file.as_ref().context("no state_dir")?;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(file)?;
        writeln!(f, "{id} {label}")?;
        self.invited.lock().unwrap().insert(id, label.to_owned());
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Proxy {
    cfg: Arc<ServerConfig>,
    allowed: Arc<Allowed>,
}

/// How long a client that isn't allowed gets to present an invite.
const INVITE_TIMEOUT: Duration = Duration::from_secs(10);

impl ProtocolHandler for Proxy {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        let Some(label) = self.allowed.check(&peer) else {
            self.guest(conn).await;
            return Ok(());
        };
        let who = if label.is_empty() { peer.fmt_short().to_string() } else { format!("{label} ({})", peer.fmt_short()) };
        eprintln!("connected {who}");
        log_paths(conn.clone());
        tokio::spawn(serve_datagrams(conn.clone(), Arc::new(self.cfg.udp_services.clone())));
        while let Ok((send, recv)) = conn.accept_bi().await {
            let this = self.clone();
            let who = who.clone();
            tokio::spawn(async move {
                if let Err(e) = this.serve_stream(send, recv).await {
                    eprintln!("{who}: {e:#}");
                }
            });
        }
        eprintln!("disconnected {who}");
        Ok(())
    }
}

impl Proxy {
    async fn serve_stream(&self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        let mut name = vec![0; recv.read_u8().await? as usize];
        if name.is_empty() {
            send.write_all(listing(&self.cfg).as_bytes()).await?;
            send.finish()?;
            send.stopped().await?;
            return Ok(());
        }
        recv.read_exact(&mut name).await?;
        let name = String::from_utf8(name)?;
        if name.starts_with("!invite ") {
            // Already allowed: nothing to redeem.
            send.write_all(b"ok").await?;
            send.finish()?;
            return Ok(());
        }
        let Some(target) = self.cfg.services.get(&name) else { bail!("unknown service {name:?}") };
        let mut tcp = TcpStream::connect(target).await.with_context(|| format!("{name} -> {target}"))?;
        copy_bidirectional(&mut join(recv, send), &mut tcp).await?;
        Ok(())
    }

    /// A client that isn't allowed: it may redeem an invite, and nothing else.
    async fn guest(&self, conn: Connection) {
        let peer = conn.remote_id();
        let res = timeout(INVITE_TIMEOUT, async {
            let (mut send, mut recv) = conn.accept_bi().await?;
            let mut name = vec![0; recv.read_u8().await? as usize];
            recv.read_exact(&mut name).await?;
            let token = String::from_utf8_lossy(&name).strip_prefix("!invite ").map(str::to_owned);
            if token.is_none() {
                _ = send.reset(1u32.into()); // anything else is refused (dropping would finish cleanly)
                return Ok((false, None));
            }
            let label = match (&token, &self.cfg.state_dir) {
                (Some(t), Some(dir)) => take_invite(dir, t)?,
                _ => None,
            };
            if let Some(label) = &label {
                self.allowed.add(peer, label)?;
            }
            send.write_all(if label.is_some() { b"ok" } else { b"invalid" }).await?;
            send.finish()?;
            // Let the answer arrive before the connection closes, but don't wait on a client that
            // has already gone (and whose close got lost).
            _ = timeout(Duration::from_secs(2), send.stopped()).await;
            anyhow::Ok((token.is_some(), label))
        })
        .await;
        match res {
            Ok(Ok((_, Some(label)))) => {
                eprintln!("{peer} joined with an invite{}", if label.is_empty() { String::new() } else { format!(" as {label}") });
                conn.close(0u32.into(), b"invited");
                return;
            }
            Ok(Ok((true, None))) => eprintln!("rejected {peer}: invalid invite"),
            _ => eprintln!("rejected {peer}"),
        }
        conn.close(1u32.into(), b"not allowed");
    }
}

type ServerFlows = Arc<std::sync::Mutex<HashMap<u32, Arc<UdpSocket>>>>;

async fn serve_datagrams(conn: Connection, udp: Arc<HashMap<String, String>>) {
    let peer = conn.remote_id().fmt_short();
    let flows = ServerFlows::default();
    while let Ok(d) = conn.read_datagram().await {
        let Some((flow, rest)) = d.split_first_chunk::<4>() else { continue };
        let flow = u32::from_be_bytes(*flow);
        let Some((&len, rest)) = rest.split_first() else { continue };
        let Some((name, payload)) = rest.split_at_checked(len as usize) else { continue };
        let sock = flows.lock().unwrap().get(&flow).cloned();
        let sock = match sock {
            Some(s) => s,
            None => match udp_flow(&conn, &udp, flow, name, flows.clone()).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{peer}: {e:#}");
                    continue;
                }
            },
        };
        _ = sock.send(payload).await;
    }
}

/// Opens a UDP socket to the service's target and relays its replies back as datagrams.
async fn udp_flow(conn: &Connection, udp: &HashMap<String, String>, flow: u32, name: &[u8], flows: ServerFlows) -> Result<Arc<UdpSocket>> {
    let name = String::from_utf8_lossy(name);
    let Some(target) = udp.get(name.as_ref()) else { bail!("unknown udp service {name:?}") };
    let addr = tokio::net::lookup_host(target).await?.next().with_context(|| format!("resolving {target}"))?;
    let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    sock.connect(addr).await?;
    let sock = Arc::new(sock);
    flows.lock().unwrap().insert(flow, sock.clone());
    let (conn, s, name) = (conn.clone(), sock.clone(), name.into_owned());
    tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        while let Ok(Ok(n)) = timeout(UDP_IDLE, s.recv(&mut buf)).await {
            let d = [&flow.to_be_bytes(), &buf[..n]].concat();
            if let Err(e) = conn.send_datagram(d.into()) {
                if conn.close_reason().is_some() {
                    break;
                }
                // Dropped like UDP over a small MTU; the max is ~1160 bytes over a relay.
                eprintln!("{name}: dropped {n}-byte reply: {e}");
            }
        }
        flows.lock().unwrap().remove(&flow);
    });
    Ok(sock)
}

/// Starts serving `cfg` (see [`ServerConfig`]). Drop/shutdown the Router to stop.
pub async fn serve(key: SecretKey, relay: Option<RelayUrl>, cfg: ServerConfig) -> Result<Router> {
    if let Some(d) = cfg.dns.as_ref().filter(|d| !cfg.services.contains_key(*d)) {
        bail!("dns: no TCP service named {d:?}");
    }
    for (name, hosts) in &cfg.hostnames {
        if !cfg.services.contains_key(name) && !cfg.udp_services.contains_key(name) {
            bail!("hostnames: no service named {name:?}");
        }
        if let Some(h) = hosts.iter().find(|h| h.is_empty() || h.contains(char::is_whitespace)) {
            bail!("hostnames: invalid name {h:?} for {name}");
        }
    }
    let allowed = Arc::new(Allowed::new(cfg.allowed.clone(), cfg.state_dir.as_deref()));
    let proxy = Proxy { cfg: Arc::new(cfg), allowed };
    Ok(Router::builder(bind(key, relay).await?).accept(ALPN, proxy).spawn())
}

// ---------- client ----------

/// How a client's connection to its server currently travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    /// Through a relay server, rather than direct UDP.
    pub relay: bool,
    /// The server's IP address and port, or the relay's hostname.
    pub addr: String,
    pub rtt: Duration,
}

type ClientFlows = Arc<std::sync::Mutex<HashMap<u32, (Arc<UdpSocket>, SocketAddr)>>>;

pub struct Client {
    ep: Endpoint,
    server: EndpointId,
    conn: Mutex<Option<Connection>>,
    udp: ClientFlows,
    next_flow: AtomicU32,
}

impl Client {
    pub async fn new(key: SecretKey, server: EndpointId, relay: Option<RelayUrl>) -> Result<Arc<Self>> {
        Ok(Self::with_endpoint(bind(key, relay).await?, server))
    }

    /// A client for `server` on an existing endpoint, so one key (one client id) can reach
    /// several servers. See [`bind`].
    pub fn with_endpoint(ep: Endpoint, server: EndpointId) -> Arc<Self> {
        Arc::new(Self { ep, server, conn: Mutex::new(None), udp: Default::default(), next_flow: AtomicU32::new(0) })
    }

    pub fn id(&self) -> EndpointId {
        self.ep.id()
    }

    /// The connection's selected path, if connected (and not in the middle of connecting).
    pub fn path(&self) -> Option<PathInfo> {
        let conn = self.conn.try_lock().ok()?.clone().filter(|c| c.close_reason().is_none())?;
        let list = conn.paths();
        let p = list.iter().find(|p| p.is_selected())?;
        let addr = match p.remote_addr() {
            TransportAddr::Ip(a) => a.to_string(),
            TransportAddr::Relay(url) => url.host_str().unwrap_or_default().trim_end_matches('.').to_owned(),
            other => format!("{other:?}"),
        };
        Some(PathInfo { relay: p.is_relay(), addr, rtt: p.rtt() })
    }

    /// The server this client talks to.
    pub fn server(&self) -> EndpointId {
        self.server
    }

    /// The live connection, (re)connecting if it is gone (e.g. after laptop sleep).
    async fn conn(&self) -> Result<Connection> {
        let mut conn = self.conn.lock().await;
        if let Some(c) = conn.as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(c.clone());
        }
        let c = self.ep.connect(self.server, ALPN).await?;
        log_paths(c.clone());
        tokio::spawn(recv_datagrams(c.clone(), self.udp.clone()));
        *conn = Some(c.clone());
        Ok(c)
    }

    async fn open(&self) -> Result<(SendStream, RecvStream)> {
        match self.conn().await?.open_bi().await {
            Ok(s) => Ok(s),
            // A failed open marks the connection closed, so this reconnects.
            Err(_) => Ok(self.conn().await?.open_bi().await?),
        }
    }

    /// Opens a stream to the TCP `service` on the server.
    pub async fn connect(&self, service: &str) -> Result<(SendStream, RecvStream)> {
        if service.len() > u8::MAX as usize {
            bail!("service name too long");
        }
        let (mut send, recv) = self.open().await?;
        send.write_u8(service.len() as u8).await?;
        send.write_all(service.as_bytes()).await?;
        Ok((send, recv))
    }

    /// Sends one DNS message to the TCP DNS `service` (RFC 1035 framing: a 2-byte length, then
    /// the message) and returns the reply.
    pub async fn dns_query(&self, service: &str, query: &[u8]) -> Result<Vec<u8>> {
        let len = u16::try_from(query.len()).context("DNS query too long")?;
        let (mut send, mut recv) = self.connect(service).await?;
        send.write_all(&[&len.to_be_bytes()[..], query].concat()).await?;
        send.finish()?;
        let mut reply = vec![0; recv.read_u16().await? as usize];
        recv.read_exact(&mut reply).await?;
        Ok(reply)
    }

    /// Asks the server which services it offers.
    pub async fn services(&self) -> Result<Vec<Service>> {
        Ok(parse_services(&self.listing().await?))
    }

    /// The server's discovery listing (see the crate docs), e.g. for [`parse_server_name`].
    pub async fn listing(&self) -> Result<String> {
        let (mut send, mut recv) = self.open().await?;
        send.write_u8(0).await?;
        send.finish()?;
        let list = recv.read_to_end(64 * 1024).await.context("listing services")?;
        Ok(String::from_utf8_lossy(&list).into_owned())
    }

    /// Redeems an invite token, after which the server allows this client.
    pub async fn redeem(&self, token: &str) -> Result<()> {
        let msg = format!("!invite {token}");
        let (mut send, mut recv) = self.open().await?;
        send.write_u8(msg.len() as u8).await?;
        send.write_all(msg.as_bytes()).await?;
        send.finish()?;
        let reply = recv.read_to_end(64).await.context("redeeming invite")?;
        // The server closes a guest's connection after redeeming; start afresh.
        if let Some(c) = self.conn.lock().await.take() {
            c.close(0u32.into(), b"invited");
        }
        if reply != b"ok" {
            return Err(InviteRejected.into());
        }
        Ok(())
    }

    /// Listens on `addr` and forwards it to `svc` in the background; returns the bound address.
    /// With no `addr`, uses `127.0.0.1:<svc.port>`, or a random port if that one is taken or
    /// privileged (e.g. below 1024 on Android).
    pub async fn expose(self: &Arc<Self>, svc: &Service, addr: Option<&str>) -> Result<SocketAddr> {
        let default = format!("127.0.0.1:{}", svc.port);
        let addrs = match addr {
            Some(a) => vec![a],
            None => vec![default.as_str(), "127.0.0.1:0"],
        };
        let mut err = None;
        for a in addrs {
            if svc.udp {
                match UdpSocket::bind(a).await {
                    Ok(s) => {
                        let local = s.local_addr()?;
                        tokio::spawn(self.clone().forward_udp(svc.name.clone(), s));
                        return Ok(local);
                    }
                    Err(e) => err = Some(anyhow::Error::from(e).context(format!("binding udp {a}"))),
                }
            } else {
                match TcpListener::bind(a).await {
                    Ok(l) => {
                        let local = l.local_addr()?;
                        tokio::spawn(self.clone().forward(svc.name.clone(), l));
                        return Ok(local);
                    }
                    Err(e) => err = Some(anyhow::Error::from(e).context(format!("binding {a}"))),
                }
            }
        }
        Err(err.unwrap())
    }

    /// Accepts TCP connections on `listener` forever, piping each to `service` on the server.
    pub async fn forward(self: Arc<Self>, service: String, listener: TcpListener) -> Result<()> {
        if service.len() > u8::MAX as usize {
            bail!("service name too long");
        }
        loop {
            let (mut tcp, _) = listener.accept().await?;
            let (this, service) = (self.clone(), service.clone());
            tokio::spawn(async move {
                let res = async {
                    let (send, recv) = this.connect(&service).await?;
                    copy_bidirectional(&mut tcp, &mut join(recv, send)).await?;
                    anyhow::Ok(())
                };
                if let Err(e) = res.await {
                    eprintln!("{service}: {e:#}");
                }
            });
        }
    }

    /// Relays UDP packets received on `sock` to the `service` UDP service on the server, and its
    /// replies back to each sender.
    pub async fn forward_udp(self: Arc<Self>, service: String, sock: UdpSocket) -> Result<()> {
        if service.len() > u8::MAX as usize {
            bail!("service name too long");
        }
        let sock = Arc::new(sock);
        let mut ids = HashMap::new();
        let mut buf = vec![0; 65535];
        loop {
            let (n, src) = sock.recv_from(&mut buf).await?;
            let now = Instant::now();
            if !ids.contains_key(&src) {
                // Sweep idle flows whenever a new one starts (DNS uses a new source port per query).
                ids.retain(|_, (id, seen): &mut (u32, Instant)| {
                    let keep = now - *seen < UDP_IDLE;
                    if !keep {
                        self.udp.lock().unwrap().remove(id);
                    }
                    keep
                });
            }
            let (flow, seen) = ids.entry(src).or_insert_with(|| {
                let id = self.next_flow.fetch_add(1, Ordering::Relaxed);
                self.udp.lock().unwrap().insert(id, (sock.clone(), src));
                (id, now)
            });
            *seen = now;
            let flow = *flow;
            let d = [&flow.to_be_bytes(), &[service.len() as u8][..], service.as_bytes(), &buf[..n]].concat();
            if let Err(e) = async { anyhow::Ok(self.conn().await?.send_datagram(d.into())?) }.await {
                eprintln!("{service}: {e:#}");
            }
        }
    }
}

async fn recv_datagrams(conn: Connection, flows: ClientFlows) {
    while let Ok(d) = conn.read_datagram().await {
        let Some((flow, payload)) = d.split_first_chunk::<4>() else { continue };
        let dst = flows.lock().unwrap().get(&u32::from_be_bytes(*flow)).cloned();
        if let Some((sock, src)) = dst {
            _ = sock.send_to(payload, src).await;
        }
    }
}

/// For non-tokio apps (e.g. jellyui): starts a background thread that forwards
/// `127.0.0.1:<random port>` to `service` and returns that address. Runs for the process lifetime.
pub fn forward_in_background(
    key: SecretKey,
    server: EndpointId,
    relay: Option<RelayUrl>,
    service: &str,
) -> Result<SocketAddr> {
    let (tx, rx) = std::sync::mpsc::channel();
    let service = service.to_owned();
    std::thread::Builder::new().name("iroh-proxy".into()).spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                _ = tx.send(Err(e.into()));
                return;
            }
        };
        rt.block_on(async move {
            let setup = async {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                anyhow::Ok((Client::new(key, server, relay).await?, listener))
            };
            match setup.await {
                Ok((client, listener)) => {
                    _ = tx.send(Ok(listener.local_addr().unwrap()));
                    if let Err(e) = client.forward(service, listener).await {
                        eprintln!("iroh-proxy: {e:#}");
                    }
                }
                Err(e) => _ = tx.send(Err(e)),
            }
        })
    })?;
    rx.recv()?
}
