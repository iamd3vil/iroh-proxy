//! Expose named TCP services from one iroh endpoint to an allowlist of peers.
//!
//! TCP: per QUIC bi-stream, `u8 len` + service name, then raw bytes both ways.
//! Discovery: a bi-stream with an empty name gets back one `tcp|udp <port> <name>\n` line per
//! service, where port is the target's port (a suggested local port), then one
//! `host <pattern> <name>\n` line per hostname a service answers for (see [`Service::hostnames`]),
//! then EOF.
//! UDP: one QUIC datagram per UDP packet. Client -> server: `u32 flow` + `u8 len` + service name +
//! payload; server -> client: `u32 flow` + payload. A flow is one client-side source address.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
pub use iroh::Endpoint;
use iroh::{
    EndpointId, RelayMode, SecretKey,
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
}

fn listing(tcp: &HashMap<String, String>, udp: &HashMap<String, String>, hosts: &HashMap<String, Vec<String>>) -> String {
    let port = |t: &String| t.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(0);
    let mut lines: Vec<String> = (tcp.iter().map(|(n, t)| format!("tcp {} {n}\n", port(t))))
        .chain(udp.iter().map(|(n, t)| format!("udp {} {n}\n", port(t))))
        .collect();
    lines.sort();
    let mut host_lines: Vec<String> = hosts.iter().flat_map(|(n, hs)| hs.iter().map(move |h| format!("host {h} {n}\n"))).collect();
    host_lines.sort();
    lines.extend(host_lines);
    lines.concat()
}

/// Parses the discovery listing format (see the crate docs); skips malformed lines.
pub fn parse_services(s: &str) -> Vec<Service> {
    let mut services = Vec::new();
    let mut hosts = Vec::new();
    for l in s.lines() {
        let mut it = l.splitn(3, ' ');
        let (Some(kind), Some(arg), Some(name)) = (it.next(), it.next(), it.next()) else { continue };
        match kind {
            "tcp" | "udp" => {
                let Ok(port) = arg.parse() else { continue };
                services.push(Service { name: name.to_owned(), udp: kind == "udp", port, hostnames: vec![] });
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
    services
}

/// The listing lines describing `svc`; the inverse of [`parse_services`].
pub fn service_lines(svc: &Service) -> String {
    let proto = if svc.udp { "udp" } else { "tcp" };
    let mut out = format!("{proto} {} {}\n", svc.port, svc.name);
    for h in &svc.hostnames {
        out += &format!("host {h} {}\n", svc.name);
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

#[derive(Debug, Clone)]
struct Proxy {
    services: Arc<HashMap<String, String>>,
    udp: Arc<HashMap<String, String>>,
    hostnames: Arc<HashMap<String, Vec<String>>>,
    allowed: Arc<HashSet<EndpointId>>,
}

impl ProtocolHandler for Proxy {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id();
        if !self.allowed.contains(&peer) {
            eprintln!("rejected {peer}");
            conn.close(1u32.into(), b"not allowed");
            return Ok(());
        }
        eprintln!("connected {}", peer.fmt_short());
        log_paths(conn.clone());
        tokio::spawn(serve_datagrams(conn.clone(), self.udp.clone()));
        while let Ok((send, recv)) = conn.accept_bi().await {
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.serve_stream(send, recv).await {
                    eprintln!("{peer}: {e:#}");
                }
            });
        }
        eprintln!("disconnected {peer}");
        Ok(())
    }
}

impl Proxy {
    async fn serve_stream(&self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        let mut name = vec![0; recv.read_u8().await? as usize];
        if name.is_empty() {
            send.write_all(listing(&self.services, &self.udp, &self.hostnames).as_bytes()).await?;
            send.finish()?;
            send.stopped().await?;
            return Ok(());
        }
        recv.read_exact(&mut name).await?;
        let name = String::from_utf8(name)?;
        let Some(target) = self.services.get(&name) else { bail!("unknown service {name:?}") };
        let mut tcp = TcpStream::connect(target).await.with_context(|| format!("{name} -> {target}"))?;
        copy_bidirectional(&mut join(recv, send), &mut tcp).await?;
        Ok(())
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

/// Starts serving TCP `services` and `udp` services (name -> "host:port") to `allowed` peers.
/// `hostnames` (service name -> DNS names) is advertised to VPN-mode clients.
/// Drop/shutdown the Router to stop.
pub async fn serve(
    key: SecretKey,
    relay: Option<RelayUrl>,
    services: HashMap<String, String>,
    udp: HashMap<String, String>,
    hostnames: HashMap<String, Vec<String>>,
    allowed: HashSet<EndpointId>,
) -> Result<Router> {
    for (name, hosts) in &hostnames {
        if !services.contains_key(name) && !udp.contains_key(name) {
            bail!("hostnames: no service named {name:?}");
        }
        if let Some(h) = hosts.iter().find(|h| h.is_empty() || h.contains(char::is_whitespace)) {
            bail!("hostnames: invalid name {h:?} for {name}");
        }
    }
    let proxy = Proxy {
        services: Arc::new(services),
        udp: Arc::new(udp),
        hostnames: Arc::new(hostnames),
        allowed: Arc::new(allowed),
    };
    Ok(Router::builder(bind(key, relay).await?).accept(ALPN, proxy).spawn())
}

// ---------- client ----------

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

    /// Asks the server which services it offers.
    pub async fn services(&self) -> Result<Vec<Service>> {
        let (mut send, mut recv) = self.open().await?;
        send.write_u8(0).await?;
        send.finish()?;
        let list = recv.read_to_end(64 * 1024).await.context("listing services")?;
        Ok(parse_services(&String::from_utf8_lossy(&list)))
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
