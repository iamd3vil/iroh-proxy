//! Expose named TCP services from one iroh endpoint to an allowlist of peers.
//!
//! Wire protocol, per QUIC bi-stream: `u8 len` + service name, then raw bytes both ways.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use iroh::{
    Endpoint, EndpointId, RelayMode, SecretKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_future::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, join},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

pub use iroh::{EndpointId as PeerId, RelayUrl, SecretKey as Key};

pub const ALPN: &[u8] = b"iroh-proxy/0";

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

/// `relay`: your own iroh-relay instead of n0's public ones. Set the same one on both ends.
async fn bind(key: SecretKey, relay: Option<RelayUrl>) -> Result<Endpoint> {
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
        while let Ok((send, recv)) = conn.accept_bi().await {
            let services = self.services.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_stream(&services, send, recv).await {
                    eprintln!("{peer}: {e:#}");
                }
            });
        }
        eprintln!("disconnected {peer}");
        Ok(())
    }
}

async fn serve_stream(services: &HashMap<String, String>, send: SendStream, mut recv: RecvStream) -> Result<()> {
    let mut name = vec![0; recv.read_u8().await? as usize];
    recv.read_exact(&mut name).await?;
    let name = String::from_utf8(name)?;
    let Some(target) = services.get(&name) else { bail!("unknown service {name:?}") };
    let mut tcp = TcpStream::connect(target).await.with_context(|| format!("{name} -> {target}"))?;
    copy_bidirectional(&mut join(recv, send), &mut tcp).await?;
    Ok(())
}

/// Starts serving `services` (name -> "host:port") to `allowed` peers. Drop/shutdown the Router to stop.
pub async fn serve(
    key: SecretKey,
    relay: Option<RelayUrl>,
    services: HashMap<String, String>,
    allowed: HashSet<EndpointId>,
) -> Result<Router> {
    let proxy = Proxy { services: Arc::new(services), allowed: Arc::new(allowed) };
    Ok(Router::builder(bind(key, relay).await?).accept(ALPN, proxy).spawn())
}

// ---------- client ----------

pub struct Client {
    ep: Endpoint,
    server: EndpointId,
    conn: Mutex<Option<Connection>>,
}

impl Client {
    pub async fn new(key: SecretKey, server: EndpointId, relay: Option<RelayUrl>) -> Result<Arc<Self>> {
        Ok(Arc::new(Self { ep: bind(key, relay).await?, server, conn: Mutex::new(None) }))
    }

    pub fn id(&self) -> EndpointId {
        self.ep.id()
    }

    /// Opens a stream, (re)connecting if the connection is gone (e.g. after laptop sleep).
    // ponytail: one lock around open_bi serialises stream opens; fine for a handful of HTTP conns.
    async fn open(&self) -> Result<(SendStream, RecvStream)> {
        let mut conn = self.conn.lock().await;
        if let Some(c) = conn.as_ref().filter(|c| c.close_reason().is_none()) {
            if let Ok(s) = c.open_bi().await {
                return Ok(s);
            }
        }
        let c = self.ep.connect(self.server, ALPN).await?;
        let s = c.open_bi().await?;
        log_paths(c.clone());
        *conn = Some(c);
        Ok(s)
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
                    let (mut send, recv) = this.open().await?;
                    send.write_u8(service.len() as u8).await?;
                    send.write_all(service.as_bytes()).await?;
                    copy_bidirectional(&mut tcp, &mut join(recv, send)).await?;
                    anyhow::Ok(())
                };
                if let Err(e) = res.await {
                    eprintln!("{service}: {e:#}");
                }
            });
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
