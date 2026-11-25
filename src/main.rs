use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use iroh_proxy::{
    Client, InviteRejected, PeerId, RelayUrl, ServerConfig, Service, bind, create_invite, de_relay, dns, invite_code, load_or_create_key,
    parse_invite,
};
use serde::Deserialize;

#[cfg(all(unix, not(target_os = "android")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Deserialize)]
struct ServerFile {
    key_file: String,
    /// Preferred over n0's relays, which are used while it is down; also put in invites.
    #[serde(default, deserialize_with = "de_relay")]
    relay: Option<RelayUrl>,
    #[serde(flatten)]
    cfg: ServerConfig,
}

impl ServerFile {
    /// `state_dir` defaults to the key file's directory.
    fn load(path: &str) -> Result<Self> {
        let mut f: Self = load(path)?;
        if f.cfg.state_dir.is_none() {
            let dir = Path::new(&f.key_file).parent().unwrap_or(Path::new("."));
            f.cfg.state_dir = Some(if dir.as_os_str().is_empty() { PathBuf::from(".") } else { dir.to_owned() });
        }
        Ok(f)
    }
}

#[derive(Deserialize)]
struct ClientConfig {
    key_file: String,
    /// Preferred over n0's relays, which are used while it is down. `join` sets it from the
    /// invite if unset.
    #[serde(default, deserialize_with = "de_relay")]
    relay: Option<RelayUrl>,
    /// The server to connect to; or several, with `servers`. All see the same client id.
    server: Option<PeerId>,
    #[serde(default)]
    servers: Vec<PeerId>,
    /// Every service the servers offer is forwarded on 127.0.0.1:<its port> (or a random port if
    /// that is taken). These override the local "host:port" per service name.
    #[serde(default)]
    forwards: HashMap<String, String>,
    #[serde(default)]
    udp_forwards: HashMap<String, String>,
    /// Run a DNS server here (e.g. "127.0.0.1:53") answering the services' hostnames with their
    /// local forward's address, and everything else via a server's DNS service (if one is
    /// offered) or `upstream_dns`.
    dns: Option<SocketAddr>,
    /// Resolvers for names the servers don't handle ("ip" or "ip:port"); default: the system's,
    /// from /etc/resolv.conf (minus `dns` itself).
    upstream_dns: Option<Vec<String>>,
}

/// How long to wait for each server's service list.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);

async fn connect(cfg: ClientConfig) -> Result<()> {
    let mut servers: Vec<PeerId> = cfg.server.into_iter().chain(cfg.servers).collect();
    let mut seen = HashSet::new();
    servers.retain(|s| seen.insert(*s));
    if servers.is_empty() {
        bail!("no `server` or `servers` in the config");
    }
    let ep = bind(load_or_create_key(&cfg.key_file)?, cfg.relay).await?;
    println!("client id: {} (add to each server's `allowed`)", ep.id());
    let clients: Vec<_> = servers.iter().map(|s| Client::with_endpoint(ep.clone(), *s)).collect();

    // Discover all servers at once; a slow or offline one shouldn't hold up the rest.
    let mut found = vec![vec![]; clients.len()];
    let mut asks = tokio::task::JoinSet::new();
    for (i, c) in clients.iter().enumerate() {
        let c = c.clone();
        asks.spawn(async move { (i, tokio::time::timeout(DISCOVERY_TIMEOUT, c.services()).await) });
    }
    while let Some(Ok((i, res))) = asks.join_next().await {
        match res {
            Ok(Ok(list)) => found[i] = list,
            Ok(Err(e)) => eprintln!("{}: service discovery failed ({e:#})", servers[i].fmt_short()),
            Err(_) => eprintln!("{}: service discovery timed out", servers[i].fmt_short()),
        }
    }
    // Configured forwards nobody advertised (e.g. an older server) go to the first server.
    let configured = (cfg.forwards.keys().map(|n| (n, false))).chain(cfg.udp_forwards.keys().map(|n| (n, true)));
    for (name, udp) in configured {
        if !found.iter().flatten().any(|s| s.name == *name && s.udp == udp) {
            found[0].push(Service { name: name.clone(), udp, port: 0, hostnames: vec![], dns: false });
        }
    }

    let mut names = dns::Names::default();
    let mut tunnel = None;
    for (client, services) in clients.iter().zip(&found) {
        let from = if clients.len() > 1 { format!(" on {}", client.server().fmt_short()) } else { String::new() };
        for svc in services {
            if svc.dns {
                if tunnel.is_none() {
                    println!("dns -> {}{from}", svc.name);
                    tunnel = Some((client.clone(), svc.name.clone()));
                }
                continue;
            }
            let addr = if svc.udp { &cfg.udp_forwards } else { &cfg.forwards }.get(&svc.name);
            let proto = if svc.udp { "udp" } else { "tcp" };
            let local = match client.expose(svc, addr.map(String::as_str)).await {
                Ok(local) => local,
                Err(e) => {
                    eprintln!("{proto} {}{from}: {e:#}", svc.name);
                    continue;
                }
            };
            println!("{proto} {local} -> {}{from}", svc.name);
            if svc.udp || svc.hostnames.is_empty() {
                continue;
            }
            let ip = match local.ip() {
                IpAddr::V4(ip) if !ip.is_unspecified() => ip,
                _ => Ipv4Addr::LOCALHOST,
            };
            for h in &svc.hostnames {
                names.insert(h, ip);
            }
            if cfg.dns.is_some() && local.port() != svc.port {
                eprintln!(
                    "  dns answers {} with {ip}, but {} is on port {} there, not {}; set forwards.{} = \"{ip}:{}\" \
                     (ports below 1024 need root)",
                    svc.hostnames.join(", "),
                    svc.name,
                    local.port(),
                    svc.port,
                    svc.name,
                    svc.port,
                );
            }
        }
    }

    if let Some(addr) = cfg.dns {
        let upstream: Vec<SocketAddr> = match &cfg.upstream_dns {
            Some(list) => list
                .iter()
                .map(|s| s.parse().or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53))))
                .collect::<Result<_, _>>()
                .context("upstream_dns")?,
            None => dns::system_upstream(addr),
        };
        if upstream.is_empty() {
            eprintln!("dns: no upstream resolvers; set upstream_dns (e.g. your router) for names the servers don't handle");
        }
        println!("dns {addr}: hostnames locally, then {}", if tunnel.is_some() { "the server's DNS" } else { "upstream" });
        tokio::spawn(async move {
            if let Err(e) = dns::serve(addr, names, tunnel, upstream).await {
                eprintln!("dns: {e:#}");
            }
        });
    }
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn load<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    Ok(toml::from_str(&s)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("serve"), Some(path)) => {
            let f = ServerFile::load(path)?;
            let router = iroh_proxy::serve(load_or_create_key(&f.key_file)?, f.relay, f.cfg).await?;
            println!("server id: {}", router.endpoint().id());
            tokio::signal::ctrl_c().await?;
            router.shutdown().await?;
        }
        (Some("invite"), Some(path)) => {
            let f = ServerFile::load(path)?;
            let label = args.get(3).map_or("", String::as_str);
            let token = create_invite(f.cfg.state_dir.as_deref().unwrap(), label)?;
            let server = load_or_create_key(&f.key_file)?.public();
            println!("{}", invite_code(server, &token, f.relay.as_ref()));
            eprintln!("One-time invite{}. Paste it into the app, or run `iroh-proxy join <client.toml> <invite>`.",
                if label.is_empty() { String::new() } else { format!(" for {label}") });
        }
        (Some("join"), Some(path)) => {
            let cfg: ClientConfig = load(path)?;
            let invite = args.get(3).and_then(|c| parse_invite(c)).context("usage: join <client.toml> <invite code>")?;
            let (server, token) = (invite.server, invite.token);
            let client = Client::new(load_or_create_key(&cfg.key_file)?, server, cfg.relay.clone()).await?;
            // A server that just started may not be findable yet; a refused invite is final.
            let mut tries = 0;
            while let Err(e) = client.redeem(&token).await {
                tries += 1;
                if tries == 4 || e.downcast_ref::<InviteRejected>().is_some() {
                    return Err(e);
                }
                eprintln!("{e:#}; retrying");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            println!("joined {server}");
            if !cfg.server.iter().chain(&cfg.servers).any(|s| *s == server) {
                eprintln!("Add it to `servers` in {path} to connect to it.");
            }
            // Like the app: the server's relay, unless one is set already.
            if let (Some(relay), None) = (invite.relay, &cfg.relay) {
                let old = std::fs::read_to_string(path)?;
                // At the top, since a top-level key can't come after a [table].
                std::fs::write(path, format!("relay = \"{relay}\"\n{old}"))?;
                println!("relay set to {relay} in {path}");
            }
        }
        (Some("connect"), Some(path)) => connect(load(path)?).await?,
        (Some("id"), Some(key_file)) => println!("{}", load_or_create_key(key_file)?.public()),
        _ => eprintln!(
            "usage: iroh-proxy serve <server.toml> | invite <server.toml> [label] | connect <client.toml> \
             | join <client.toml> <invite> | id <key_file>"
        ),
    }
    Ok(())
}
