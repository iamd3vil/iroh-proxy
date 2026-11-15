use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use iroh_proxy::{Client, PeerId, RelayUrl, Service, load_or_create_key};
use serde::Deserialize;

#[derive(Deserialize)]
struct ServerConfig {
    key_file: String,
    relay: Option<RelayUrl>,
    /// Client endpoint ids allowed to connect.
    allowed: HashSet<PeerId>,
    /// name -> "host:port" on the homelab side.
    #[serde(default)]
    services: HashMap<String, String>,
    #[serde(default)]
    udp_services: HashMap<String, String>,
    /// service name -> DNS names (e.g. "*.example.com") VPN-mode clients resolve to it.
    #[serde(default)]
    hostnames: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct ClientConfig {
    key_file: String,
    relay: Option<RelayUrl>,
    server: PeerId,
    /// Every service the server offers is forwarded on 127.0.0.1:<its port> (or a random port if
    /// that is taken). These override the local "host:port" per service name.
    #[serde(default)]
    forwards: HashMap<String, String>,
    #[serde(default)]
    udp_forwards: HashMap<String, String>,
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
            let cfg: ServerConfig = load(path)?;
            let router = iroh_proxy::serve(load_or_create_key(&cfg.key_file)?, cfg.relay, cfg.services, cfg.udp_services, cfg.hostnames, cfg.allowed).await?;
            println!("server id: {}", router.endpoint().id());
            tokio::signal::ctrl_c().await?;
            router.shutdown().await?;
        }
        (Some("connect"), Some(path)) => {
            let cfg: ClientConfig = load(path)?;
            let client = Client::new(load_or_create_key(&cfg.key_file)?, cfg.server, cfg.relay).await?;
            println!("client id: {} (add to server's `allowed`)", client.id());
            let mut services = client.services().await.unwrap_or_else(|e| {
                eprintln!("service discovery failed ({e:#}); forwarding configured services only");
                vec![]
            });
            // Configured forwards the server didn't advertise (e.g. an older server) still count.
            let configured = (cfg.forwards.keys().map(|n| (n, false))).chain(cfg.udp_forwards.keys().map(|n| (n, true)));
            for (name, udp) in configured {
                if !services.iter().any(|s| s.name == *name && s.udp == udp) {
                    services.push(Service { name: name.clone(), udp, port: 0, hostnames: vec![] });
                }
            }
            for svc in &services {
                let addr = if svc.udp { &cfg.udp_forwards } else { &cfg.forwards }.get(&svc.name);
                let proto = if svc.udp { "udp" } else { "tcp" };
                match client.expose(svc, addr.map(String::as_str)).await {
                    Ok(local) => println!("{proto} {local} -> {}", svc.name),
                    Err(e) => eprintln!("{proto} {}: {e:#}", svc.name),
                }
            }
            tokio::signal::ctrl_c().await?;
        }
        (Some("id"), Some(key_file)) => println!("{}", load_or_create_key(key_file)?.public()),
        _ => eprintln!("usage: iroh-proxy serve <server.toml> | connect <client.toml> | id <key_file>"),
    }
    Ok(())
}
