use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use iroh_proxy::{Client, PeerId, RelayUrl, load_or_create_key};
use serde::Deserialize;
use tokio::net::{TcpListener, UdpSocket};

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
}

#[derive(Deserialize)]
struct ClientConfig {
    key_file: String,
    relay: Option<RelayUrl>,
    server: PeerId,
    /// service name -> local "host:port" to listen on.
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
            let router = iroh_proxy::serve(load_or_create_key(&cfg.key_file)?, cfg.relay, cfg.services, cfg.udp_services, cfg.allowed).await?;
            println!("server id: {}", router.endpoint().id());
            tokio::signal::ctrl_c().await?;
            router.shutdown().await?;
        }
        (Some("connect"), Some(path)) => {
            let cfg: ClientConfig = load(path)?;
            let client = Client::new(load_or_create_key(&cfg.key_file)?, cfg.server, cfg.relay).await?;
            println!("client id: {} (add to server's `allowed`)", client.id());
            for (service, local) in cfg.forwards {
                let listener = TcpListener::bind(&local).await.with_context(|| format!("binding {local}"))?;
                println!("{local} -> {service}");
                tokio::spawn(client.clone().forward(service, listener));
            }
            for (service, local) in cfg.udp_forwards {
                let sock = UdpSocket::bind(&local).await.with_context(|| format!("binding udp {local}"))?;
                println!("udp {local} -> {service}");
                tokio::spawn(client.clone().forward_udp(service, sock));
            }
            tokio::signal::ctrl_c().await?;
        }
        (Some("id"), Some(key_file)) => println!("{}", load_or_create_key(key_file)?.public()),
        _ => eprintln!("usage: iroh-proxy serve <server.toml> | connect <client.toml> | id <key_file>"),
    }
    Ok(())
}
