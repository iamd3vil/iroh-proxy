// Needs internet: peers find each other via n0 DNS/relays, like in real use.
use std::{collections::HashMap, time::Duration};

use iroh_proxy::{Client, Key, ServerConfig, Service, create_invite, serve};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

async fn echo_server() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                tokio::io::copy(&mut r, &mut w).await.ok();
            });
        }
    });
    addr
}

async fn udp_echo_server() -> String {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut buf = [0; 1500];
        loop {
            let (n, from) = s.recv_from(&mut buf).await.unwrap();
            s.send_to(&buf[..n], from).await.unwrap();
        }
    });
    addr
}

/// A stand-in DNS server over TCP: answers each length-prefixed message with "re:" + message.
async fn dns_tcp_server() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut msg = vec![0; s.read_u16().await.unwrap() as usize];
                s.read_exact(&mut msg).await.unwrap();
                let reply = [&b"re:"[..], &msg].concat();
                s.write_u16(reply.len() as u16).await.unwrap();
                s.write_all(&reply).await.unwrap();
            });
        }
    });
    addr
}

/// Datagrams can be lost, so retry a few times.
async fn udp_roundtrip(client: std::sync::Arc<Client>, service: &str) -> Option<Vec<u8>> {
    let fwd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = fwd.local_addr().unwrap();
    tokio::spawn(client.forward_udp(service.into(), fwd));
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0; 16];
    for _ in 0..5 {
        s.send_to(b"ping", addr).await.unwrap();
        if let Ok(Ok(n)) = timeout(Duration::from_secs(4), s.recv(&mut buf)).await {
            return Some(buf[..n].to_vec());
        }
    }
    None
}

async fn roundtrip(client: std::sync::Arc<Client>, service: &str) -> std::io::Result<Vec<u8>> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    tokio::spawn(client.forward(service.into(), l));
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(b"hello").await?;
    let mut buf = vec![0; 5];
    timeout(Duration::from_secs(20), s.read_exact(&mut buf)).await??;
    Ok(buf)
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_peer_reaches_service_and_stranger_does_not() {
    let (server_key, good, bad) = (Key::generate(), Key::generate(), Key::generate());
    let (tcp_addr, udp_addr) = (echo_server().await, udp_echo_server().await);
    let port = |a: &str| a.rsplit_once(':').unwrap().1.parse::<u16>().unwrap();
    let (tcp_port, udp_port) = (port(&tcp_addr), port(&udp_addr));
    let services = HashMap::from([("echo".to_string(), tcp_addr), ("dns".to_string(), dns_tcp_server().await)]);
    let udp = HashMap::from([("echo".to_string(), udp_addr)]);
    let hostnames = HashMap::from([("echo".to_string(), vec!["*.echo.test".to_string()])]);
    let cfg = ServerConfig {
        services,
        udp_services: udp,
        hostnames,
        dns: Some("dns".into()),
        allowed: [good.public()].into(),
        ..Default::default()
    };
    let router = serve(server_key.clone(), None, cfg).await.unwrap();
    router.endpoint().online().await;

    let ok = Client::new(good, server_key.public(), None).await.unwrap();
    assert_eq!(roundtrip(ok.clone(), "echo").await.unwrap(), b"hello");
    assert!(roundtrip(ok.clone(), "nope").await.is_err(), "unknown service must not connect");
    assert_eq!(udp_roundtrip(ok.clone(), "echo").await.as_deref(), Some(&b"ping"[..]));

    let found = ok.services().await.unwrap();
    let hosts = vec!["*.echo.test".to_string()];
    let echo = Service { name: "echo".into(), udp: false, port: tcp_port, hostnames: hosts.clone(), dns: false };
    assert!(found.contains(&echo));
    assert!(found.contains(&Service { name: "echo".into(), udp: true, port: udp_port, hostnames: hosts, dns: false }));
    assert!(found.iter().any(|s| s.name == "dns" && s.dns), "dns service must be advertised: {found:?}");
    assert_eq!(found.len(), 3);
    assert_eq!(ok.dns_query("dns", b"query").await.unwrap(), b"re:query");
    assert!(ok.path().is_some(), "a connected client reports its path");
    // The echo server already holds its own port, so expose must fall back to a random one.
    let local = ok.expose(&echo, None).await.unwrap();
    assert_ne!(local.port(), tcp_port);
    let mut s = TcpStream::connect(local).await.unwrap();
    s.write_all(b"hi").await.unwrap();
    let mut buf = [0; 2];
    timeout(Duration::from_secs(20), s.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"hi");

    let stranger = Client::new(bad, server_key.public(), None).await.unwrap();
    assert!(stranger.services().await.is_err(), "non-allowlisted peer must not list services");
    assert!(roundtrip(stranger.clone(), "echo").await.is_err(), "non-allowlisted peer must be rejected");
    assert_eq!(udp_roundtrip(stranger, "echo").await, None, "non-allowlisted peer must not get udp");
}

#[tokio::test(flavor = "multi_thread")]
async fn invites_let_new_clients_in_once() {
    let dir = std::env::temp_dir().join(format!("iroh-proxy-test-{}", std::process::id()));
    let server_key = Key::generate();
    let services = HashMap::from([("echo".to_string(), echo_server().await)]);
    let cfg = ServerConfig { services, state_dir: Some(dir.clone()), name: Some("Home".into()), ..Default::default() };
    let router = serve(server_key.clone(), None, cfg.clone()).await.unwrap();
    router.endpoint().online().await;

    let token = create_invite(&dir, "mom-phone").unwrap();
    let (newcomer, other) = (Key::generate(), Key::generate());
    let client = Client::new(newcomer.clone(), server_key.public(), None).await.unwrap();
    assert!(client.services().await.is_err(), "not allowed before redeeming");
    assert!(client.redeem("00000000000000000000000000000000").await.is_err(), "a wrong token is refused");
    client.redeem(&token).await.unwrap();
    assert_eq!(roundtrip(client.clone(), "echo").await.unwrap(), b"hello");
    assert_eq!(iroh_proxy::parse_server_name(&client.listing().await.unwrap()).as_deref(), Some("Home"));

    let second = Client::new(other, server_key.public(), None).await.unwrap();
    assert!(second.redeem(&token).await.is_err(), "an invite works once");
    assert!(second.services().await.is_err());

    // Remembered across restarts (state_dir/allowed).
    router.shutdown().await.unwrap();
    let router = serve(server_key.clone(), None, cfg).await.unwrap();
    router.endpoint().online().await;
    let again = Client::new(newcomer, server_key.public(), None).await.unwrap();
    assert!(again.services().await.is_ok());
    assert!(std::fs::read_to_string(dir.join("allowed")).unwrap().contains("mom-phone"));
    _ = std::fs::remove_dir_all(&dir);
}
