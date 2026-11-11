// Needs internet: peers find each other via n0 DNS/relays, like in real use.
use std::{collections::HashMap, time::Duration};

use iroh_proxy::{Client, Key, serve};
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
    let services = HashMap::from([("echo".to_string(), echo_server().await)]);
    let udp = HashMap::from([("echo".to_string(), udp_echo_server().await)]);
    let router = serve(server_key.clone(), None, services, udp, [good.public()].into()).await.unwrap();
    router.endpoint().online().await;

    let ok = Client::new(good, server_key.public(), None).await.unwrap();
    assert_eq!(roundtrip(ok.clone(), "echo").await.unwrap(), b"hello");
    assert!(roundtrip(ok.clone(), "nope").await.is_err(), "unknown service must not connect");
    assert_eq!(udp_roundtrip(ok, "echo").await.as_deref(), Some(&b"ping"[..]));

    let stranger = Client::new(bad, server_key.public(), None).await.unwrap();
    assert!(roundtrip(stranger.clone(), "echo").await.is_err(), "non-allowlisted peer must be rejected");
    assert_eq!(udp_roundtrip(stranger, "echo").await, None, "non-allowlisted peer must not get udp");
}
