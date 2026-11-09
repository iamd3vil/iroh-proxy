// Needs internet: peers find each other via n0 DNS/relays, like in real use.
use std::{collections::HashMap, time::Duration};

use iroh_proxy::{Client, Key, serve};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
    let router = serve(server_key.clone(), services, [good.public()].into()).await.unwrap();
    router.endpoint().online().await;

    let ok = Client::new(good, server_key.public()).await.unwrap();
    assert_eq!(roundtrip(ok.clone(), "echo").await.unwrap(), b"hello");
    assert!(roundtrip(ok, "nope").await.is_err(), "unknown service must not connect");

    let stranger = Client::new(bad, server_key.public()).await.unwrap();
    assert!(roundtrip(stranger, "echo").await.is_err(), "non-allowlisted peer must be rejected");
}
