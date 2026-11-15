//! DNS for clients: services' hostnames are answered locally, everything else goes to a server's
//! DNS service through the tunnel (e.g. AdGuard Home; on failure, the network's resolvers), or
//! straight to the network's resolvers. Used by the Android VPN and by `iroh-proxy connect`'s
//! `dns` listener ([`serve`]).

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinSet,
    time::timeout,
};

use crate::Client;

/// Short, so answers don't outlive the forwards for long.
pub const TTL: u32 = 30;
/// How long to wait for the tunnel DNS before falling back to the network's.
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(4);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(4);

/// A server's DNS service: the client for that server and the service name.
pub type Tunnel = (Arc<Client>, String);

/// The question of a standard query.
pub struct Question {
    pub name: String,
    pub qtype: u16,
    /// Where the question ends (header + question section).
    pub end: usize,
}

/// The single question of a standard query, if `msg` is one.
pub fn parse_query(msg: &[u8]) -> Option<Question> {
    let flags = u16::from_be_bytes([*msg.get(2)?, *msg.get(3)?]);
    let qdcount = u16::from_be_bytes([*msg.get(4)?, *msg.get(5)?]);
    if flags & 0x8000 != 0 || (flags >> 11) & 0xf != 0 || qdcount != 1 {
        return None; // a response, a non-standard opcode, or several questions
    }
    let mut labels = Vec::new();
    let mut i = 12;
    loop {
        let len = *msg.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression pointers don't occur in queries
        }
        labels.push(std::str::from_utf8(msg.get(i..i + len)?).ok()?);
        i += len;
    }
    let qtype = u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]);
    Some(Question { name: labels.join("."), qtype, end: i + 4 }).filter(|q| q.end <= msg.len())
}

/// An authoritative answer to `query`: an A record for `ip`, or no records for other types (so
/// AAAA lookups fall back to the A record).
pub fn answer(query: &[u8], q: &Question, ip: Ipv4Addr) -> Vec<u8> {
    let a = q.qtype == 1;
    let mut r = query[..q.end].to_vec(); // header + question; drops any EDNS record
    r[2] = 0x84 | (query[2] & 0x01); // response, authoritative, keep RD
    r[3] = 0x80; // recursion available, NOERROR
    r[4..12].copy_from_slice(&[0, 1, 0, a as u8, 0, 0, 0, 0]);
    if a {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // name -> the question's, type A, class IN
        r.extend_from_slice(&TTL.to_be_bytes());
        r.extend_from_slice(&[0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    r
}

/// SERVFAIL for `query` (header only).
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let mut r = query[..12.min(query.len())].to_vec();
    r.resize(12, 0);
    r[2] = 0x80 | (r[2] & 0x01);
    r[3] = 0x82;
    r[4..12].fill(0);
    r
}

/// `reply` cut down to its header with the TC bit set, telling the client to retry over TCP.
pub fn truncated(reply: &[u8]) -> Vec<u8> {
    let mut r = reply[..12.min(reply.len())].to_vec();
    r.resize(12, 0);
    r[2] |= 0x02;
    r[4..12].fill(0);
    r
}

/// The largest UDP reply `query`'s sender accepts: its EDNS buffer size, or 512.
pub fn max_udp_reply(query: &[u8], q: &Question) -> usize {
    let arcount = u16::from_be_bytes([query[10], query[11]]);
    match query.get(q.end..q.end + 5) {
        Some([0, 0, 41, hi, lo]) if arcount > 0 => (u16::from_be_bytes([*hi, *lo]) as usize).max(512),
        _ => 512,
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// How well `pattern` (`name` or `*.suffix`) matches `name`; both normalized.
fn score(pattern: &str, name: &str) -> Option<usize> {
    match pattern.strip_prefix("*.") {
        Some(suffix) => (name.len() > suffix.len() + 1
            && name.ends_with(suffix)
            && name[..name.len() - suffix.len()].ends_with('.'))
        .then_some(suffix.len()),
        None => (pattern == name).then_some(usize::MAX),
    }
}

/// Hostname patterns (exact, or `*.suffix` for any subdomain) and the address each resolves to.
#[derive(Debug, Default, Clone)]
pub struct Names(Vec<(String, Ipv4Addr)>);

impl Names {
    /// Adds `pattern`, unless it's already there (the first address wins).
    pub fn insert(&mut self, pattern: &str, ip: Ipv4Addr) {
        let pattern = normalize(pattern);
        if !self.0.iter().any(|(p, _)| *p == pattern) {
            self.0.push((pattern, ip));
        }
    }

    pub fn get(&self, pattern: &str) -> Option<Ipv4Addr> {
        let pattern = normalize(pattern);
        self.0.iter().find(|(p, _)| *p == pattern).map(|(_, ip)| *ip)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The address for `name`: an exact pattern wins, then the longest matching wildcard.
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let name = normalize(name);
        self.0.iter().filter_map(|(p, ip)| score(p, &name).map(|s| (s, *ip))).max_by_key(|(s, _)| *s).map(|(_, ip)| ip)
    }
}

/// Answers `query`: from `names` if it asks for one of them, else via [`forward`]. `None` for
/// messages too short to be DNS.
pub async fn resolve(
    query: &[u8],
    names: &Names,
    tunnel: Option<&Tunnel>,
    upstream: &[SocketAddr],
    warn: impl Fn(String),
) -> Option<Vec<u8>> {
    if let Some(q) = parse_query(query)
        && let Some(ip) = names.resolve(&q.name)
    {
        return Some(answer(query, &q, ip));
    }
    (query.len() >= 12).then_some(())?;
    Some(forward(query, tunnel, upstream, warn).await)
}

/// Sends `query` to the tunnel DNS if there is one, falling back (on error or after a few
/// seconds) to `upstream`, all of which are asked at once. SERVFAIL if nothing answers.
pub async fn forward(query: &[u8], tunnel: Option<&Tunnel>, upstream: &[SocketAddr], warn: impl Fn(String)) -> Vec<u8> {
    if let Some((server, service)) = tunnel {
        match timeout(TUNNEL_TIMEOUT, server.dns_query(service, query)).await {
            Ok(Ok(reply)) => return reply,
            Ok(Err(e)) => warn(format!("dns via {service}: {e:#}; using the network's")),
            Err(_) => warn(format!("dns via {service}: timed out; using the network's")),
        }
    }
    let query: Arc<[u8]> = query.into();
    let mut asks = JoinSet::new();
    for &server in upstream {
        let query = query.clone();
        asks.spawn(async move {
            let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
            sock.connect(server).await?;
            sock.send(&query).await?;
            let mut buf = vec![0; 65535];
            loop {
                let n = sock.recv(&mut buf).await?;
                if n >= 2 && buf[..2] == query[..2] {
                    buf.truncate(n);
                    return std::io::Result::Ok(buf); // matching id
                }
            }
        });
    }
    let first = timeout(UPSTREAM_TIMEOUT, async {
        while let Some(r) = asks.join_next().await {
            if let Ok(Ok(reply)) = r {
                return Some(reply);
            }
        }
        None
    });
    match first.await {
        Ok(Some(reply)) => reply,
        _ => {
            warn(format!("dns: no answer from {upstream:?}"));
            servfail(&query)
        }
    }
}

/// The resolvers in /etc/resolv.conf (port 53), minus `ours` (the address we answer on), so we
/// never forward to ourselves when the system DNS points at us.
pub fn system_upstream(ours: SocketAddr) -> Vec<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|ip| ip.trim().split('%').next()?.parse().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .filter(|s| *s != ours && !(ours.ip().is_unspecified() && s.port() == ours.port() && s.ip().is_loopback()))
        .collect()
}

/// A DNS server on `addr` (UDP and TCP) answering as [`resolve`] does.
pub async fn serve(addr: SocketAddr, names: Names, tunnel: Option<Tunnel>, upstream: Vec<SocketAddr>) -> Result<()> {
    let udp = Arc::new(UdpSocket::bind(addr).await.with_context(|| format!("binding dns udp {addr}"))?);
    let tcp = TcpListener::bind(addr).await.with_context(|| format!("binding dns tcp {addr}"))?;
    let state = Arc::new((names, tunnel, upstream));
    let warn = |w: String| eprintln!("{w}");

    let s = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = tcp.accept().await else { continue };
            let s = s.clone();
            tokio::spawn(async move {
                // One or more length-prefixed messages per connection.
                while let Ok(len) = conn.read_u16().await {
                    let mut query = vec![0; len as usize];
                    if conn.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    let Some(reply) = resolve(&query, &s.0, s.1.as_ref(), &s.2, warn).await else { return };
                    let msg = [&(reply.len() as u16).to_be_bytes()[..], &reply].concat();
                    if conn.write_all(&msg).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let mut buf = vec![0; 65535];
    loop {
        let (n, from) = udp.recv_from(&mut buf).await?;
        let (query, s, udp) = (buf[..n].to_vec(), state.clone(), udp.clone());
        tokio::spawn(async move {
            let Some(reply) = resolve(&query, &s.0, s.1.as_ref(), &s.2, warn).await else { return };
            let limit = parse_query(&query).map_or(512, |q| max_udp_reply(&query, &q));
            let reply = if reply.len() > limit { truncated(&reply) } else { reply };
            _ = udp.send_to(&reply, from).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u8) -> Vec<u8> {
        // id 0x1234, RD, one question
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, qtype, 0, 1]);
        q
    }

    #[test]
    fn names_prefer_exact_then_longest_wildcard() {
        let mut n = Names::default();
        n.insert("*.example.com", Ipv4Addr::new(1, 1, 1, 1));
        n.insert("*.b.example.com", Ipv4Addr::new(2, 2, 2, 2));
        n.insert("JF.example.com.", Ipv4Addr::new(3, 3, 3, 3));
        n.insert("*.example.com", Ipv4Addr::new(9, 9, 9, 9)); // ignored: already there
        assert_eq!(n.resolve("a.example.com"), Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(n.resolve("x.b.example.com."), Some(Ipv4Addr::new(2, 2, 2, 2)));
        assert_eq!(n.resolve("jf.example.com"), Some(Ipv4Addr::new(3, 3, 3, 3)));
        assert_eq!(n.resolve("example.com"), None);
        assert_eq!(n.resolve("badexample.com"), None);
    }

    #[test]
    fn answers_a_and_empties_aaaa() {
        let q = query("jelly.example.com", 1);
        let parsed = parse_query(&q).unwrap();
        assert_eq!((parsed.name.as_str(), parsed.qtype), ("jelly.example.com", 1));
        let r = answer(&q, &parsed, Ipv4Addr::new(198, 18, 1, 1));
        assert_eq!(&r[..4], &[0x12, 0x34, 0x85, 0x80]);
        assert_eq!(&r[6..8], &[0, 1]);
        assert_eq!(&r[r.len() - 4..], &[198, 18, 1, 1]);

        let q = query("jelly.example.com", 28);
        let r = answer(&q, &parse_query(&q).unwrap(), Ipv4Addr::new(198, 18, 1, 1));
        assert_eq!((&r[6..8], r.len()), (&[0u8, 0][..], q.len()));
    }

    #[test]
    fn udp_reply_limit_follows_edns() {
        let mut q = query("example.com", 1);
        let parsed = parse_query(&q).unwrap();
        assert_eq!(max_udp_reply(&q, &parsed), 512);
        q[11] = 1; // ARCOUNT 1: an OPT record advertising 1232 bytes
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(max_udp_reply(&q, &parse_query(&q).unwrap()), 1232);
        assert_eq!(truncated(&q)[2] & 0x02, 0x02);
    }

    #[tokio::test]
    async fn serves_names_over_udp_and_tcp() {
        let addr: SocketAddr = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let mut names = Names::default();
        names.insert("*.home.test", Ipv4Addr::new(127, 0, 0, 1));
        tokio::spawn(serve(addr, names, None, vec![]));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let q = query("jelly.home.test", 1);
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&q, addr).await.unwrap();
        let mut buf = [0; 512];
        let n = timeout(Duration::from_secs(5), sock.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1]);

        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&[&(q.len() as u16).to_be_bytes()[..], &q].concat()).await.unwrap();
        let mut reply = vec![0; tcp.read_u16().await.unwrap() as usize];
        tcp.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[reply.len() - 4..], &[127, 0, 0, 1]);

        // No tunnel and no upstream: anything else is SERVFAIL.
        sock.send_to(&query("example.org", 1), addr).await.unwrap();
        let n = timeout(Duration::from_secs(10), sock.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!((n, buf[3] & 0x0f), (12, 2));
    }
}
