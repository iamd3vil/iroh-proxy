//! VPN mode: services reachable by their usual hostnames (e.g. `https://jelly.example.com`).
//!
//! The app's VPN routes only [`NET`]. It is also the phone's DNS server ([`DNS_IP`]): names a
//! service claims resolve to a virtual IP (one per hostname pattern), everything else is forwarded
//! to the real network's resolvers. TCP to `virtual IP:port` is terminated here by smoltcp and
//! streamed to the service with that hostname and port; anything else is refused.

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsRawFd, OwnedFd},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use iroh_proxy::{Client, Service};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr, TcpPacket, UdpPacket,
        UdpRepr,
    },
};
use tokio::{
    io::unix::AsyncFd,
    net::UdpSocket,
    sync::{
        Notify,
        mpsc::{self, error::TryRecvError, error::TrySendError},
    },
    time::{sleep, timeout},
};

/// The VPN's address range; the Android side routes exactly this.
pub const NET: (Ipv4Addr, u8) = (Ipv4Addr::new(198, 18, 0, 0), 16);
/// The TUN interface's own address.
pub const IFACE_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// The DNS server the VPN hands to the phone.
pub const DNS_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
/// Virtual IPs for hostname patterns count up from here.
const FIRST_VIP: Ipv4Addr = Ipv4Addr::new(198, 18, 1, 1);
pub const MTU: usize = 1500;
/// Short, so stale answers don't outlive the VPN for long.
const DNS_TTL: u32 = 30;
const TCP_BUF: usize = 128 * 1024;
/// A listening socket whose handshake never completed is dropped after this.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The real network's DNS servers, for names that aren't ours. Set from the Android side.
static UPSTREAM: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

pub fn set_upstream(mut servers: Vec<SocketAddr>) {
    // Never ourselves: that would loop (and can't work, as the app bypasses its own VPN).
    let ours = |ip: &Ipv4Addr| u32::from(*ip) >> (32 - NET.1) == u32::from(NET.0) >> (32 - NET.1);
    servers.retain(|s| !matches!(s, SocketAddr::V4(v4) if ours(v4.ip())));
    crate::info(&format!("dns upstream: {servers:?}"));
    *UPSTREAM.lock().unwrap() = servers;
}

/// Which names resolve to which virtual IP, and which service each `virtual IP:port` reaches.
pub struct Table {
    names: Vec<(String, Ipv4Addr)>,
    ports: HashMap<SocketAddrV4, String>,
}

impl Table {
    /// From the TCP services' hostnames; UDP isn't routed in VPN mode.
    pub fn new(services: &[Service]) -> Self {
        let tcp = || services.iter().filter(|s| !s.udp);
        let mut patterns: Vec<String> = tcp().flat_map(|s| s.hostnames.iter().map(|h| normalize(h))).collect();
        patterns.sort();
        patterns.dedup();
        let names: Vec<(String, Ipv4Addr)> =
            patterns.into_iter().enumerate().map(|(i, p)| (p, Ipv4Addr::from(u32::from(FIRST_VIP) + i as u32))).collect();
        let mut ports = HashMap::new();
        for svc in tcp() {
            for h in &svc.hostnames {
                let vip = names.iter().find(|(p, _)| *p == normalize(h)).unwrap().1;
                ports.entry(SocketAddrV4::new(vip, svc.port)).or_insert_with(|| svc.name.clone());
            }
        }
        Self { names, ports }
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The virtual IP for `name`: an exact pattern wins, then the longest matching wildcard.
    fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let name = normalize(name);
        self.names.iter().filter_map(|(p, ip)| score(p, &name).map(|s| (s, *ip))).max_by_key(|(s, _)| *s).map(|(_, ip)| ip)
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// How well `pattern` (`name` or `*.suffix`) matches `name`; both normalized.
fn score(pattern: &str, name: &str) -> Option<usize> {
    match pattern.strip_prefix("*.") {
        Some(suffix) => (name.len() > suffix.len() + 1 && name.ends_with(suffix) && name[..name.len() - suffix.len()].ends_with('.'))
            .then_some(suffix.len()),
        None => (pattern == name).then_some(usize::MAX),
    }
}

// ---------- DNS ----------

struct Question {
    name: String,
    qtype: u16,
    /// Where the question ends (header + question section).
    end: usize,
}

/// The single question of a standard query, if `msg` is one.
fn parse_query(msg: &[u8]) -> Option<Question> {
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
fn answer(query: &[u8], q: &Question, ip: Ipv4Addr) -> Vec<u8> {
    let a = q.qtype == 1;
    let mut r = query[..q.end].to_vec(); // header + question; drops any EDNS record
    r[2] = 0x84 | (query[2] & 0x01); // response, authoritative, keep RD
    r[3] = 0x80; // recursion available, NOERROR
    r[4..12].copy_from_slice(&[0, 1, 0, a as u8, 0, 0, 0, 0]);
    if a {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // name -> the question's, type A, class IN
        r.extend_from_slice(&DNS_TTL.to_be_bytes());
        r.extend_from_slice(&[0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    r
}

/// SERVFAIL for `query` (header only).
fn servfail(query: &[u8]) -> Vec<u8> {
    let mut r = query[..12.min(query.len())].to_vec();
    r.resize(12, 0);
    r[2] = 0x80 | (r[2] & 0x01);
    r[3] = 0x82;
    r[4..12].fill(0);
    r
}

/// Sends `query` to all of the real network's resolvers at once and queues the first reply for
/// `client` (some listed servers, e.g. IPv6 ones, may not answer at all).
async fn forward_dns(query: Vec<u8>, client: SocketAddrV4, replies: mpsc::Sender<(SocketAddrV4, Vec<u8>)>) {
    let upstream = UPSTREAM.lock().unwrap().clone();
    let query = Arc::new(query);
    let mut asks = tokio::task::JoinSet::new();
    for server in upstream {
        let query = query.clone();
        asks.spawn(async move {
            let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
            sock.connect(server).await?;
            sock.send(&query).await?;
            let mut buf = vec![0; 4096];
            loop {
                let n = sock.recv(&mut buf).await?;
                if n >= 2 && buf[..2] == query[..2] {
                    buf.truncate(n);
                    return io::Result::Ok(buf); // matching id
                }
            }
        });
    }
    let first = timeout(Duration::from_secs(4), async {
        while let Some(r) = asks.join_next().await {
            if let Ok(Ok(reply)) = r {
                return Some(reply);
            }
        }
        None
    });
    let reply = match first.await {
        Ok(Some(reply)) => reply,
        _ => {
            crate::log(&format!("dns: no answer from {:?}", *UPSTREAM.lock().unwrap()));
            servfail(&query)
        }
    };
    _ = replies.send((client, reply)).await;
}

/// An IPv4/UDP packet from `src` to `dst`. Replies too big for the MTU are truncated (TC bit),
/// as a DNS server would over UDP.
fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let truncated;
    let payload = if 20 + 8 + payload.len() > MTU && payload.len() >= 12 {
        let mut t = servfail(payload);
        t[3] = payload[3];
        t[2] = payload[2] | 0x02;
        truncated = t;
        &truncated[..]
    } else {
        payload
    };
    let caps = ChecksumCapabilities::default();
    let ip = Ipv4Repr {
        src_addr: *src.ip(),
        dst_addr: *dst.ip(),
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    };
    let mut buf = vec![0; ip.buffer_len() + ip.payload_len];
    let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
    ip.emit(&mut p, &caps);
    UdpRepr { src_port: src.port(), dst_port: dst.port() }.emit(
        &mut UdpPacket::new_unchecked(p.payload_mut()),
        &IpAddress::Ipv4(*src.ip()),
        &IpAddress::Ipv4(*dst.ip()),
        payload.len(),
        |b| b.copy_from_slice(payload),
        &caps,
    );
    buf
}

// ---------- TUN + TCP ----------

/// smoltcp's view of the TUN: packets queued in memory, moved to/from the fd by [`run`].
#[derive(Default)]
struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}

/// One phone-side TCP connection and the channels to its [`bridge`] task.
struct Conn {
    handle: SocketHandle,
    /// To the service; dropped once the phone side has sent FIN.
    to_service: Option<mpsc::Sender<Vec<u8>>>,
    /// From the service; closed once it has sent everything.
    from_service: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    sent: usize,
    closing: bool,
    born: Instant,
}

fn now() -> smoltcp::time::Instant {
    smoltcp::time::Instant::now()
}

fn sys(n: isize) -> io::Result<usize> {
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

/// Serves the TUN `fd` until it fails or the task is dropped (which closes it, ending the VPN).
pub async fn run(fd: OwnedFd, table: Table, client: Arc<Client>) -> Result<()> {
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    // SAFETY: an OwnedFd stays open and keeps its number for as long as it is owned.
    let tun = unsafe { AsyncFd::register(fd) }.map_err(|e| anyhow::anyhow!("registering tun: {e}"))?;
    let write = |p: &[u8]| {
        // A full TUN drops the packet, as a link would; TCP retransmits.
        _ = sys(unsafe { libc::write(tun.get_ref().as_raw_fd(), p.as_ptr().cast(), p.len()) });
    };

    let mut dev = Queue::default();
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
    iface.update_ip_addrs(|a| a.push(IpCidr::new(IpAddress::Ipv4(IFACE_IP), NET.1)).unwrap());
    iface.set_any_ip(true); // accept connections to every virtual IP
    let mut sockets = SocketSet::new(vec![]);
    let mut conns: HashMap<(SocketAddrV4, SocketAddrV4), Conn> = HashMap::new();
    let notify = Arc::new(Notify::new());
    let (dns_tx, mut dns_rx) = mpsc::channel::<(SocketAddrV4, Vec<u8>)>(64);
    let mut buf = vec![0u8; 65536];
    let mut incoming = Vec::new();

    loop {
        for p in dev.tx.drain(..) {
            write(&p);
        }
        let delay = iface.poll_delay(now(), &sockets).map_or(Duration::from_secs(5), |d| Duration::from_micros(d.total_micros()));
        tokio::select! {
            ready = tun.readable() => {
                let mut ready = ready?;
                while let Ok(n) = ready.try_io(|fd| sys(unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) })) {
                    match n? {
                        0 => return Ok(()),
                        n => incoming.push(buf[..n].to_vec()),
                    }
                }
            }
            Some((dst, reply)) = dns_rx.recv() => write(&udp_packet(SocketAddrV4::new(DNS_IP, 53), dst, &reply)),
            _ = notify.notified() => {}
            _ = sleep(delay.min(Duration::from_secs(5))) => {}
        }

        for pkt in incoming.drain(..) {
            let Ok(ip) = Ipv4Packet::new_checked(&pkt[..]) else { continue }; // IPv6 isn't routed here
            let (src_ip, dst_ip) = (ip.src_addr(), ip.dst_addr());
            match ip.next_header() {
                IpProtocol::Udp if dst_ip == DNS_IP => {
                    let Ok(udp) = UdpPacket::new_checked(ip.payload()) else { continue };
                    if udp.dst_port() != 53 {
                        continue;
                    }
                    let client_addr = SocketAddrV4::new(src_ip, udp.src_port());
                    let query = udp.payload();
                    match parse_query(query).and_then(|q| Some((table.resolve(&q.name)?, q))) {
                        Some((vip, q)) => write(&udp_packet(SocketAddrV4::new(DNS_IP, 53), client_addr, &answer(query, &q, vip))),
                        None if query.len() >= 12 => {
                            tokio::spawn(forward_dns(query.to_vec(), client_addr, dns_tx.clone()));
                        }
                        None => {}
                    }
                    continue;
                }
                IpProtocol::Tcp => {
                    if let Ok(tcp) = TcpPacket::new_checked(ip.payload()) {
                        let key = (SocketAddrV4::new(src_ip, tcp.src_port()), SocketAddrV4::new(dst_ip, tcp.dst_port()));
                        if tcp.syn() && !tcp.ack() && !conns.contains_key(&key)
                            && let Some(service) = table.ports.get(&key.1)
                            && let Some(conn) = accept(key.1, service, &client, &notify, &mut sockets)
                        {
                            conns.insert(key, conn);
                        }
                    }
                }
                _ => {}
            }
            // smoltcp answers the rest: TCP for our connections, RST/ICMP unreachable otherwise.
            dev.rx.push_back(pkt);
        }

        iface.poll(now(), &mut dev, &mut sockets);
        pump(&mut conns, &mut sockets);
        iface.poll(now(), &mut dev, &mut sockets);
    }
}

/// A listening socket for a SYN to `dst`, plus a task streaming the connection to `service`.
fn accept(dst: SocketAddrV4, service: &str, client: &Arc<Client>, notify: &Arc<Notify>, sockets: &mut SocketSet) -> Option<Conn> {
    let mut sock = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUF]), tcp::SocketBuffer::new(vec![0; TCP_BUF]));
    sock.set_nagle_enabled(false);
    sock.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    sock.listen(IpListenEndpoint { addr: Some(IpAddress::Ipv4(*dst.ip())), port: dst.port() }).ok()?;
    let (to_service, up) = mpsc::channel(16);
    let (down, from_service) = mpsc::channel(16);
    tokio::spawn(bridge(client.clone(), service.to_owned(), up, down, notify.clone()));
    Some(Conn {
        handle: sockets.add(sock),
        to_service: Some(to_service),
        from_service,
        pending: Vec::new(),
        sent: 0,
        closing: false,
        born: Instant::now(),
    })
}

/// Moves data between each smoltcp socket and its bridge task, and reaps finished connections.
fn pump(conns: &mut HashMap<(SocketAddrV4, SocketAddrV4), Conn>, sockets: &mut SocketSet) {
    use tcp::State;
    conns.retain(|_, c| {
        let s = sockets.get_mut::<tcp::Socket>(c.handle);

        if let Some(tx) = &c.to_service {
            while s.can_recv() {
                match tx.try_reserve() {
                    Ok(permit) => {
                        if let Ok(data) = s.recv(|b| (b.len(), b.to_vec())) {
                            permit.send(data);
                        }
                    }
                    Err(TrySendError::Full(())) => break, // leave it in smoltcp; its window closes
                    Err(TrySendError::Closed(())) => {
                        s.abort();
                        break;
                    }
                }
            }
            let handshaking = matches!(s.state(), State::Listen | State::SynReceived | State::SynSent);
            if !s.may_recv() && !handshaking {
                c.to_service = None; // the phone sent FIN: finish the stream to the service
            }
        }

        loop {
            if c.sent == c.pending.len() {
                match c.from_service.try_recv() {
                    Ok(d) => (c.pending, c.sent) = (d, 0),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        if !c.closing {
                            s.close();
                            c.closing = true;
                        }
                        break;
                    }
                }
            }
            match s.send_slice(&c.pending[c.sent..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => c.sent += n,
            }
        }

        let done = s.state() == State::Closed || (s.state() == State::Listen && c.born.elapsed() > HANDSHAKE_TIMEOUT);
        if done {
            sockets.remove(c.handle);
        }
        !done
    });
}

/// Streams one phone-side connection to `service`. Ends (closing the phone side) when either
/// side is done; errors such as the service being down just close the connection.
async fn bridge(
    client: Arc<Client>,
    service: String,
    mut up: mpsc::Receiver<Vec<u8>>,
    down: mpsc::Sender<Vec<u8>>,
    notify: Arc<Notify>,
) {
    let res = async {
        let (mut send, mut recv) = client.connect(&service).await?;
        let n = notify.clone();
        let to_service = async {
            while let Some(d) = up.recv().await {
                n.notify_one(); // room for more
                send.write_all(&d).await?;
            }
            send.finish()?;
            anyhow::Ok(())
        };
        let n = notify.clone();
        // Owns `down`, so the phone side gets FIN as soon as the service is done.
        let to_phone = async move {
            let mut buf = vec![0; 16 * 1024];
            while let Some(len) = recv.read(&mut buf).await? {
                if down.send(buf[..len].to_vec()).await.is_err() {
                    break;
                }
                n.notify_one();
            }
            anyhow::Ok(())
        };
        tokio::try_join!(to_service, to_phone)?;
        anyhow::Ok(())
    };
    if let Err(e) = res.await {
        crate::log(&format!("{service}: {e:#}"));
    }
    notify.notify_one();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(name: &str, port: u16, hosts: &[&str]) -> Service {
        Service { name: name.into(), udp: false, port, hostnames: hosts.iter().map(|h| h.to_string()).collect() }
    }

    #[test]
    fn resolves_exact_before_wildcard() {
        let t = Table::new(&[svc("proxy", 443, &["*.example.com"]), svc("proxy-http", 80, &["*.example.com"]), svc("jf", 8096, &["JF.example.com."])]);
        let wild = t.resolve("jelly.example.com").unwrap();
        assert_eq!(t.resolve("a.b.example.com."), Some(wild));
        assert_ne!(t.resolve("jf.example.com"), Some(wild));
        assert_eq!(t.resolve("example.com"), None);
        assert_eq!(t.resolve("badexample.com"), None);
        assert_eq!(t.ports[&SocketAddrV4::new(wild, 443)], "proxy");
        assert_eq!(t.ports[&SocketAddrV4::new(wild, 80)], "proxy-http");
        assert!(!t.ports.contains_key(&SocketAddrV4::new(wild, 22)));
    }

    #[test]
    fn answers_a_and_empties_aaaa() {
        // id 0x1234, RD, one question: jelly.example.com A IN
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["jelly", "example", "com"] {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let parsed = parse_query(&q).unwrap();
        assert_eq!((parsed.name.as_str(), parsed.qtype), ("jelly.example.com", 1));
        let r = answer(&q, &parsed, Ipv4Addr::new(198, 18, 1, 1));
        assert_eq!(&r[..4], &[0x12, 0x34, 0x85, 0x80]);
        assert_eq!(&r[6..8], &[0, 1]);
        assert_eq!(&r[r.len() - 4..], &[198, 18, 1, 1]);

        let n = q.len();
        q[n - 3] = 28; // AAAA
        let r = answer(&q, &parse_query(&q).unwrap(), Ipv4Addr::new(198, 18, 1, 1));
        assert_eq!((&r[6..8], r.len()), (&[0u8, 0][..], q.len()));
    }
}
