//! VPN mode: services reachable by their usual hostnames (e.g. `https://jelly.example.com`).
//!
//! The app's VPN routes only [`NET`]. It is also the phone's DNS server ([`DNS_IP`]): names a
//! service claims resolve to a virtual IP (one per hostname pattern), everything else goes to a
//! server's DNS service through the tunnel if one is in use (e.g. AdGuard Home), otherwise (or if
//! it doesn't answer) to the real network's resolvers. TCP to `virtual IP:port` is terminated here by smoltcp and
//! streamed to the service with that hostname and port (on whichever server offers it); anything
//! else is refused.

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsRawFd, OwnedFd},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use iroh_proxy::{
    Client, Service,
    dns::{self, Names},
};
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
    sync::{
        Notify,
        mpsc::{self, error::TryRecvError, error::TrySendError},
    },
    time::sleep,
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

/// Which names resolve to which virtual IP, and which service (a `T`, e.g. the server's client,
/// plus the service name) each `virtual IP:port` reaches.
pub struct Table<T> {
    names: Names,
    ports: HashMap<SocketAddrV4, (T, String)>,
}

impl<T: Clone> Table<T> {
    /// From the TCP services' hostnames; UDP isn't routed in VPN mode. When services (e.g. on two
    /// servers) claim the same name and port, the first one listed wins.
    pub fn new(services: &[(T, Service)]) -> Self {
        let tcp = || services.iter().filter(|(_, s)| !s.udp);
        let mut patterns: Vec<String> = tcp().flat_map(|(_, s)| s.hostnames.iter().map(|h| h.trim_end_matches('.').to_ascii_lowercase())).collect();
        patterns.sort();
        patterns.dedup();
        let mut names = Names::default();
        for (i, p) in patterns.iter().enumerate() {
            names.insert(p, Ipv4Addr::from(u32::from(FIRST_VIP) + i as u32));
        }
        let mut ports = HashMap::new();
        for (target, svc) in tcp() {
            for h in &svc.hostnames {
                let vip = names.get(h).unwrap();
                ports.entry(SocketAddrV4::new(vip, svc.port)).or_insert_with(|| (target.clone(), svc.name.clone()));
            }
        }
        Self { names, ports }
    }

    #[cfg(test)]
    fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        self.names.resolve(name)
    }
}

/// Answers `query` from `client` (names locally, the rest via [`dns::forward`]) and queues the
/// reply, truncated if it wouldn't fit the TUN's MTU.
async fn answer_dns(
    query: Vec<u8>,
    client: SocketAddrV4,
    names: Arc<Names>,
    tunnel: Option<TunnelDns>,
    replies: mpsc::Sender<(SocketAddrV4, Vec<u8>)>,
) {
    let upstream = UPSTREAM.lock().unwrap().clone();
    let Some(reply) = dns::resolve(&query, &names, tunnel.as_ref(), &upstream, |w| crate::log(&w)).await else { return };
    let reply = if 20 + 8 + reply.len() > MTU { dns::truncated(&reply) } else { reply };
    _ = replies.send((client, reply)).await;
}

/// A server's DNS service, used for every name the VPN doesn't answer itself.
pub type TunnelDns = dns::Tunnel;

/// An IPv4/UDP packet from `src` to `dst`.
fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
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
pub async fn run(fd: OwnedFd, table: Table<Arc<Client>>, tunnel_dns: Option<TunnelDns>) -> Result<()> {
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
    let names = Arc::new(table.names.clone());

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
                    tokio::spawn(answer_dns(udp.payload().to_vec(), client_addr, names.clone(), tunnel_dns.clone(), dns_tx.clone()));
                    continue;
                }
                IpProtocol::Tcp => {
                    if let Ok(tcp) = TcpPacket::new_checked(ip.payload()) {
                        let key = (SocketAddrV4::new(src_ip, tcp.src_port()), SocketAddrV4::new(dst_ip, tcp.dst_port()));
                        if tcp.syn() && !tcp.ack() && !conns.contains_key(&key)
                            && let Some((client, service)) = table.ports.get(&key.1)
                            && let Some(conn) = accept(key.1, service, client, &notify, &mut sockets)
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

    fn svc(server: u8, name: &str, port: u16, hosts: &[&str]) -> (u8, Service) {
        (server, Service { name: name.into(), udp: false, port, hostnames: hosts.iter().map(|h| h.to_string()).collect(), dns: false })
    }

    #[test]
    fn resolves_exact_before_wildcard() {
        let t = Table::new(&[
            svc(1, "proxy", 443, &["*.example.com"]),
            svc(1, "proxy-http", 80, &["*.example.com"]),
            svc(2, "jf", 8096, &["JF.example.com."]),
            svc(2, "other-proxy", 443, &["*.example.com"]), // loses to server 1's
        ]);
        let wild = t.resolve("jelly.example.com").unwrap();
        assert_eq!(t.resolve("a.b.example.com."), Some(wild));
        assert_ne!(t.resolve("jf.example.com"), Some(wild));
        assert_eq!(t.resolve("example.com"), None);
        assert_eq!(t.resolve("badexample.com"), None);
        assert_eq!(t.ports[&SocketAddrV4::new(wild, 443)], (1, "proxy".into()));
        assert_eq!(t.ports[&SocketAddrV4::new(wild, 80)], (1, "proxy-http".into()));
        assert_eq!(t.ports[&SocketAddrV4::new(t.resolve("jf.example.com").unwrap(), 8096)], (2, "jf".into()));
        assert!(!t.ports.contains_key(&SocketAddrV4::new(wild, 22)));
    }
}
