//! JNI bindings for the Android app (`app.irohproxy.Native`).
//!
//! Lists cross the boundary as text lines: a server's services in the discovery listing format;
//! what to forward as that format in `server <id>` sections; forwards as
//! `<server> tcp|udp <local addr or -> <name>`. Errors become Java exceptions.

mod vpn;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use iroh_proxy::{Client, Endpoint, InviteRejected, PeerId, Service, bind, load_or_create_key, parse_invite, parse_services};
use jni::{
    JNIEnv,
    objects::{JClass, JObject, JString},
    sys::{jint, jstring},
};
use tokio::{runtime::Runtime, time::timeout};

/// Dialing a server that is offline can otherwise hang for a long time.
const TIMEOUT: Duration = Duration::from_secs(20);

/// One endpoint per process (two with the same key would fight over the id), with a client per
/// server on it: every server sees the same device id.
struct Session {
    rt: Runtime,
    ep: Endpoint,
    clients: HashMap<PeerId, Arc<Client>>,
    /// What [`start`] was asked to forward; VPN mode routes these services' hostnames.
    services: Vec<(Arc<Client>, Service)>,
}

impl Session {
    fn open(key_path: &str) -> Result<Self> {
        let key = load_or_create_key(key_path)?;
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let ep = rt.block_on(bind(key, None))?;
        Ok(Self { rt, ep, clients: HashMap::new(), services: vec![] })
    }

    fn client(&mut self, server: &str) -> Result<Arc<Client>> {
        let id: PeerId = server.trim().parse().with_context(|| format!("invalid server id {server:?}"))?;
        Ok(self.clients.entry(id).or_insert_with(|| Client::with_endpoint(self.ep.clone(), id)).clone())
    }
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn close(session: &mut Option<Session>) {
    if let Some(s) = session.take() {
        s.rt.shutdown_background();
    }
}

fn services(key_path: &str, server: &str) -> Result<String> {
    let (rt, client) = {
        let mut session = SESSION.lock().unwrap();
        if session.is_none() {
            *session = Some(Session::open(key_path)?);
        }
        let s = session.as_mut().unwrap();
        (s.rt.handle().clone(), s.client(server)?)
    }; // unlocked, so one slow server doesn't hold up the others
    rt.block_on(async { timeout(TIMEOUT, client.listing()).await }).context("server did not answer")?
}

/// Redeems the invite code in `text`; returns the server's id.
fn redeem(key_path: &str, text: &str) -> Result<String> {
    let (server, token) = parse_invite(text).context("no invite code found")?;
    let (rt, client) = {
        let mut session = SESSION.lock().unwrap();
        if session.is_none() {
            *session = Some(Session::open(key_path)?);
        }
        let s = session.as_mut().unwrap();
        (s.rt.handle().clone(), s.client(&server.to_string())?)
    };
    rt.block_on(async {
        // A server that just started may not be findable yet; a refused invite is final.
        let mut tries = 0;
        loop {
            match timeout(TIMEOUT, client.redeem(&token)).await {
                Ok(Ok(())) => return Ok(server.to_string()),
                Ok(Err(e)) if e.downcast_ref::<InviteRejected>().is_some() => return Err(e),
                res => {
                    tries += 1;
                    if tries == 3 {
                        return Err(res.map_or_else(|_| anyhow::anyhow!("the server didn't answer"), |r| r.unwrap_err()));
                    }
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    })
}

/// Replaces any session with a fresh one forwarding each service in `spec` (port 0 or a taken
/// port falls back to a random one).
fn start(key_path: &str, spec: &str) -> Result<String> {
    let mut session = SESSION.lock().unwrap();
    close(&mut session);
    let mut s = Session::open(key_path)?;
    let mut sections: Vec<(&str, String)> = Vec::new();
    for line in spec.lines() {
        match line.strip_prefix("server ") {
            Some(server) => sections.push((server, String::new())),
            None => {
                let (_, body) = sections.last_mut().context("spec must start with a server line")?;
                *body += line;
                body.push('\n');
            }
        }
    }
    for (server, body) in sections {
        let client = s.client(server)?;
        s.services.extend(parse_services(&body).into_iter().map(|svc| (client.clone(), svc)));
    }
    let out = s.rt.block_on(async {
        let mut out = String::new();
        for (client, svc) in &s.services {
            if svc.dns {
                continue; // used by the VPN's DNS, not through a local port
            }
            let local = match client.expose(svc, None).await {
                Ok(a) => a.to_string(),
                Err(_) => "-".into(),
            };
            out += &format!("{} {} {local} {}\n", client.server(), proto(svc), svc.name);
        }
        out
    });
    *session = Some(s);
    Ok(out)
}

/// Serves the VPN's TUN `fd` (taking ownership) for the session [`start`] opened.
fn start_vpn(fd: i32) -> Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let session = SESSION.lock().unwrap();
    let s = session.as_ref().context("not connected")?;
    let table = vpn::Table::new(&s.services);
    // The first server (in the user's order) offering DNS handles it.
    let dns = s.services.iter().find(|(_, svc)| svc.dns).map(|(c, svc)| (c.clone(), svc.name.clone()));
    // With neither hostnames nor DNS (e.g. Always-on VPN), it still forwards DNS to the network.
    if let Some((client, _)) = &dns {
        let client = client.clone();
        s.rt.spawn(async move { _ = client.services().await }); // connect now, not on the first lookup
    }
    s.rt.spawn(async move {
        if let Err(e) = vpn::run(fd, table, dns).await {
            log(&format!("vpn: {e:#}"));
        }
    });
    Ok(())
}

/// Errors that would otherwise go unseen; stderr goes nowhere on Android.
pub(crate) fn log(msg: &str) {
    write_log(6 /* ERROR */, msg);
}

pub(crate) fn info(msg: &str) {
    write_log(4 /* INFO */, msg);
}

fn write_log(prio: i32, msg: &str) {
    #[cfg(target_os = "android")]
    {
        #[link(name = "log")]
        unsafe extern "C" {
            fn __android_log_write(prio: i32, tag: *const std::ffi::c_char, text: *const std::ffi::c_char) -> i32;
        }
        let msg = std::ffi::CString::new(msg.replace('\0', "")).unwrap_or_default();
        unsafe { __android_log_write(prio, c"iroh-proxy".as_ptr(), msg.as_ptr()) };
    }
    #[cfg(not(target_os = "android"))]
    {
        _ = prio;
        eprintln!("{msg}");
    }
}

fn proto(s: &Service) -> &'static str {
    if s.udp { "udp" } else { "tcp" }
}

fn string(env: &mut JNIEnv, s: &JString) -> Result<String> {
    Ok(env.get_string(s)?.into())
}

/// Returns `f`'s string to Java, or throws its error (or panic) as a `java.lang.Exception`.
fn ret(env: &mut JNIEnv, f: impl FnOnce(&mut JNIEnv) -> Result<String>) -> jstring {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(env)))
        .unwrap_or_else(|_| Err(anyhow::anyhow!("internal error (see logcat)")));
    match res.and_then(|s| Ok(env.new_string(s)?)) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            _ = env.throw_new("java/lang/Exception", format!("{e:#}"));
            std::ptr::null_mut()
        }
    }
}

/// Lets iroh read the system DNS servers through the application context. Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_init(env: JNIEnv, _: JClass, context: JObject) {
    #[cfg(target_os = "android")]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            log_panics();
            let (Ok(vm), Ok(ctx)) = (env.get_java_vm(), env.new_global_ref(context)) else { return };
            let ctx_ptr = ctx.as_obj().as_raw();
            std::mem::forget(ctx); // must stay valid for the process lifetime
            unsafe { iroh::dns::install_android_jni_context(vm.get_java_vm_pointer().cast(), ctx_ptr.cast()) };
        });
    }
    #[cfg(not(target_os = "android"))]
    {
        _ = (env, context);
    }
}

#[cfg(target_os = "android")]
fn log_panics() {
    std::panic::set_hook(Box::new(|info| log(&info.to_string())));
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_clientId(mut env: JNIEnv, _: JClass, key_path: JString) -> jstring {
    ret(&mut env, |env| Ok(load_or_create_key(string(env, &key_path)?)?.public().to_string()))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_services(mut env: JNIEnv, _: JClass, key_path: JString, server: JString) -> jstring {
    ret(&mut env, |env| services(&string(env, &key_path)?, &string(env, &server)?))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_start(mut env: JNIEnv, _: JClass, key_path: JString, spec: JString) -> jstring {
    ret(&mut env, |env| start(&string(env, &key_path)?, &string(env, &spec)?))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_startVpn(mut env: JNIEnv, _: JClass, fd: jint) -> jstring {
    ret(&mut env, |_| start_vpn(fd).map(|()| String::new()))
}

/// The real network's DNS servers (one IP per line), for names the VPN doesn't answer itself.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_setDns(mut env: JNIEnv, _: JClass, servers: JString) {
    if let Ok(s) = string(&mut env, &servers) {
        vpn::set_upstream(s.lines().filter_map(|l| l.trim().parse().ok()).map(|ip| std::net::SocketAddr::new(ip, 53)).collect());
    }
}

/// Redeems the invite code found in `text`; returns the server's id.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_redeem(mut env: JNIEnv, _: JClass, key_path: JString, text: JString) -> jstring {
    ret(&mut env, |env| redeem(&string(env, &key_path)?, &string(env, &text)?))
}

/// Each connected server's path: `<server> direct|relay <ip:port or relay host> <rtt ms>` lines.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_paths(mut env: JNIEnv, _: JClass) -> jstring {
    ret(&mut env, |_| {
        let session = SESSION.lock().unwrap();
        let Some(s) = session.as_ref() else { return Ok(String::new()) };
        Ok(s.clients
            .iter()
            .filter_map(|(id, c)| c.path().map(|p| (id, p)))
            .map(|(id, p)| format!("{id} {} {} {}\n", if p.relay { "relay" } else { "direct" }, p.addr, p.rtt.as_millis()))
            .collect())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_stop(_: JNIEnv, _: JClass) {
    close(&mut SESSION.lock().unwrap());
}
