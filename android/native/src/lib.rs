//! JNI bindings for the Android app (`app.irohproxy.Native`).
//!
//! Lists cross the boundary as text lines: services as `tcp|udp <port> <name>` (the discovery
//! listing format), forwards as `tcp|udp <local addr or -> <name>`. Errors become Java exceptions.

mod vpn;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use iroh_proxy::{Client, PeerId, Service, load_or_create_key, parse_services, service_lines};
use jni::{
    JNIEnv,
    objects::{JClass, JObject, JString},
    sys::{jint, jstring},
};
use tokio::{runtime::Runtime, time::timeout};

/// Dialing a server that is offline can otherwise hang for a long time.
const TIMEOUT: Duration = Duration::from_secs(20);

/// One client endpoint per process: two endpoints with the same key would fight over the id.
struct Session {
    rt: Runtime,
    client: Arc<Client>,
    server: PeerId,
    /// What [`start`] was asked to forward; VPN mode routes these services' hostnames.
    services: Vec<Service>,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn close(session: &mut Option<Session>) {
    if let Some(s) = session.take() {
        s.rt.shutdown_background();
    }
}

fn open(key_path: &str, server: &str) -> Result<Session> {
    let server: PeerId = server.trim().parse().context("invalid server id")?;
    let key = load_or_create_key(key_path)?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let client = rt.block_on(Client::new(key, server, None))?;
    Ok(Session { rt, client, server, services: vec![] })
}

fn services(key_path: &str, server: &str) -> Result<String> {
    let mut session = SESSION.lock().unwrap();
    let wanted: PeerId = server.trim().parse().context("invalid server id")?;
    if session.as_ref().is_none_or(|s| s.server != wanted) {
        close(&mut session);
        *session = Some(open(key_path, server)?);
    }
    let s = session.as_ref().unwrap();
    let list = s.rt.block_on(async { timeout(TIMEOUT, s.client.services()).await }).context("server did not answer")??;
    Ok(list.iter().map(service_lines).collect())
}

/// Replaces any session with a fresh one forwarding each service in `spec` (port 0 or a taken
/// port falls back to a random one).
fn start(key_path: &str, server: &str, spec: &str) -> Result<String> {
    let mut session = SESSION.lock().unwrap();
    close(&mut session);
    let mut s = open(key_path, server)?;
    s.services = parse_services(spec);
    let out = s.rt.block_on(async {
        let mut out = String::new();
        for svc in &s.services {
            let local = match s.client.expose(svc, None).await {
                Ok(a) => a.to_string(),
                Err(_) => "-".into(),
            };
            out += &format!("{} {local} {}\n", proto(svc), svc.name);
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
    anyhow::ensure!(!table.is_empty(), "no service has hostnames");
    let client = s.client.clone();
    s.rt.spawn(async move {
        if let Err(e) = vpn::run(fd, table, client).await {
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
pub extern "system" fn Java_app_irohproxy_Native_start(
    mut env: JNIEnv,
    _: JClass,
    key_path: JString,
    server: JString,
    spec: JString,
) -> jstring {
    ret(&mut env, |env| start(&string(env, &key_path)?, &string(env, &server)?, &string(env, &spec)?))
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_irohproxy_Native_stop(_: JNIEnv, _: JClass) {
    close(&mut SESSION.lock().unwrap());
}
