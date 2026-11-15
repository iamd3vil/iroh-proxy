//! JNI bindings for the Android app (`app.irohproxy.Native`).
//!
//! Lists cross the boundary as text lines: services as `tcp|udp <port> <name>` (the discovery
//! listing format), forwards as `tcp|udp <local addr or -> <name>`. Errors become Java exceptions.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use iroh_proxy::{Client, PeerId, Service, load_or_create_key, parse_services};
use jni::{
    JNIEnv,
    objects::{JClass, JObject, JString},
    sys::jstring,
};
use tokio::{runtime::Runtime, time::timeout};

/// Dialing a server that is offline can otherwise hang for a long time.
const TIMEOUT: Duration = Duration::from_secs(20);

/// One client endpoint per process: two endpoints with the same key would fight over the id.
struct Session {
    rt: Runtime,
    client: Arc<Client>,
    server: PeerId,
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
    Ok(Session { rt, client, server })
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
    Ok(list.iter().map(|s| format!("{} {} {}\n", proto(s), s.port, s.name)).collect())
}

/// Replaces any session with a fresh one forwarding each service in `spec` (port 0 or a taken
/// port falls back to a random one).
fn start(key_path: &str, server: &str, spec: &str) -> Result<String> {
    let mut session = SESSION.lock().unwrap();
    close(&mut session);
    let s = open(key_path, server)?;
    let out = s.rt.block_on(async {
        let mut out = String::new();
        for svc in parse_services(spec) {
            let local = match s.client.expose(&svc, None).await {
                Ok(a) => a.to_string(),
                Err(_) => "-".into(),
            };
            out += &format!("{} {local} {}\n", proto(&svc), svc.name);
        }
        out
    });
    *session = Some(s);
    Ok(out)
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

/// Sends panic messages to logcat; stderr goes nowhere on Android.
#[cfg(target_os = "android")]
fn log_panics() {
    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: i32, tag: *const std::ffi::c_char, text: *const std::ffi::c_char) -> i32;
    }
    std::panic::set_hook(Box::new(|info| {
        let msg = std::ffi::CString::new(info.to_string().replace('\0', "")).unwrap_or_default();
        unsafe { __android_log_write(6 /* ERROR */, c"iroh-proxy".as_ptr(), msg.as_ptr()) };
    }));
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
pub extern "system" fn Java_app_irohproxy_Native_stop(_: JNIEnv, _: JClass) {
    close(&mut SESSION.lock().unwrap());
}
