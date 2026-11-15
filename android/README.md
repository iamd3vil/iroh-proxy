# Android client

For people who just need the homelab services on their phone. The app runs the same Rust client
(`native/`, via JNI) and forwards every service the server offers to `127.0.0.1:<port>` on the phone.

## Use

1. Install the APK, open it, and tap **Share device code** to send it to each server's owner (the
   code is the same for every server).
2. They add it to `allowed` in `server.toml`, restart the server, and send back the **server code**
   (the server's id, printed when it starts).
3. Tap **Add server code** and paste it; pasting their whole message works. Repeat for more
   servers. Each server's services are listed automatically.
4. Tap the power button to connect to every server at once. Each service shows how to reach it,
   with **Open** (in the browser) or **Copy**. A notification stays up while connected.

Tapping a service (while disconnected) shows its settings: turn it off, or pick the port it uses
on the phone.

A service's default port is the port it has on the server side. Ports that are taken, or below
1024 (not allowed on Android), fall back to a random free port.

## Reaching services by name (VPN mode)

For services behind a reverse proxy that routes by hostname (`https://jelly.example.com`), give
the service hostnames in `server.toml`:

```toml
[services]
proxy = "192.168.1.10:443"

[hostnames]
proxy = ["*.example.com"]   # exact names, or *.suffix for any subdomain
```

Connect then asks for VPN permission. The VPN carries only `198.18.0.0/16`, and the app becomes
the phone's DNS server: names matching a pattern resolve to a virtual IP that reaches the service
on its port (443 here), so `https://jelly.example.com` works unchanged, certificate included.
Hostnames from all servers share one VPN; if two servers claim the same name and port, the one
added first wins. Other names are forwarded to the network's own DNS servers, and all other traffic bypasses the
VPN. Only TCP is carried this way.

Limits: Android allows one VPN at a time, and a Private DNS setting with a specific hostname
(Settings → Network → Private DNS) bypasses the app's DNS, so names won't resolve; "Automatic"
works.

## Using the server's DNS (e.g. AdGuard Home)

A server can offer a TCP DNS service as the phone's DNS, like Tailscale's DNS setting. Running
`iroh-proxy serve` on the AdGuard machine:

```toml
dns = "adguard"             # top level, before any [table]

[services]
adguard = "127.0.0.1:53"    # AdGuard answers DNS over TCP on 53 by default
```

While connected, every lookup the app doesn't answer itself goes through the tunnel to that
service (one stream per query, so large answers aren't an issue). If it doesn't answer within 4
seconds, or the server is unreachable, the lookup falls back to the network's DNS so the phone
keeps working (unfiltered) while the server is down. With several servers offering DNS, the first
one in the app's list is used; the service's settings can turn it off.

AdGuard sees every phone as one client (the server's address), so per-client rules and stats
can't tell them apart.

## Build

Needs the Android SDK with NDK 28.2.13676358, JDK 17 (Android Studio's bundled one works), and the
Rust targets:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cd android
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk
```

Gradle runs `build-native.sh` first, which cross-compiles `native/` into `app/src/main/jniLibs/`.

### Release build

`./gradlew assembleRelease` gives a shrunk APK at `app/build/outputs/apk/release/app-release.apk`,
signed with the key named in `keystore.properties` (gitignored; without it the APK is unsigned):

```properties
storeFile=/path/to/release.jks
storePassword=...
keyAlias=iroh-proxy
keyPassword=...
```

Back up the keystore and its password: updates must be signed with the same key, otherwise users
have to uninstall first, which also deletes their device key (and so changes their device ID).
