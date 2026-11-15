# Android client

For people who just need the homelab services on their phone. The app runs the same Rust client
(`native/`, via JNI) and forwards every service the server offers to `127.0.0.1:<port>` on the phone.

## Use

1. Install the APK, open it, and send the **device ID** to the server's owner.
2. They add it to `allowed` in `server.toml` and restart the server.
3. Paste the **server ID** and tap Save. The server's services are listed automatically.
4. Change a local port or switch a service off if you like, then tap **Connect**. Point other apps
   at the address shown (e.g. `127.0.0.1:8096`). A notification stays up while connected.

A service's default port is the port it has on the server side. Ports that are taken, or below
1024 (not allowed on Android), fall back to a random free port.

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
