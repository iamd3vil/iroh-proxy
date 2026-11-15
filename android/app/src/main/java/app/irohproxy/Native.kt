package app.irohproxy

import android.content.Context

/** The Rust client (android/native). Calls block on network I/O: never call from the main thread. */
object Native {
    init {
        System.loadLibrary("iroh_proxy_android")
    }

    /** Must run before the others; idempotent. */
    external fun init(context: Context)

    /** This device's id, creating its key at [keyPath] if needed. */
    external fun clientId(keyPath: String): String

    /** The server's services as `tcp|udp <port> <name>` lines. */
    external fun services(keyPath: String, server: String): String

    /** Forwards each `tcp|udp <port> <name>` line of [spec], replacing earlier forwards. Returns
     *  `tcp|udp <local addr or -> <name>` lines. */
    external fun start(keyPath: String, server: String, spec: String): String

    external fun stop()
}

/** A service offered by the server; [port] is its suggested local port. */
data class Svc(val udp: Boolean, val port: Int, val name: String) {
    val key get() = "${if (udp) "udp" else "tcp"} $name"
    fun line(port: Int) = "${if (udp) "udp" else "tcp"} $port $name"

    companion object {
        fun parse(lines: String) = lines.lines().mapNotNull { l ->
            val parts = l.split(' ', limit = 3)
            if (parts.size != 3) return@mapNotNull null
            Svc(parts[0] == "udp", parts[1].toIntOrNull() ?: return@mapNotNull null, parts[2])
        }
    }
}

class Prefs(ctx: Context) {
    private val p = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val keyPath: String = ctx.filesDir.resolve("client.key").path

    var server: String
        get() = p.getString("server", "")!!
        set(v) = p.edit().putString("server", v.trim()).apply()

    /** The user's local port override for a service, if any. */
    fun port(svc: Svc): Int? = if (p.contains("port:${svc.key}")) p.getInt("port:${svc.key}", 0) else null
    fun setPort(svc: Svc, port: Int?) = p.edit().apply {
        if (port == null || port == svc.port) remove("port:${svc.key}") else putInt("port:${svc.key}", port)
    }.apply()

    fun enabled(svc: Svc) = p.getBoolean("on:${svc.key}", true)
    fun setEnabled(svc: Svc, on: Boolean) = p.edit().putBoolean("on:${svc.key}", on).apply()
}
