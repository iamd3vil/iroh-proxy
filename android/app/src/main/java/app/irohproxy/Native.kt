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

    /** The server's services, in the listing format (see [Svc.parse]). */
    external fun services(keyPath: String, server: String): String

    /** Forwards each service in [spec] (listing format), replacing earlier forwards. Returns
     *  `tcp|udp <local addr or -> <name>` lines. */
    external fun start(keyPath: String, server: String, spec: String): String

    /** Serves the VPN interface [fd] (taking ownership), routing the started services' hostnames. */
    external fun startVpn(fd: Int): String

    /** The real network's DNS servers, one IP per line, for names the VPN doesn't answer. */
    external fun setDns(servers: String)

    external fun stop()
}

/** A service offered by the server; [port] is its suggested local port. [hostnames] are reached
 *  through the VPN. */
data class Svc(val udp: Boolean, val port: Int, val name: String, val hostnames: List<String> = emptyList()) {
    val key get() = "${if (udp) "udp" else "tcp"} $name"
    val needsVpn get() = !udp && hostnames.isNotEmpty()

    /** This service in the listing format, forwarded on local [port]. */
    fun lines(port: Int) = buildString {
        append("${if (udp) "udp" else "tcp"} $port $name\n")
        hostnames.forEach { append("host $it $name\n") }
    }

    companion object {
        /** Parses `tcp|udp <port> <name>` and `host <pattern> <name>` lines. */
        fun parse(text: String): List<Svc> {
            val svcs = mutableListOf<Svc>()
            val hosts = mutableListOf<Pair<String, String>>()
            for (l in text.lines()) {
                val p = l.split(' ', limit = 3)
                if (p.size != 3) continue
                when (p[0]) {
                    "tcp", "udp" -> p[1].toIntOrNull()?.let { svcs += Svc(p[0] == "udp", it, p[2]) }
                    "host" -> hosts += p[1] to p[2]
                }
            }
            return svcs.map { s -> s.copy(hostnames = hosts.filter { it.second == s.name }.map { it.first }) }
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
