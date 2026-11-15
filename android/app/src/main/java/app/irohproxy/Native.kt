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

    /** Forwards each service in [spec] (see [spec]), replacing earlier forwards. Returns
     *  `<server> tcp|udp <local addr or -> <name>` lines. */
    external fun start(keyPath: String, spec: String): String

    /** Serves the VPN interface [fd] (taking ownership), routing the started services' hostnames. */
    external fun startVpn(fd: Int): String

    /** The real network's DNS servers, one IP per line, for names the VPN doesn't answer. */
    external fun setDns(servers: String)

    external fun stop()
}

/** A server the user added; [name] is their own label for it. */
data class Server(val id: String, val name: String) {
    val label get() = name.ifBlank { id.take(12) + "…" }
}

/** A service offered by [server]; [port] is its suggested local port. [hostnames] are reached
 *  through the VPN. */
data class Svc(
    val server: String,
    val udp: Boolean,
    val port: Int,
    val name: String,
    val hostnames: List<String> = emptyList(),
) {
    /** Unique across servers; also how [Native.start] reports this service's forward. */
    val key get() = "$server ${if (udp) "udp" else "tcp"} $name"
    val needsVpn get() = !udp && hostnames.isNotEmpty()

    /** This service in the listing format, forwarded on local [port]. */
    fun lines(port: Int) = buildString {
        append("${if (udp) "udp" else "tcp"} $port $name\n")
        hostnames.forEach { append("host $it $name\n") }
    }

    companion object {
        /** What [Native.start] takes: each server's chosen services, on the given local ports. */
        fun spec(chosen: List<Svc>, port: (Svc) -> Int) = chosen.groupBy { it.server }.entries.joinToString("") {
            (server, svcs) -> "server $server\n" + svcs.joinToString("") { it.lines(port(it)) }
        }

        /** Parses [server]'s listing: `tcp|udp <port> <name>` and `host <pattern> <name>` lines. */
        fun parse(text: String, server: String): List<Svc> {
            val svcs = mutableListOf<Svc>()
            val hosts = mutableListOf<Pair<String, String>>()
            for (l in text.lines()) {
                val p = l.split(' ', limit = 3)
                if (p.size != 3) continue
                when (p[0]) {
                    "tcp", "udp" -> p[1].toIntOrNull()?.let { svcs += Svc(server, p[0] == "udp", it, p[2]) }
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

    /** One `id<TAB>name` line per server; older versions stored a single "server". */
    var servers: List<Server>
        get() = p.getString("servers", null)
            ?.lines()?.filter { it.isNotBlank() }?.map { Server(it.substringBefore('\t'), it.substringAfter('\t', "")) }
            ?: listOfNotNull(p.getString("server", null)?.takeIf { it.isNotBlank() }?.let { Server(it, "") })
        set(v) = p.edit().putString("servers", v.joinToString("\n") { "${it.id}\t${it.name}" }).remove("server").apply()

    /** The user's local port override for a service, if any. */
    fun port(svc: Svc): Int? = if (p.contains("port:${svc.key}")) p.getInt("port:${svc.key}", 0) else null
    fun setPort(svc: Svc, port: Int?) = p.edit().apply {
        if (port == null || port == svc.port) remove("port:${svc.key}") else putInt("port:${svc.key}", port)
    }.apply()

    fun enabled(svc: Svc) = p.getBoolean("on:${svc.key}", true)
    fun setEnabled(svc: Svc, on: Boolean) = p.edit().putBoolean("on:${svc.key}", on).apply()
}
