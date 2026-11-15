package app.irohproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/** Keeps the process (and so the forwards) alive while the user is connected, and runs the VPN
 *  that makes services reachable by hostname. */
class ProxyService : VpnService() {
    /** Observed by the UI. Only written on the main thread. */
    object State {
        var running by mutableStateOf(false)
        /** Between Connect and the forwards being up (or failing). */
        var connecting by mutableStateOf(false)
        /** [Svc.key] -> local address, or null if it could not be bound. */
        var forwards by mutableStateOf<Map<String, String?>>(emptyMap())
        var error by mutableStateOf<String?>(null)
        var vpn by mutableStateOf(false)
    }

    private val main = Handler(Looper.getMainLooper())
    @Volatile private var stopped = false
    private var dnsWatch: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        // No spec: Android started us (Always-on VPN, or after a reboot), so use the saved setup.
        val spec = intent?.getStringExtra(EXTRA_SPEC)
        stopped = false
        Native.init(applicationContext)
        startForeground(notification("Connecting…"))
        State.error = null
        State.connecting = true
        val prefs = Prefs(this)
        // Android expects a VPN when it started us itself.
        val vpn = spec == null || intent?.getBooleanExtra(EXTRA_VPN, false) == true
        worker.execute {
            val result = runCatching {
                Native.start(prefs.keyPath, spec ?: savedSpec(prefs)).also { if (vpn) startVpn() }
            }
            main.post {
                State.connecting = false
                if (stopped) return@post
                result.onSuccess { out ->
                    State.forwards = out.lines().filter { it.isNotBlank() }.associate { l ->
                        val (server, proto, addr, name) = l.split(' ', limit = 4)
                        "$server $proto $name" to addr.takeIf { it != "-" }
                    }
                    State.running = true
                    State.vpn = vpn
                    val n = State.forwards.values.count { it != null }
                    val text = "Forwarding $n service${if (n == 1) "" else "s"}${if (vpn) " · VPN on" else ""}"
                    getSystemService(NotificationManager::class.java).notify(NOTIFICATION, notification(text))
                }.onFailure {
                    State.error = it.message
                    shutdown()
                }
            }
        }
        return START_NOT_STICKY
    }

    /** The user turned the VPN off in system settings, or another VPN took over. */
    override fun onRevoke() = shutdown()

    override fun onDestroy() = shutdown()

    /** Closes everything. The system stays bound to a VPN service while its interface is open, so
     *  stopping it isn't enough: the interface must be closed (by Native.stop) first. */
    private fun shutdown() {
        if (stopped) return
        stopped = true
        State.running = false
        State.connecting = false
        State.vpn = false
        State.forwards = emptyMap()
        dnsWatch?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        dnsWatch = null
        worker.execute { Native.stop() } // closes the VPN interface too
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** What the user last chose, for starts without the app: every saved server's enabled services
     *  on their saved ports. Servers that can't be reached right now are skipped. Blocks. */
    private fun savedSpec(prefs: Prefs): String {
        val servers = prefs.servers
        check(servers.isNotEmpty()) { "No servers added yet" }
        val chosen = servers.flatMap { srv ->
            runCatching { Svc.parse(Native.services(prefs.keyPath, srv.id), srv.id) }.getOrDefault(emptyList())
        }.filter { prefs.enabled(it) }
        return Svc.spec(chosen) { prefs.port(it) ?: it.port }
    }

    /** Routes only the VPN range through us; we are the phone's DNS (see android/native/src/vpn.rs). */
    private fun startVpn() {
        // DNS servers of every real (non-VPN) network; the forwarder asks them all and takes the
        // first answer, so ones unreachable from the current route don't matter.
        val servers = ConcurrentHashMap<Network, List<String>>()
        fun push() = Native.setDns(servers.values.flatten().distinct().joinToString("\n"))
        val watch = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                servers[network] = lp.dnsServers.mapNotNull { it.hostAddress }
                push()
            }

            override fun onLost(network: Network) {
                servers.remove(network)
                push()
            }
        }
        val realNetworks = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        getSystemService(ConnectivityManager::class.java).registerNetworkCallback(realNetworks, watch)
        dnsWatch = watch
        val tun = Builder()
            .setSession("iroh proxy")
            .addAddress("198.18.0.1", 16)
            .addRoute("198.18.0.0", 16)
            .addDnsServer("198.18.0.2")
            .setMtu(1500)
            .addDisallowedApplication(packageName) // iroh and forwarded DNS use the real network
            .establish() ?: error("VPN permission was revoked")
        Native.startVpn(tun.detachFd())
    }

    private fun startForeground(n: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION, n)
        }
    }

    private fun notification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Connection", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ProxyService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("iroh proxy")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
    }

    companion object {
        private const val CHANNEL = "connection"
        private const val NOTIFICATION = 1
        private const val ACTION_STOP = "stop"
        private const val EXTRA_SPEC = "spec"
        private const val EXTRA_VPN = "vpn"

        /** Serializes start/stop so a quick Stop then Start can't run out of order. */
        private val worker = Executors.newSingleThreadExecutor()

        /** [spec] as for [Native.start]; [vpn] if any of its services has hostnames. */
        fun start(ctx: Context, spec: String, vpn: Boolean) {
            ctx.startForegroundService(
                Intent(ctx, ProxyService::class.java).putExtra(EXTRA_SPEC, spec).putExtra(EXTRA_VPN, vpn),
            )
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, ProxyService::class.java).setAction(ACTION_STOP))
        }
    }
}
