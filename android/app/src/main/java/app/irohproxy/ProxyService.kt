package app.irohproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.concurrent.Executors

/** Keeps the process (and so the forwards) alive while the user is connected. */
class ProxyService : Service() {
    /** Observed by the UI. Only written on the main thread. */
    object State {
        var running by mutableStateOf(false)
        /** Service key ("tcp name") -> local address, or null if it could not be bound. */
        var forwards by mutableStateOf<Map<String, String?>>(emptyMap())
        var error by mutableStateOf<String?>(null)
    }

    private val main = Handler(Looper.getMainLooper())
    @Volatile private var stopped = false

    override fun onBind(intent: Intent?) = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val spec = intent?.getStringExtra(EXTRA_SPEC)
        if (intent?.action == ACTION_STOP || spec == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        Native.init(applicationContext)
        startForeground(notification("Connecting…"))
        State.error = null
        val prefs = Prefs(this)
        worker.execute {
            val result = runCatching { Native.start(prefs.keyPath, prefs.server, spec) }
            main.post {
                if (stopped) return@post
                result.onSuccess { out ->
                    State.forwards = out.lines().filter { it.isNotBlank() }.associate { l ->
                        val (proto, addr, name) = l.split(' ', limit = 3)
                        "$proto $name" to addr.takeIf { it != "-" }
                    }
                    State.running = true
                    val n = State.forwards.values.count { it != null }
                    getSystemService(NotificationManager::class.java)
                        .notify(NOTIFICATION, notification("Forwarding $n service${if (n == 1) "" else "s"}"))
                }.onFailure {
                    State.error = it.message
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopped = true
        State.running = false
        State.forwards = emptyMap()
        worker.execute { Native.stop() }
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

        /** Serializes start/stop so a quick Stop then Start can't run out of order. */
        private val worker = Executors.newSingleThreadExecutor()

        fun start(ctx: Context, spec: String) {
            ctx.startForegroundService(Intent(ctx, ProxyService::class.java).putExtra(EXTRA_SPEC, spec))
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, ProxyService::class.java))
        }
    }
}
