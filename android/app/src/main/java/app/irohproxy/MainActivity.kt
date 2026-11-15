package app.irohproxy

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        Native.init(applicationContext)
        setContent {
            val dark = isSystemInDarkTheme()
            val colors = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    if (dark) dynamicDarkColorScheme(this) else dynamicLightColorScheme(this)
                dark -> darkColorScheme()
                else -> lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) {
                Surface(Modifier.fillMaxSize()) { App() }
            }
        }
    }
}

/** A server code (an iroh endpoint id) anywhere in [text], e.g. a pasted message. */
private val SERVER_CODE = Regex("[0-9a-fA-F]{64}")

@Composable
fun App() {
    val ctx = LocalContext.current
    val prefs = remember { Prefs(ctx) }
    val scope = rememberCoroutineScope()
    var clientId by remember { mutableStateOf("") }
    var servers by remember { mutableStateOf(prefs.servers) }
    val services = remember { mutableStateMapOf<String, List<Svc>>() } // by server id
    val loading = remember { mutableStateMapOf<String, Boolean>() }
    val errors = remember { mutableStateMapOf<String, String>() }
    val ports = remember { mutableStateMapOf<String, String>() } // port text field per Svc.key
    val enabled = remember { mutableStateMapOf<String, Boolean>() }
    var error by remember { mutableStateOf<String?>(null) }
    var adding by remember { mutableStateOf(false) }
    var explainVpn by remember { mutableStateOf<Intent?>(null) } // Android's consent screen, after ours
    val state = ProxyService.State
    var pending by remember { mutableStateOf<String?>(null) } // spec waiting for VPN consent
    val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val spec = pending
        pending = null
        if (r.resultCode == android.app.Activity.RESULT_OK && spec != null) ProxyService.start(ctx, spec, vpn = true)
        else error = "Some services need the VPN permission to work by name. Tap the button again to allow it."
    }

    fun refresh(server: String) {
        loading[server] = true
        errors.remove(server)
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching { Native.services(prefs.keyPath, server) } }
            loading.remove(server)
            r.onSuccess { out ->
                val list = Svc.parse(out, server)
                services[server] = list
                for (s in list) {
                    ports.getOrPut(s.key) { (prefs.port(s) ?: s.port).toString() }
                    enabled.getOrPut(s.key) { prefs.enabled(s) }
                }
            }.onFailure {
                services.remove(server)
                errors[server] = it.message ?: it.toString()
            }
        }
    }

    fun saveServers(list: List<Server>) {
        servers = list
        prefs.servers = list
    }

    val all = servers.flatMap { services[it.id].orEmpty() }
    val chosen = all.filter { enabled[it.key] ?: true }

    fun connect() {
        error = null
        val spec = Svc.spec(chosen) { s ->
            val port = ports[s.key]?.toIntOrNull()?.takeIf { it in 0..65535 } ?: s.port
            prefs.setPort(s, port)
            port
        }
        val vpn = chosen.any { it.needsVpn }
        val consent = if (vpn) VpnService.prepare(ctx) else null
        if (consent != null) {
            pending = spec
            explainVpn = consent
        } else {
            ProxyService.start(ctx, spec, vpn)
        }
    }

    LaunchedEffect(Unit) {
        clientId = withContext(Dispatchers.IO) { Native.clientId(prefs.keyPath) }
        servers.forEach { refresh(it.id) }
    }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Text("iroh proxy", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)

        if (servers.isEmpty()) {
            Welcome(clientId, onAdd = { adding = true })
        } else {
            Status(
                running = state.running,
                connecting = state.connecting,
                canConnect = chosen.isNotEmpty(),
                loading = loading.isNotEmpty(),
                summary = "${chosen.size} service${if (chosen.size == 1) "" else "s"} from " +
                    "${servers.size} server${if (servers.size == 1) "" else "s"}",
                error = state.error ?: error,
                onToggle = { if (state.running) ProxyService.stop(ctx) else connect() },
            )
            for (srv in servers) {
                ServerServices(
                    server = srv,
                    services = services[srv.id],
                    loading = loading[srv.id] == true,
                    error = errors[srv.id],
                    running = state.running,
                    ports = ports,
                    enabled = enabled,
                    forwards = state.forwards,
                    onEnabled = { s, on -> enabled[s.key] = on; prefs.setEnabled(s, on) },
                    onRetry = { refresh(srv.id) },
                )
            }
            Manage(
                servers = servers,
                clientId = clientId,
                running = state.running,
                onAdd = { adding = true },
                onRemove = { srv ->
                    saveServers(servers - srv)
                    services.remove(srv.id)
                    errors.remove(srv.id)
                },
            )
        }
    }

    explainVpn?.let { consent ->
        AlertDialog(
            onDismissRequest = { explainVpn = null; pending = null },
            title = { Text("One more step") },
            text = {
                Text(
                    "To open services by their usual web address, this app sets up a VPN on your phone. " +
                        "It only carries traffic for your servers. Everything else goes through your normal " +
                        "connection, untouched.\n\nAndroid will ask you to confirm.",
                )
            },
            confirmButton = {
                Button(onClick = { explainVpn = null; vpnConsent.launch(consent) }) { Text("Continue") }
            },
            dismissButton = { TextButton(onClick = { explainVpn = null; pending = null }) { Text("Not now") } },
        )
    }

    if (adding) {
        AddServer(
            existing = servers.map { it.id }.toSet(),
            onDismiss = { adding = false },
            onAdd = { srv ->
                adding = false
                saveServers(servers + srv)
                refresh(srv.id)
            },
        )
    }
}

/** First run: what to do, in order. */
@Composable
private fun Welcome(clientId: String, onAdd: () -> Unit) {
    val ctx = LocalContext.current
    Text(
        "Reach the services someone shares with you, from anywhere.",
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Step(1, "Send your device code", "The person who runs the server needs it to let this phone in.") {
        Button(onClick = { shareDeviceCode(ctx, clientId) }, enabled = clientId.isNotEmpty()) { Text("Share device code") }
    }
    Step(2, "Add their server", "Once they've added you, they'll send you a server code.") {
        Button(onClick = onAdd) { Text("Add server code") }
    }
}

@Composable
private fun Step(n: Int, title: String, body: String, action: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(20.dp), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp)) {
                Box(contentAlignment = Alignment.Center) {
                    Text("$n", color = MaterialTheme.colorScheme.onPrimary, fontWeight = FontWeight.Bold)
                }
            }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                action()
            }
        }
    }
}

/** The big on/off button and what it means right now. */
@Composable
private fun Status(
    running: Boolean,
    connecting: Boolean,
    canConnect: Boolean,
    loading: Boolean,
    summary: String,
    error: String?,
    onToggle: () -> Unit,
) {
    val on = running || connecting
    val ring by animateColorAsState(if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.primaryContainer)
    val glyph = if (running) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onPrimaryContainer
    val clickable = !connecting && (running || canConnect)
    Card(Modifier.fillMaxWidth()) {
        Column(
            Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Surface(
                shape = CircleShape,
                color = ring,
                modifier = Modifier.size(112.dp).clickable(enabled = clickable, onClick = onToggle),
                shadowElevation = if (running) 6.dp else 0.dp,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    if (connecting) {
                        CircularProgressIndicator(Modifier.size(48.dp))
                    } else {
                        Icon(
                            painterResource(R.drawable.ic_power),
                            contentDescription = if (on) "Disconnect" else "Connect",
                            tint = if (clickable) glyph else glyph.copy(alpha = 0.4f),
                            modifier = Modifier.size(48.dp),
                        )
                    }
                }
            }
            Text(
                when {
                    connecting -> "Connecting…"
                    running -> "Connected"
                    else -> "Not connected"
                },
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                when {
                    running -> summary
                    loading && !canConnect -> "Looking for services…"
                    canConnect -> "Tap to connect"
                    else -> "No services to connect to yet"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            error?.let { Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center) }
        }
    }
}

/** One server's services, or why they aren't shown. */
@Composable
private fun ServerServices(
    server: Server,
    services: List<Svc>?,
    loading: Boolean,
    error: String?,
    running: Boolean,
    ports: MutableMap<String, String>,
    enabled: Map<String, Boolean>,
    forwards: Map<String, String?>,
    onEnabled: (Svc, Boolean) -> Unit,
    onRetry: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                server.label,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.weight(1f),
            )
            if (loading) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
        }
        if (error != null) {
            Problem(
                "Can't reach this server right now. It may be offline, or it hasn't let this phone in yet.",
                details = error,
                onRetry = onRetry,
            )
        }
        if (services != null && services.isEmpty()) {
            Text("This server isn't sharing anything yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (!services.isNullOrEmpty()) {
            Card(Modifier.fillMaxWidth()) {
                services.forEachIndexed { i, s ->
                    if (i > 0) HorizontalDivider(Modifier.padding(horizontal = 16.dp))
                    ServiceRow(
                        svc = s,
                        port = ports[s.key] ?: "",
                        onPort = { ports[s.key] = it.filter(Char::isDigit).take(5) },
                        enabled = enabled[s.key] ?: true,
                        onEnabled = { onEnabled(s, it) },
                        running = running,
                        forward = forwards[s.key],
                    )
                }
            }
        }
    }
}

/** A service: how to use it when connected; tap for its settings when not. */
@Composable
private fun ServiceRow(
    svc: Svc,
    port: String,
    onPort: (String) -> Unit,
    enabled: Boolean,
    onEnabled: (Boolean) -> Unit,
    running: Boolean,
    forward: String?,
) {
    val ctx = LocalContext.current
    var open by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxWidth()
            .clickable(enabled = !running) { open = !open }
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    svc.name.replaceFirstChar { it.uppercase() },
                    style = MaterialTheme.typography.titleMedium,
                    color = if (enabled) Color.Unspecified else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    usage(svc, enabled, running, forward),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (running && enabled) {
                val link = link(svc, forward)
                if (link != null) FilledTonalButton(onClick = { openLink(ctx, link) }) { Text("Open") }
                if (link == null && forward != null && !svc.needsVpn) TextButton(onClick = { copy(ctx, forward) }) { Text("Copy") }
            } else if (!running) {
                val turn by animateFloatAsState(if (open) 180f else 0f)
                Icon(
                    painterResource(R.drawable.ic_expand),
                    contentDescription = if (open) "Hide settings" else "Settings",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.rotate(turn),
                )
            }
        }
        AnimatedVisibility(open && !running) {
            Column(Modifier.padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Use this service", Modifier.weight(1f))
                    Switch(checked = enabled, onCheckedChange = onEnabled)
                }
                if (!svc.needsVpn) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Port on this phone")
                            Text(
                                "Only change this if another app needs a specific port.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        OutlinedTextField(
                            value = port,
                            onValueChange = onPort,
                            singleLine = true,
                            enabled = enabled,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.width(104.dp),
                        )
                    }
                }
                Text(
                    "${if (svc.udp) "UDP" else "TCP"} · port ${svc.port} on the server",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** One line on how to reach [svc]. */
private fun usage(svc: Svc, enabled: Boolean, running: Boolean, forward: String?): String = when {
    !enabled -> "Turned off"
    svc.needsVpn -> svc.hostnames.joinToString(", ") { it.replace("*.", "any address ending in .") }
    !running -> "Ready"
    forward == null -> "Couldn't start on this phone"
    else -> forward
}

/** A browser link for [svc], when there is one to open. */
private fun link(svc: Svc, forward: String?): String? = when {
    svc.udp -> null
    svc.needsVpn -> svc.hostnames.firstOrNull { !it.startsWith("*.") }?.let { host ->
        when (svc.port) {
            443 -> "https://$host"
            80 -> "http://$host"
            else -> "http://$host:${svc.port}"
        }
    }
    forward != null -> "http://$forward"
    else -> null
}

@Composable
private fun Problem(message: String, details: String, onRetry: () -> Unit) {
    var show by remember { mutableStateOf(false) }
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(message, color = MaterialTheme.colorScheme.onErrorContainer)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onRetry) { Text("Try again") }
                TextButton(onClick = { show = !show }) { Text(if (show) "Hide details" else "Details") }
            }
            if (show) Text(details, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onErrorContainer)
        }
    }
}

/** Servers and this device's code, below the everyday stuff. */
@Composable
private fun Manage(servers: List<Server>, clientId: String, running: Boolean, onAdd: () -> Unit, onRemove: (Server) -> Unit) {
    val ctx = LocalContext.current
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Servers", style = MaterialTheme.typography.titleMedium)
        Card(Modifier.fillMaxWidth()) {
            servers.forEachIndexed { i, srv ->
                if (i > 0) HorizontalDivider(Modifier.padding(horizontal = 16.dp))
                Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(srv.label)
                        Text(
                            srv.id,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    TextButton(onClick = { onRemove(srv) }, enabled = !running) { Text("Remove") }
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onAdd, enabled = !running) { Text("Add server") }
            OutlinedButton(onClick = { shareDeviceCode(ctx, clientId) }, enabled = clientId.isNotEmpty()) { Text("Share device code") }
        }
        if (running) {
            Text(
                "Disconnect to add or remove servers.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AddServer(existing: Set<String>, onDismiss: () -> Unit, onAdd: (Server) -> Unit) {
    val ctx = LocalContext.current
    var text by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    val code = SERVER_CODE.find(text)?.value?.lowercase()
    val problem = when {
        text.isBlank() -> null
        code == null -> "That doesn't look like a server code. It's a long run of letters and numbers."
        code in existing -> "You've already added this server."
        else -> null
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add a server") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Paste the server code you were sent. You can paste the whole message.")
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text("Server code") },
                    isError = problem != null,
                    supportingText = problem?.let { { Text(it) } },
                    maxLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
                TextButton(onClick = { text = paste(ctx) }) { Text("Paste") }
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name it (optional), e.g. Home") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            Button(onClick = { onAdd(Server(code!!, name.trim())) }, enabled = code != null && problem == null) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun shareDeviceCode(ctx: Context, clientId: String) {
    val text = "Please let my phone into your iroh proxy server. My device code is:\n$clientId"
    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
    ctx.startActivity(Intent.createChooser(send, "Share device code"))
}

private fun openLink(ctx: Context, url: String) {
    runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
}

private fun copy(ctx: Context, text: String) {
    ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("iroh proxy", text))
}

private fun paste(ctx: Context): String =
    ctx.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString().orEmpty()
