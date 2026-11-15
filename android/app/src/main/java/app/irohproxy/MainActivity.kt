package app.irohproxy

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
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

@Composable
fun App() {
    val ctx = LocalContext.current
    val prefs = remember { Prefs(ctx) }
    val scope = rememberCoroutineScope()
    var clientId by remember { mutableStateOf("") }
    var servers by remember { mutableStateOf(prefs.servers) }
    var newId by remember { mutableStateOf("") }
    var newName by remember { mutableStateOf("") }
    val services = remember { mutableStateMapOf<String, List<Svc>>() } // by server id
    val loading = remember { mutableStateMapOf<String, Boolean>() }
    val errors = remember { mutableStateMapOf<String, String>() }
    val ports = remember { mutableStateMapOf<String, String>() } // port text field per Svc.key
    val enabled = remember { mutableStateMapOf<String, Boolean>() }
    var error by remember { mutableStateOf<String?>(null) }
    val running = ProxyService.State.running
    var pending by remember { mutableStateOf<String?>(null) } // spec waiting for VPN consent
    val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val spec = pending
        pending = null
        if (r.resultCode == android.app.Activity.RESULT_OK && spec != null) ProxyService.start(ctx, spec, vpn = true)
        else error = "VPN permission is needed to reach services by name."
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

    LaunchedEffect(Unit) {
        clientId = withContext(Dispatchers.IO) { Native.clientId(prefs.keyPath) }
        servers.forEach { refresh(it.id) }
    }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("iroh proxy", style = MaterialTheme.typography.headlineMedium)

        Section("Your device ID") {
            Text(
                "Send this to whoever runs each server, so they can let this phone in.",
                style = MaterialTheme.typography.bodyMedium,
            )
            SelectionContainer {
                Text(clientId, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { copy(ctx, clientId) }, enabled = clientId.isNotEmpty()) { Text("Copy") }
                OutlinedButton(onClick = {
                    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, clientId)
                    ctx.startActivity(Intent.createChooser(send, "Share device ID"))
                }, enabled = clientId.isNotEmpty()) { Text("Share") }
            }
        }

        Section("Servers") {
            for (srv in servers) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(srv.label, style = MaterialTheme.typography.titleMedium)
                        Text(
                            srv.id,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    TextButton(onClick = {
                        saveServers(servers - srv)
                        services.remove(srv.id)
                        errors.remove(srv.id)
                    }, enabled = !running) { Text("Remove") }
                }
            }
            OutlinedTextField(
                value = newId,
                onValueChange = { newId = it.trim() },
                label = { Text("Server ID") },
                singleLine = true,
                enabled = !running,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = newName,
                onValueChange = { newName = it },
                label = { Text("Name (optional)") },
                singleLine = true,
                enabled = !running,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val srv = Server(newId, newName.trim())
                        saveServers(servers + srv)
                        newId = ""
                        newName = ""
                        refresh(srv.id)
                    },
                    enabled = !running && newId.isNotEmpty() && servers.none { it.id == newId },
                ) { Text("Add server") }
                OutlinedButton(
                    onClick = { servers.forEach { refresh(it.id) } },
                    enabled = servers.isNotEmpty() && loading.isEmpty(),
                ) { Text("Refresh") }
            }
        }

        if (servers.isNotEmpty()) Section("Services") {
            for (srv in servers) {
                Text(srv.label, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
                if (loading[srv.id] == true) CircularProgressIndicator(Modifier.size(24.dp))
                errors[srv.id]?.let {
                    Text(
                        "Couldn't reach this server. It may be offline, or this phone isn't allowed in yet " +
                            "(send your device ID to the server's owner).",
                        color = MaterialTheme.colorScheme.error,
                    )
                    Text(it, style = MaterialTheme.typography.bodySmall)
                }
                val list = services[srv.id]
                if (list != null && list.isEmpty()) Text("This server offers no services.")
                for (s in list.orEmpty()) {
                    ServiceRow(
                        svc = s,
                        port = ports[s.key] ?: "",
                        onPort = { ports[s.key] = it.filter(Char::isDigit).take(5) },
                        enabled = enabled[s.key] ?: true,
                        onEnabled = { enabled[s.key] = it; prefs.setEnabled(s, it) },
                        running = running,
                        forward = ProxyService.State.forwards[s.key],
                        ctx = ctx,
                    )
                }
                Spacer(Modifier.height(8.dp))
            }
            (ProxyService.State.error ?: error)?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            val all = servers.flatMap { services[it.id].orEmpty() }
            if (running) {
                Button(onClick = { ProxyService.stop(ctx) }, modifier = Modifier.fillMaxWidth()) { Text("Disconnect") }
            } else {
                Button(
                    onClick = {
                        error = null
                        val chosen = all.filter { enabled[it.key] ?: true }
                        val spec = Svc.spec(chosen) { s ->
                            val port = ports[s.key]?.toIntOrNull()?.takeIf { it in 0..65535 } ?: s.port
                            prefs.setPort(s, port)
                            port
                        }
                        val vpn = chosen.any { it.needsVpn }
                        val consent = if (vpn) VpnService.prepare(ctx) else null
                        if (consent != null) {
                            pending = spec
                            vpnConsent.launch(consent)
                        } else {
                            ProxyService.start(ctx, spec, vpn)
                        }
                    },
                    enabled = all.any { enabled[it.key] ?: true },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Connect") }
            }
        }
    }
}

@Composable
private fun ServiceRow(
    svc: Svc,
    port: String,
    onPort: (String) -> Unit,
    enabled: Boolean,
    onEnabled: (Boolean) -> Unit,
    running: Boolean,
    forward: String?,
    ctx: Context,
) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Column(Modifier.weight(1f)) {
            Text(svc.name, style = MaterialTheme.typography.titleMedium)
            if (svc.needsVpn) {
                Text(
                    svc.hostnames.joinToString(", ") + if (running && enabled) " (VPN)" else "",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            when {
                !running -> Text(if (svc.udp) "UDP" else "TCP", style = MaterialTheme.typography.bodySmall)
                !enabled -> Text("off", style = MaterialTheme.typography.bodySmall)
                forward == null -> Text("couldn't open a local port", color = MaterialTheme.colorScheme.error)
                else -> TextButton(onClick = { copy(ctx, forward) }) {
                    Text("$forward (tap to copy)", fontFamily = FontFamily.Monospace)
                }
            }
        }
        if (!running) {
            OutlinedTextField(
                value = port,
                onValueChange = onPort,
                label = { Text("Port") },
                singleLine = true,
                enabled = enabled,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.width(96.dp),
            )
            Switch(checked = enabled, onCheckedChange = onEnabled)
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            content()
        }
    }
}

private fun copy(ctx: Context, text: String) {
    ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("iroh proxy", text))
}
