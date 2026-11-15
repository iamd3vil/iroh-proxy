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
import androidx.compose.runtime.mutableStateListOf
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
    var server by remember { mutableStateOf(prefs.server) }
    val services = remember { mutableStateListOf<Svc>() }
    val ports = remember { mutableStateMapOf<String, String>() } // port text field per service key
    val enabled = remember { mutableStateMapOf<String, Boolean>() }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val running = ProxyService.State.running
    var pendingSpec by remember { mutableStateOf<String?>(null) }
    val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val spec = pendingSpec
        pendingSpec = null
        if (r.resultCode == android.app.Activity.RESULT_OK && spec != null) ProxyService.start(ctx, spec)
        else error = "VPN permission is needed to reach services by name."
    }

    fun refresh() {
        if (prefs.server.isBlank()) return
        loading = true
        error = null
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching { Native.services(prefs.keyPath, prefs.server) } }
            loading = false
            r.onSuccess { out ->
                val list = Svc.parse(out)
                services.clear()
                services.addAll(list)
                for (s in list) {
                    ports.getOrPut(s.key) { (prefs.port(s) ?: s.port).toString() }
                    enabled.getOrPut(s.key) { prefs.enabled(s) }
                }
            }.onFailure { error = it.message ?: it.toString() }
        }
    }

    LaunchedEffect(Unit) {
        clientId = withContext(Dispatchers.IO) { Native.clientId(prefs.keyPath) }
        refresh()
    }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("iroh proxy", style = MaterialTheme.typography.headlineMedium)

        Section("Your device ID") {
            Text(
                "Send this to whoever runs the server, so they can let this phone in.",
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

        Section("Server") {
            OutlinedTextField(
                value = server,
                onValueChange = { server = it },
                label = { Text("Server ID") },
                singleLine = true,
                enabled = !running,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = {
                    prefs.server = server
                    services.clear()
                    refresh()
                },
                enabled = !running && server.isNotBlank() && !loading,
            ) { Text(if (prefs.server.isNotBlank() && server.trim() == prefs.server) "Refresh services" else "Save") }
        }

        if (prefs.server.isNotBlank()) Section("Services") {
            if (loading) CircularProgressIndicator(Modifier.size(24.dp))
            error?.let {
                Text(
                    "Couldn't reach the server. It may be offline, or this phone isn't allowed in yet " +
                        "(send your device ID to the server's owner).",
                    color = MaterialTheme.colorScheme.error,
                )
                Text(it, style = MaterialTheme.typography.bodySmall)
            }
            ProxyService.State.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (!loading && error == null && services.isEmpty()) Text("The server offers no services.")
            for (s in services) {
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
            Spacer(Modifier.height(4.dp))
            if (running) {
                Button(onClick = { ProxyService.stop(ctx) }, modifier = Modifier.fillMaxWidth()) { Text("Disconnect") }
            } else {
                Button(
                    onClick = {
                        val chosen = services.filter { enabled[it.key] ?: true }
                        val spec = chosen.joinToString("") { s ->
                            val port = ports[s.key]?.toIntOrNull()?.takeIf { it in 0..65535 } ?: s.port
                            prefs.setPort(s, port)
                            s.lines(port)
                        }
                        val consent = if (chosen.any { it.needsVpn }) VpnService.prepare(ctx) else null
                        if (consent != null) {
                            pendingSpec = spec
                            vpnConsent.launch(consent)
                        } else {
                            ProxyService.start(ctx, spec)
                        }
                    },
                    enabled = services.any { enabled[it.key] ?: true },
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
