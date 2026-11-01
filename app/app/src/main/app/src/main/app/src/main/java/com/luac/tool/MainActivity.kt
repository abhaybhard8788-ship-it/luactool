package com.luac.tool

import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { App() } }
    }
}

@Composable
fun App() {
    val ctx = LocalContext.current
    val ui = remember { Handler(Looper.getMainLooper()) }
    var input by remember { mutableStateOf<Uri?>(null) }
    var key by remember { mutableStateOf("") }
    var sign by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val logs = remember { mutableStateListOf<String>() }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { input = it }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { out ->
        val inp = input
        if (out != null && inp != null) {
            busy = true; logs.clear()
            Thread {
                try { Engine.run(ctx, inp, out, key, sign) { m -> ui.post { logs.add(m) } } }
                catch (e: Throwable) { ui.post { logs.add("ERROR: ${e.message}") } }
                ui.post { busy = false }
            }.start()
        }
    }
    Column(Modifier.statusBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Luac Decrypt + Decompile", style = MaterialTheme.typography.titleLarge)
        Button(onClick = { pick.launch(arrayOf("*/*")) }) { Text(if (input == null) "1. APK / file chuno" else "File selected") }
        OutlinedTextField(key, { key = it }, label = { Text("Key (optional, XOR/XXTEA)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(sign, { sign = it }, label = { Text("Sign (optional, e.g. XXTEA)") }, modifier = Modifier.fillMaxWidth())
        Button(enabled = input != null && !busy, onClick = { save.launch("output.zip") }) {
            Text(if (busy) "Working..." else "2. Start & ZIP save karo")
        }
        LazyColumn { items(logs) { Text(it, style = MaterialTheme.typography.bodySmall) } }
    }
}
