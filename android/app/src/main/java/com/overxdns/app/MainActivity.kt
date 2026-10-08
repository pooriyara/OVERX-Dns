package com.overxdns.app

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.webkit.*
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

/**
 * OVERX Dns — Android UI.
 * Loads shared/ui/index.html in WebView, same HTML as Windows (icon.png, bottom nav includes Logs).
 * Bridges JS <-> Kotlin via @JavascriptInterface + postMessage.
 * Shows persistent notification via DnsVpnService using same icon on status bar when connected.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var store: SettingsStore
    private var vpnPermissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()){ res ->
        if(res.resultCode == Activity.RESULT_OK) startVpn()
        else Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
    }

    private val stateReceiver = object: BroadcastReceiver(){
        override fun onReceive(ctx: Context?, intent: Intent?){
            when(intent?.action){
                "com.overxdns.STATE" -> {
                    val c = intent.getBooleanExtra("connected", false)
                    pushStatus(c)
                }
                "com.overxdns.LOG" -> {
                    val line = intent.getStringExtra("line") ?: return
                    pushLog(line)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = SettingsStore(this)
        setContentView(R.layout.activity_main)
        webView = findViewById(R.id.webView)

        setupWebView()
        webView.loadUrl("file:///android_asset/index.html")

        // Listen for service broadcasts
        registerReceiver(stateReceiver, IntentFilter().apply{
            addAction("com.overxdns.STATE"); addAction("com.overxdns.LOG")
        }, RECEIVER_NOT_EXPORTED)

        // initial push after load delayed
        webView.postDelayed({ pushStatus(store.isConnected); pushAllLogs() }, 1200)
    }

    private fun setupWebView(){
        with(webView.settings){
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            allowContentAccess = true
            mediaPlaybackRequiresUserGesture = false
            cacheMode = WebSettings.LOAD_DEFAULT
            setSupportZoom(false)
        }
        webView.webViewClient = object: WebViewClient(){
            override fun shouldOverrideUrlLoading(view: WebView?, req: WebResourceRequest?): Boolean = false
            override fun onPageFinished(view: WebView?, url: String?){
                pushStatus(store.isConnected)
                pushAllLogs()
            }
        }
        webView.webChromeClient = WebChromeClient()
        webView.addJavascriptInterface(Bridge(), "AndroidBridge")
        // Also intercept chrome.webview.postMessage style by injecting shim
        webView.evaluateJavascript("""
            (function(){
              window.AndroidBridgeOrig = window.AndroidBridge;
              window.chrome = window.chrome || {};
              window.chrome.webview = {
                postMessage: function(msg){ window.AndroidBridge.postMessage(msg); }
              };
            })();
        """.trimIndent(), null)
    }

    inner class Bridge {
        @JavascriptInterface
        fun postMessage(msg: String){
            runOnUiThread{
                try{
                    val obj = JSONObject(msg)
                    when(obj.optString("action")){
                        "apply" -> requestVpn()
                        "clear" -> stopVpn()
                        "page" -> { /* page changed: ${obj.optString("page")} */ }
                        "getLogs" -> pushAllLogs()
                        "getStatus" -> pushStatus(store.isConnected)
                        else -> {
                            // profile switch
                            if(obj.has("dns")){
                                store.primaryDns = obj.optString("dns")
                                store.dnsProfile = obj.optString("profile", store.dnsProfile)
                                pushStatus(store.isConnected)
                            }
                        }
                    }
                } catch(e: Exception){
                    // also handle plain logs from JS
                    pushLog("JS: $msg")
                }
            }
        }
        @JavascriptInterface
        fun getStatus(): String = JSONObject().put("connected", store.isConnected).toString()
        @JavascriptInterface
        fun getLogs(): String = store.getLogs()
    }

    private fun requestVpn(){
        val prep = VpnService.prepare(this)
        if(prep != null){
            vpnPermissionLauncher.launch(prep)
        } else {
            startVpn()
        }
    }
    private fun startVpn(){
        val svc = Intent(this, DnsVpnService::class.java)
        // Android 14+ requires foregroundServiceType
        startForegroundService(svc)
        store.isConnected = true
        pushStatus(true)
        Toast.makeText(this, "OVERX Dns — connecting…", Toast.LENGTH_SHORT).show()
    }
    private fun stopVpn(){
        val svc = Intent(this, DnsVpnService::class.java).apply{ action = DnsVpnService.ACTION_DISCONNECT }
        startService(svc)
        store.isConnected = false
        pushStatus(false)
        Toast.makeText(this, "OVERX Dns — disconnected", Toast.LENGTH_SHORT).show()
    }

    private fun pushStatus(connected: Boolean){
        val json = JSONObject().put("type","status").put("state", if(connected) "connected" else "disconnected").toString()
        // Escape for JS
        val esc = json.replace("\\","\\\\").replace("'","\\'").replace("\"","\\\"")
        webView.evaluateJavascript("try{ handleHostMessage('$esc'); }catch(e){ console.log(e)}", null)
        // also via postMessage fallback
        webView.evaluateJavascript("window.dispatchEvent(new MessageEvent('message',{data:'$esc'}));", null)
    }
    private fun pushLog(line: String){
        val json = JSONObject().put("type","log").put("line", line).toString()
        val esc = json.replace("\\","\\\\").replace("'","\\'").replace("\n","\\n")
        webView.evaluateJavascript("try{ handleHostMessage('$esc'); }catch(e){}", null)
    }
    private fun pushAllLogs(){
        val logs = store.getLogs()
        if(logs.isBlank()) return
        logs.lines().takeLast(80).forEach{ pushLog(it) }
    }

    override fun onDestroy() {
        try{ unregisterReceiver(stateReceiver) } catch(_: Exception){}
        super.onDestroy()
    }

    override fun onBackPressed(){
        if(webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }
}
