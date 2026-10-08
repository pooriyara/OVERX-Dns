package com.overxdns.app

import android.content.Context
import android.content.SharedPreferences

/**
 * Shared-Prefs store for OVERX Dns — mirrors Windows registry HKCU\Software\OVERX Dns
 */
class SettingsStore(ctx: Context) {
    private val prefs: SharedPreferences =
        ctx.getSharedPreferences("OVERX_Dns", Context.MODE_PRIVATE)

    var dnsProfile: String
        get() = prefs.getString("dns_profile", "Cloudflare") ?: "Cloudflare"
        set(v) = prefs.edit().putString("dns_profile", v).apply()

    var primaryDns: String
        get() = prefs.getString("primary_dns", "1.1.1.1") ?: "1.1.1.1"
        set(v) = prefs.edit().putString("primary_dns", v).apply()

    var secondaryDns: String
        get() = prefs.getString("secondary_dns", "1.0.0.1") ?: "1.0.0.1"
        set(v) = prefs.edit().putString("secondary_dns", v).apply()

    var dohUrl: String
        get() = prefs.getString("doh_url", "https://cloudflare-dns.com/dns-query") ?: "https://cloudflare-dns.com/dns-query"
        set(v) = prefs.edit().putString("doh_url", v).apply()

    var isConnected: Boolean
        get() = prefs.getBoolean("connected", false)
        set(v) = prefs.edit().putBoolean("connected", v).apply()

    var blockQuic: Boolean
        get() = prefs.getBoolean("block_quic", true)
        set(v) = prefs.edit().putBoolean("block_quic", v).apply()

    var noAAAA: Boolean
        get() = prefs.getBoolean("no_aaaa", true)
        set(v) = prefs.edit().putBoolean("no_aaaa", v).apply()

    var useRescue: Boolean
        get() = prefs.getBoolean("use_rescue", true)
        set(v) = prefs.edit().putBoolean("use_rescue", v).apply()

    var languageIsFa: Boolean
        get() = prefs.getBoolean("lang_fa", false)
        set(v) = prefs.edit().putBoolean("lang_fa", v).apply()

    fun putLog(lines: List<String>) {
        // keep last 400 lines
        val trimmed = if (lines.size > 400) lines.takeLast(400) else lines
        prefs.edit().putString("logs", trimmed.joinToString("\n")).apply()
    }
    fun getLogs(): String = prefs.getString("logs", "") ?: ""
}
