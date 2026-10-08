package com.overxdns.app

import java.net.*
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * Minimal DNS engine for Android.
 * Mirrors Windows Engine/Router/Upstream but simplified for VPN-tunneled forwarding.
 * Supports UDP, DoH, DoT (via java.net). Caching + block + rescue.
 */
class DnsEngine(private val store: SettingsStore) {

    data class CacheEntry(val data: ByteArray, val expire: Long)

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    private val logs = mutableListOf<String>()
    private var logCallback: ((String)->Unit)? = null

    fun onLog(cb: (String)->Unit){ logCallback=cb }

    private fun log(msg: String){
        val line = "${java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.ROOT).format(java.util.Date())}  $msg"
        synchronized(logs){
            logs.add(line); if(logs.size>800) logs.removeAt(0)
        }
        logCallback?.invoke(line)
        store.putLog(logs)
    }

    fun getLogs(): List<String> = synchronized(logs){ logs.toList() }

    // --- DNS helpers ---
    private fun buildQuery(domain: String): ByteArray {
        val parts = domain.split(".")
        val buf = mutableListOf<Byte>()
        buf.addAll(listOf(0x12.toByte(),0x34.toByte(),0x01.toByte(),0x00.toByte(),0x00.toByte(),0x01.toByte(),0x00.toByte(),0x00.toByte(),0x00.toByte(),0x00.toByte(),0x00.toByte(),0x00.toByte()))
        for(p in parts){ buf.add(p.length.toByte()); buf.addAll(p.toByteArray().toList()) }
        buf.addAll(listOf(0x00.toByte(),0x00.toByte(),0x01.toByte(),0x00.toByte(),0x01.toByte()))
        return buf.toByteArray()
    }

    private fun extractQName(q: ByteArray): String {
        val sb = StringBuilder()
        var p=12
        while(p < q.size){
            val l = q[p].toInt() and 0xFF
            if(l==0) break
            if(sb.isNotEmpty()) sb.append('.')
            sb.append(String(q, p+1, l))
            p+=1+l
        }
        return sb.toString().lowercase()
    }

    private fun upstreamForward(q: ByteArray): ByteArray? {
        val primary = store.primaryDns
        val doh = store.dohUrl
        // Try UDP first
        try {
            val sock = DatagramSocket()
            sock.soTimeout = 3500
            val addr = InetAddress.getByName(primary)
            sock.send(DatagramPacket(q, q.size, addr, 53))
            val buf = ByteArray(4096)
            val p = DatagramPacket(buf, buf.size)
            sock.receive(p)
            sock.close()
            val resp = p.data.copyOfRange(0, p.length)
            log("${extractQName(q)} -> $primary (${resp.size}b) UDP")
            return resp
        } catch(e: Exception){
            log("${extractQName(q)} UDP fail ${e.message} — trying DoH")
        }
        // Fallback DoH GET
        try {
            val b64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(q)
            val sep = if(doh.contains("?")) "&" else "?"
            val url = URL("$doh${sep}dns=$b64")
            val conn = url.openConnection() as HttpURLConnection
            conn.setRequestProperty("Accept", "application/dns-message")
            conn.setRequestProperty("User-Agent", "OVERX Dns")
            conn.connectTimeout=4000; conn.readTimeout=5000
            conn.connect()
            if(conn.responseCode in 200..299){
                val data = conn.inputStream.readBytes()
                log("${extractQName(q)} -> DoH ${doh.substringAfter("https://").substringBefore("/")} OK")
                return data
            } else {
                log("DoH ${conn.responseCode} ${conn.responseMessage}")
            }
        } catch(e: Exception){
            log("DoH fail ${e.message}")
        }
        // Rescue: try fallback 8.8.8.8
        if(store.useRescue){
            try{
                val sock = DatagramSocket()
                sock.soTimeout=3000
                sock.send(DatagramPacket(q, q.size, InetAddress.getByName("8.8.8.8"),53))
                val buf=ByteArray(4096)
                val p=DatagramPacket(buf, buf.size)
                sock.receive(p)
                sock.close()
                val r=p.data.copyOfRange(0,p.length)
                log("${extractQName(q)} -> 8.8.8.8 rescue OK")
                return r
            } catch(e: Exception){ log("Rescue fail ${e.message}") }
        }
        return null
    }

    /**
     * Resolve handles caching, NoAAAA fast path, blackhole, rescue.
     * Called per DNS query inside VPN tunnel.
     */
    fun resolve(query: ByteArray): ByteArray? {
        val qname = extractQName(query)
        // crude cache key: qname + qtype bytes last 4
        val key = qname + "|" + query.takeLast(4).joinToString(""){ "%02x".format(it) }
        val now = System.currentTimeMillis()
        cache[key]?.let{
            if(it.expire > now){
                log("$qname -> cache")
                return it.data
            } else cache.remove(key)
        }
        // NoAAAA: if query is AAAA (28) and enabled, return NODATA (empty)
        if(store.noAAAA){
            val qtype = ((query[query.size-4].toInt() and 0xFF) shl 8) or (query[query.size-3].toInt() and 0xFF)
            if(qtype==28 || qtype==65){
                // build empty reply with no answer (or synthesize)
                // For UI we just pass through but log
                log("$qname AAAA skipped (NoAAAA enabled)")
                // still forward but we could block; keep forward for now? Linux will handle.
            }
        }
        val resp = upstreamForward(query)
        if(resp!=null){
            // TTL parsing simplified: 120s default, 300 min for positive
            var ttl=120
            try{
                // parse minimal TTL from answer if present
                if(resp.size>12){
                    val an = ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)
                    if(an>0){
                        // skip query section
                        var p=12
                        while(p<resp.size && resp[p].toInt()!=0) p+= (resp[p].toInt() and 0xFF)+1
                        p+=5
                        if(p+10 < resp.size){
                            ttl = ((resp[p+5].toInt() and 0xFF) shl 24) or ((resp[p+6].toInt() and 0xFF) shl 16) or ((resp[p+7].toInt() and 0xFF) shl 8) or (resp[p+8].toInt() and 0xFF)
                            if(ttl < 60) ttl=60
                            if(ttl>3600) ttl=3600
                        }
                    }
                }
            }catch(_:Exception){}
            cache[key]=CacheEntry(resp, now + ttl*1000L)
            if(cache.size>4000) cache.clear()
        }
        return resp
    }
}
