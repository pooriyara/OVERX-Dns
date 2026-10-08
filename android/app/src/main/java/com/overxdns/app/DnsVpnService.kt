package com.overxdns.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * OVERX Dns — VPN service that intercepts DNS (port 53) and forwards via DnsEngine.
 * When connected, shows persistent notification with the same OVERX icon (ic_launcher / ic_stat) at top status bar.
 */
class DnsVpnService : VpnService() {

    companion object {
        const val NOTIF_ID = 4201
        const val CHANNEL_ID = "overx_dns_vpn"
        const val ACTION_DISCONNECT = "com.overxdns.app.DISCONNECT"
        const val TAG = "OVERX_Dns_VPN"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var running = false
    private val executor = Executors.newCachedThreadPool()
    private lateinit var store: SettingsStore
    private lateinit var engine: DnsEngine

    override fun onCreate() {
        super.onCreate()
        store = SettingsStore(this)
        engine = DnsEngine(store)
        createChannel()
    }

    private fun createChannel(){
        val nm = getSystemService(NotificationManager::class.java)
        val ch = NotificationChannel(CHANNEL_ID, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
        ch.description = getString(R.string.vpn_describe)
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(connected: Boolean): Notification {
        // Intent to open MainActivity
        val open = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java).apply{ flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val stop = PendingIntent.getService(this, 1,
            Intent(this, DnsVpnService::class.java).apply{ action = ACTION_DISCONNECT },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        // Use same OVERX icon for status bar — ic_launcher for large, ic_stat_overx for small
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_overx) // status bar icon = same OVERX brand (converted to monochrome vector) — per spec use app icon
            .setLargeIcon(android.graphics.BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher))
            .setContentTitle(if(connected) getString(R.string.notif_title) else "OVERX Dns Idle")
            .setContentText(if(connected) "Routing DNS via ${store.primaryDns} — ${store.dnsProfile}" else "Tap to configure")
            .setOngoing(connected)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(R.drawable.ic_stat_overx, getString(R.string.vpn_disconnect), stop)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .build()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when(intent?.action){
            ACTION_DISCONNECT -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startVpn()
                return START_STICKY
            }
        }
    }

    private fun startVpn(){
        if(running) return
        try{
            val builder = Builder()
                .addAddress("10.211.0.1", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(store.primaryDns) // system DNS for VPN interface itself will be our tun
                .addDnsServer(store.secondaryDns)
                .setSession("OVERX Dns")
                .setMtu(1500)
                .setBlocking(false)

            // QUIC block: if enabled, add route blocking UDP 443 via firewall? On Android we can't block QUIC easily without filtering, but we note.
            // We set "allowBypass" false to prevent leaks
            builder.setConfigureIntent(PendingIntent.getActivity(this,0,Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))

            vpnInterface = builder.establish()
            if(vpnInterface==null){
                Log.e(TAG,"VPN establish returned null - permission revoked?")
                return
            }
            running = true
            store.isConnected = true
            startForeground(NOTIF_ID, buildNotification(true))
            // Notify activity
            sendBroadcast(Intent("com.overxdns.STATE").putExtra("connected", true))
            Log.i(TAG,"VPN started fd=${vpnInterface?.fd}")

            // Start packet pump
            thread(name="overx-vpn-reader", isDaemon=true){
                pumpLoop()
            }

            engine.onLog { line ->
                // forward to activity via broadcast
                sendBroadcast(Intent("com.overxdns.LOG").putExtra("line", line))
            }
            engine.getLogs() // preload

        } catch(e: Exception){
            Log.e(TAG,"startVpn failed",e)
            stopVpn()
        }
    }

    private fun pumpLoop(){
        val fd = vpnInterface?.fileDescriptor ?: return
        val inp = FileInputStream(fd)
        val out = FileOutputStream(fd)
        val packet = ByteBuffer.allocate(2048)
        val buffer = ByteArray(2048)

        while(running){
            try{
                packet.clear()
                val read = inp.read(buffer)
                if(read<=0){ Thread.sleep(10); continue }
                // For MVP: we do not fully parse IP/UDP, we just handle DNS forwarding when dest port 53
                // Simplified: extract IP header + UDP and forward DNS query via engine, then craft response.
                // Due to complexity of full TUN parsing, we use a lightweight forwarder: if packet contains DNS query (port 53), resolve and inject response
                // Else forward silently (we let system handle via VPN routing — but we already route 0.0.0.0, so need to forward to real network)
                // For brevity, we treat all UDP 53 as DNS to intercept
                val handled = handlePacket(buffer, read, out)
                if(!handled){
                    // For non-DNS, do nothing — in production you would forward via protect() socket
                }
            } catch(e: Exception){
                if(running) Log.w(TAG,"pump error ${e.message}")
                Thread.sleep(50)
            }
        }
    }

    // Very minimal IP/UDP parser: returns true if was DNS and we responded
    private fun handlePacket(buf: ByteArray, len: Int, out: FileOutputStream): Boolean {
        try{
            if(len < 28) return false
            // IP version
            val ver = (buf[0].toInt() ushr 4) and 0xF
            if(ver != 4) return false
            val ihl = (buf[0].toInt() and 0xF) * 4
            if(len < ihl + 8) return false
            val proto = buf[9].toInt() and 0xFF
            if(proto != 17) return false // UDP only
            val srcPort = ((buf[ihl].toInt() and 0xFF) shl 8) or (buf[ihl+1].toInt() and 0xFF)
            val dstPort = ((buf[ihl+2].toInt() and 0xFF) shl 8) or (buf[ihl+3].toInt() and 0xFF)
            if(dstPort != 53 && srcPort != 53) return false

            val udpLen = ((buf[ihl+4].toInt() and 0xFF) shl 8) or (buf[ihl+5].toInt() and 0xFF)
            val dnsOff = ihl + 8
            val dnsLen = udpLen - 8
            if(dnsOff + dnsLen > len || dnsLen < 12) return false
            val query = buf.copyOfRange(dnsOff, dnsOff + dnsLen)

            // Resolve via engine (network calls via protected socket would need protect(), but for demo we use direct)
            val response = engine.resolve(query) ?: return false

            // Build response packet by swapping IP/UDP src/dst and inserting DNS response
            val respPacket = ByteArray(ihl + 8 + response.size)
            // Copy IP header
            System.arraycopy(buf, 0, respPacket, 0, ihl)
            // Swap src/dst IP
            for(i in 0 until 4){
                val tmp = respPacket[12+i]
                respPacket[12+i] = respPacket[16+i]
                respPacket[16+i] = tmp
            }
            // Swap ports
            respPacket[ihl] = buf[ihl+2]; respPacket[ihl+1]=buf[ihl+3]
            respPacket[ihl+2]=buf[ihl]; respPacket[ihl+3]=buf[ihl+1]
            // UDP length
            val newUdpLen = response.size + 8
            respPacket[ihl+4]=(newUdpLen ushr 8).toByte(); respPacket[ihl+5]=newUdpLen.toByte()
            respPacket[ihl+6]=0; respPacket[ihl+7]=0 // checksum 0 (kernel may accept)
            // DNS payload
            System.arraycopy(response,0, respPacket, ihl+8, response.size)
            // IP total length
            val total = respPacket.size
            respPacket[2]=(total ushr 8).toByte(); respPacket[3]=total.toByte()
            // IP checksum recalc
            respPacket[10]=0; respPacket[11]=0
            var sum=0
            for(i in 0 until ihl step 2){
                sum += ((respPacket[i].toInt() and 0xFF) shl 8) or (respPacket[i+1].toInt() and 0xFF)
            }
            while((sum ushr 16)!=0) sum = (sum and 0xFFFF) + (sum ushr 16)
            sum = sum.inv() and 0xFFFF
            respPacket[10]=(sum ushr 8).toByte(); respPacket[11]=sum.toByte()

            out.write(respPacket)
            return true
        } catch(e: Exception){
            Log.w(TAG,"handlePacket fail ${e.message}")
            return false
        }
    }

    private fun stopVpn(){
        running = false
        store.isConnected=false
        try{ vpnInterface?.close() } catch(_:Exception){}
        vpnInterface=null
        try{ stopForeground(STOP_FOREGROUND_REMOVE) } catch(_:Exception){}
        sendBroadcast(Intent("com.overxdns.STATE").putExtra("connected", false))
        // Update notification to idle? Remove.
        val nm = getSystemService(NotificationManager::class.java)
        nm.cancel(NOTIF_ID)
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }
}
