package com.security.guardian.network

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.security.guardian.R
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.ThreatEvent
import com.security.guardian.detection.BehaviorDetectionEngine
import com.security.guardian.network.HTTPSInspector
import com.security.guardian.network.PIILeakTracker
import com.security.guardian.notification.ThreatNotificationService
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

/**
 * VPN Service for intercepting network traffic and blocking suspicious downloads
 * Implements on-device VPN to capture outbound traffic without root
 */
class VPNInterceptionService : VpnService() {
    
    private val TAG = "VPNInterceptionService"
    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var detectionEngine: BehaviorDetectionEngine
    private lateinit var downloadBuffer: DownloadBuffer
    private lateinit var httpsInspector: HTTPSInspector
    private lateinit var database: RansomwareDatabase
    private lateinit var notificationService: ThreatNotificationService
    private lateinit var piiLeakTracker: PIILeakTracker
    
    // Local threat intelligence cache
    private val maliciousDomains = mutableSetOf<String>()
    private val suspiciousDomains = mutableSetOf<String>()
    private val blockedDomains = mutableMapOf<String, Long>() // domain -> timestamp
    private val sniCache = mutableMapOf<String, HTTPSInspector.SNIResult>() // IP -> SNI result
    
    override fun onCreate() {
        super.onCreate()
        detectionEngine = BehaviorDetectionEngine(this)
        downloadBuffer = DownloadBuffer(this)
        httpsInspector = HTTPSInspector()
        database = RansomwareDatabase.getDatabase(this)
        notificationService = ThreatNotificationService(this)
        
        // Load threat intelligence cache
        loadThreatIntelligence()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVPN()
            ACTION_STOP -> stopVPN()
        }
        return START_STICKY
    }
    
    private fun startVPN() {
        if (vpnInterface != null) {
            Log.d(TAG, "VPN already running")
            return
        }
        
        try {
            val builder = Builder()
            builder.setSession("RansomwareGuard VPN")
            builder.addAddress("10.0.0.2", 30)
            builder.addRoute("0.0.0.0", 0)
            builder.addDnsServer("8.8.8.8")
            builder.addDnsServer("8.8.4.4")
            builder.setMtu(1500)
            
            val configureIntent = PendingIntent.getActivity(
                this, 0,
                Intent(this, com.security.guardian.ui.MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE
            )
            builder.setConfigureIntent(configureIntent)
            
            vpnInterface = builder.establish()
            
            if (vpnInterface != null) {
                Log.d(TAG, "VPN established")
                serviceScope.launch {
                    processPackets()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
        }
    }
    
    private fun stopVPN() {
        vpnInterface?.close()
        vpnInterface = null
        stopSelf()
    }
    
    private suspend fun processPackets() {
        val vpnInput = FileInputStream(vpnInterface!!.fileDescriptor)
        val vpnOutput = FileOutputStream(vpnInterface!!.fileDescriptor)
        val buffer = ByteArray(32767)
        
        while (vpnInterface != null && vpnInterface!!.fileDescriptor.valid()) {
            try {
                val length = vpnInput.read(buffer)
                if (length > 0) {
                    val packet = ByteBuffer.wrap(buffer, 0, length).order(ByteOrder.BIG_ENDIAN)
                    
                    // Parse IP packet
                    val ipHeader = parseIPHeader(packet)
                    if (ipHeader != null) {
                        // Try to extract SNI from TLS handshake
                        val sniResult = httpsInspector.extractSNI(buffer.sliceArray(0 until length))
                        if (sniResult.serverName != null) {
                            val domain = sniResult.serverName
                            
                            // Cache SNI result
                            val destIPString = ipHeader.destIP.joinToString(".")
                            sniCache[destIPString] = sniResult
                            
                            // Check for SNI anomalies
                            if (sniResult.anomalies.isNotEmpty()) {
                                Log.w(TAG, "SNI anomalies detected for $domain: ${sniResult.anomalies.joinToString()}")
                                serviceScope.launch {
                                    handleSNIAnomaly(domain, sniResult)
                                }
                            }
                            
                            if (shouldBlock(domain)) {
                                Log.d(TAG, "Blocked connection to malicious domain: $domain")
                                blockedDomains[domain] = System.currentTimeMillis()
                                continue
                            }
                        }
                        
                        // Check destination domain (fallback)
                        val destination = getDestinationFromPacket(ipHeader)
                        if (destination != null) {
                            if (shouldBlock(destination)) {
                                // Drop packet (don't forward)
                                Log.d(TAG, "Blocked connection to malicious domain: $destination")
                                blockedDomains[destination] = System.currentTimeMillis()
                                continue
                            }
                            
                            // Buffer download data for inspection
                            if (isDownloadFlow(ipHeader)) {
                                downloadBuffer.addData(destination, buffer, length)
                                
                                // Inspect buffered data
                                val suspicious = downloadBuffer.inspect(destination)
                                if (suspicious) {
                                    Log.w(TAG, "Suspicious download detected from: $destination")
                                    serviceScope.launch {
                                        handleSuspiciousDownload(destination)
                                    }
                                    // Block by not forwarding packet
                                    continue
                                }
                                
                                // Check content size patterns
                                val contentSize = length.toLong()
                                val suspiciousSize = httpsInspector.checkContentSizePattern(contentSize, null)
                                if (suspiciousSize) {
                                    Log.w(TAG, "Suspicious content size pattern from: $destination")
                                    serviceScope.launch {
                                        handleSuspiciousDownload(destination)
                                    }
                                }
                            }
                        }
                    }
                    
                    // Forward packet
                    vpnOutput.write(buffer, 0, length)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error processing packet", e)
                break
            }
        }
    }
    
    private fun parseIPHeader(packet: ByteBuffer): IPHeader? {
        if (packet.remaining() < 20) return null
        
        val version = (packet.get(0).toInt() shr 4) and 0x0F
        if (version != 4) return null // Only IPv4 for now
        
        val protocol = packet.get(9).toInt() and 0xFF
        val sourceIP = ByteArray(4)
        val destIP = ByteArray(4)
        
        packet.position(12)
        packet.get(sourceIP)
        packet.position(16)
        packet.get(destIP)
        
        return IPHeader(
            version = version,
            protocol = protocol,
            sourceIP = sourceIP,
            destIP = destIP,
            totalLength = packet.getShort(2).toInt() and 0xFFFF
        )
    }
    
    private fun getDestinationFromPacket(header: IPHeader): String? {
        // Try SNI extraction for HTTPS traffic
        // For now, return null and rely on domain blocking via other means
        // SNI extraction would be done in processPackets() by inspecting TLS handshake
        return null
    }
    
    private fun shouldBlock(destination: String?): Boolean {
        if (destination == null) return false
        return maliciousDomains.contains(destination) || 
               suspiciousDomains.contains(destination)
    }
    
    private fun isDownloadFlow(header: IPHeader): Boolean {
        // Check if this looks like a download (HTTP/HTTPS, large payload)
        return header.protocol == 6 || header.protocol == 17 // TCP or UDP
    }
    
    private suspend fun handleSNIAnomaly(domain: String, sniResult: HTTPSInspector.SNIResult) {
        try {
            val threat = ThreatEvent(
                type = "HTTPS_ANOMALY",
                packageName = null,
                description = "HTTPS anomaly detected for $domain: ${sniResult.anomalies.joinToString(", ")}",
                severity = "MEDIUM",
                confidence = 0.70f,
                timestamp = System.currentTimeMillis(),
                status = "DETECTED",
                indicators = sniResult.anomalies.toString()
            )
            database.threatEventDao().insertThreat(threat)
            notificationService.notifyThreat(threat)
        } catch (e: Exception) {
            Log.e(TAG, "Error handling SNI anomaly", e)
        }
    }
    
    private suspend fun handleSuspiciousDownload(domain: String) {
        try {
            val threat = ThreatEvent(
                type = "SUSPICIOUS_DOWNLOAD",
                packageName = null,
                description = "Suspicious download blocked from: $domain",
                severity = "HIGH",
                confidence = 0.80f,
                timestamp = System.currentTimeMillis(),
                status = "BLOCKED",
                indicators = listOf(domain).toString()
            )
            database.threatEventDao().insertThreat(threat)
            notificationService.notifyThreat(threat)
        } catch (e: Exception) {
            Log.e(TAG, "Error handling suspicious download", e)
        }
    }
    
    fun getBlockedDomainsCount(): Int = blockedDomains.size
    
    fun getTopBlockedDomains(limit: Int = 10): List<String> {
        return blockedDomains.entries
            .sortedByDescending { it.value }
            .take(limit)
            .map { it.key }
    }
    
    /**
     * Update stats in SharedPreferences for UI access
     */
    private fun updateStats() {
        try {
            val prefs = getSharedPreferences("vpn_stats", android.content.Context.MODE_PRIVATE)
            prefs.edit()
                .putInt("blocked_domains_count", blockedDomains.size)
                .putString("top_blocked_domains", getTopBlockedDomains(10).joinToString(","))
                .putInt("trackers_blocked", blockedDomains.size) // Simplified
                .apply()
        } catch (e: Exception) {
            Log.e(TAG, "Error updating stats", e)
        }
    }
    
    private fun loadThreatIntelligence() {
        // Load from local cache or cloud (privacy-preserving)
        // For now, use hardcoded examples
        maliciousDomains.addAll(listOf(
            "malicious.example.com",
            "ransomware.download"
        ))
    }
    
    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        stopVPN()
    }
    
    data class IPHeader(
        val version: Int,
        val protocol: Int,
        val sourceIP: ByteArray,
        val destIP: ByteArray,
        val totalLength: Int
    )
    
    companion object {
        const val ACTION_START = "com.security.guardian.VPN_START"
        const val ACTION_STOP = "com.security.guardian.VPN_STOP"
    }
}

/**
 * Buffer download data for inspection (first 16-64 KB)
 */
class DownloadBuffer(private val context: android.content.Context) {
    private val buffers = mutableMapOf<String, ByteArray>()
    private val maxBufferSize = 64 * 1024 // 64 KB
    
    fun addData(domain: String, data: ByteArray, length: Int) {
        val buffer = buffers.getOrPut(domain) { ByteArray(0) }
        if (buffer.size < maxBufferSize) {
            val newBuffer = ByteArray(buffer.size + length)
            System.arraycopy(buffer, 0, newBuffer, 0, buffer.size)
            System.arraycopy(data, 0, newBuffer, buffer.size, length)
            buffers[domain] = newBuffer
        }
    }
    
    fun inspect(domain: String): Boolean {
        val buffer = buffers[domain] ?: return false
        
        // Check file magic bytes
        val magic = buffer.take(4).toByteArray()
        val suspiciousMagic = checkSuspiciousMagic(magic)
        
        // Check entropy
        val entropy = calculateEntropy(buffer)
        val highEntropy = entropy > 7.5
        
        // Check for known ransomware signatures
        val hasSignature = checkRansomwareSignature(buffer)
        
        return suspiciousMagic || (highEntropy && hasSignature)
    }
    
    private fun checkSuspiciousMagic(magic: ByteArray): Boolean {
        // Check for suspicious file types
        val suspiciousTypes = listOf(
            byteArrayOf(0x4D.toByte(), 0x5A.toByte(), 0x90.toByte(), 0x00.toByte()), // PE executable
            byteArrayOf(0x7F.toByte(), 0x45.toByte(), 0x4C.toByte(), 0x46.toByte())  // ELF executable
        )
        return suspiciousTypes.any { it.contentEquals(magic) }
    }
    
    private fun calculateEntropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        
        val frequency = IntArray(256)
        data.forEach { byte ->
            frequency[byte.toInt() and 0xFF]++
        }
        
        var entropy = 0.0
        val length = data.size.toDouble()
        
        for (count in frequency) {
            if (count > 0) {
                val probability = count / length
                entropy -= probability * kotlin.math.log2(probability)
            }
        }
        
        return entropy
    }
    
    private fun checkRansomwareSignature(data: ByteArray): Boolean {
        val content = String(data, Charsets.UTF_8).lowercase()
        val signatures = listOf(
            "ransomware",
            "encrypt",
            "decrypt",
            "bitcoin",
            "payment"
        )
        return signatures.any { content.contains(it) }
    }
}
