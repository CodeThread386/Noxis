package com.security.guardian.network

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.security.guardian.R
import com.security.guardian.detection.BehaviorDetectionEngine
import com.security.guardian.network.HTTPSInspector
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

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
    
    // Local threat intelligence cache
    private val maliciousDomains = mutableSetOf<String>()
    private val suspiciousDomains = mutableSetOf<String>()
    
    override fun onCreate() {
        super.onCreate()
        detectionEngine = BehaviorDetectionEngine(this)
        downloadBuffer = DownloadBuffer(this)
        httpsInspector = HTTPSInspector()
        
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
                            if (shouldBlock(sniResult.serverName)) {
                                Log.d(TAG, "Blocked connection to malicious domain: ${sniResult.serverName}")
                                continue
                            }
                            
                            // Check for SNI anomalies
                            if (sniResult.anomalies.isNotEmpty()) {
                                Log.w(TAG, "SNI anomalies detected: ${sniResult.anomalies.joinToString()}")
                            }
                        }
                        
                        // Check destination domain (fallback)
                        val destination = getDestinationFromPacket(ipHeader)
                        if (destination != null) {
                            if (shouldBlock(destination)) {
                                // Drop packet (don't forward)
                                Log.d(TAG, "Blocked connection to malicious domain: $destination")
                                continue
                            }
                            
                            // Buffer download data for inspection
                            if (isDownloadFlow(ipHeader)) {
                                downloadBuffer.addData(destination, buffer, length)
                                
                                // Inspect buffered data
                                val suspicious = downloadBuffer.inspect(destination)
                                if (suspicious) {
                                    Log.w(TAG, "Suspicious download detected from: $destination")
                                    // Block by not forwarding packet
                                    continue
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
