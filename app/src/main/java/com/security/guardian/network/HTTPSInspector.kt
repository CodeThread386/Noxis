package com.security.guardian.network

import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.net.ssl.SSLException

/**
 * HTTPS/SNI inspection and certificate analysis
 * Extracts SNI from TLS handshake and analyzes certificate anomalies
 */
class HTTPSInspector {
    
    private val TAG = "HTTPSInspector"
    
    data class SNIResult(
        val serverName: String?,
        val isValid: Boolean,
        val anomalies: List<String>
    )
    
    data class CertificateAnalysis(
        val isValid: Boolean,
        val anomalies: List<String>,
        val issuer: String?,
        val subject: String?,
        val validityPeriod: Long?
    )
    
    /**
     * Extract Server Name Indication (SNI) from TLS ClientHello
     */
    fun extractSNI(packet: ByteArray): SNIResult {
        val anomalies = mutableListOf<String>()
        
        try {
            val buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
            
            // Check if this is a TLS handshake
            if (packet.size < 5) return SNIResult(null, false, listOf("Packet too small"))
            
            val contentType = packet[0].toInt() and 0xFF
            if (contentType != 22) { // 22 = Handshake
                return SNIResult(null, false, listOf("Not a TLS handshake"))
            }
            
            // Check TLS version
            val tlsVersion = ((packet[1].toInt() and 0xFF) shl 8) or (packet[2].toInt() and 0xFF)
            if (tlsVersion < 0x0301 || tlsVersion > 0x0304) {
                anomalies.add("Unusual TLS version: 0x${tlsVersion.toString(16)}")
            }
            
            // Find ClientHello message
            val handshakeType = packet[5].toInt() and 0xFF
            if (handshakeType != 1) { // 1 = ClientHello
                return SNIResult(null, false, listOf("Not a ClientHello"))
            }
            
            // Parse ClientHello to find SNI extension
            val serverName = parseSNIFromClientHello(packet)
            
            // Check for SNI anomalies
            if (serverName != null) {
                checkSNIAnomalies(serverName, anomalies)
            } else {
                anomalies.add("No SNI in ClientHello (possible evasion)")
            }
            
            return SNIResult(serverName, serverName != null, anomalies)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting SNI", e)
            return SNIResult(null, false, listOf("Error: ${e.message}"))
        }
    }
    
    private fun parseSNIFromClientHello(packet: ByteArray): String? {
        try {
            var offset = 5 // Skip TLS record header and handshake type
            
            // Skip handshake message length (3 bytes)
            offset += 3
            
            // Skip protocol version (2 bytes)
            offset += 2
            
            // Skip random (32 bytes)
            offset += 32
            
            // Skip session ID length and session ID
            if (offset >= packet.size) return null
            val sessionIdLength = packet[offset].toInt() and 0xFF
            offset += 1 + sessionIdLength
            
            // Skip cipher suites length and cipher suites
            if (offset >= packet.size) return null
            val cipherSuitesLength = ((packet[offset].toInt() and 0xFF) shl 8) or 
                                    (packet[offset + 1].toInt() and 0xFF)
            offset += 2 + cipherSuitesLength
            
            // Skip compression methods
            if (offset >= packet.size) return null
            val compressionLength = packet[offset].toInt() and 0xFF
            offset += 1 + compressionLength
            
            // Now we're at extensions
            if (offset >= packet.size) return null
            val extensionsLength = ((packet[offset].toInt() and 0xFF) shl 8) or 
                                  (packet[offset + 1].toInt() and 0xFF)
            offset += 2
            
            val extensionsEnd = offset + extensionsLength
            
            // Search for SNI extension (type 0x0000)
            while (offset < extensionsEnd && offset < packet.size - 4) {
                val extType = ((packet[offset].toInt() and 0xFF) shl 8) or 
                             (packet[offset + 1].toInt() and 0xFF)
                val extLength = ((packet[offset + 2].toInt() and 0xFF) shl 8) or 
                               (packet[offset + 3].toInt() and 0xFF)
                
                if (extType == 0x0000) { // SNI extension
                    return parseSNIExtension(packet, offset + 4, extLength)
                }
                
                offset += 4 + extLength
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing SNI", e)
        }
        
        return null
    }
    
    private fun parseSNIExtension(packet: ByteArray, offset: Int, length: Int): String? {
        try {
            if (offset + 2 >= packet.size) return null
            
            // Skip server name list length
            var pos = offset + 2
            
            if (pos >= packet.size) return null
            
            // Read server name type (0 = host_name)
            val nameType = packet[pos].toInt() and 0xFF
            if (nameType != 0) return null
            
            pos += 1
            
            // Read server name length
            if (pos + 2 > packet.size) return null
            val nameLength = ((packet[pos].toInt() and 0xFF) shl 8) or 
                            (packet[pos + 1].toInt() and 0xFF)
            pos += 2
            
            // Read server name
            if (pos + nameLength > packet.size) return null
            val serverNameBytes = ByteArray(nameLength)
            System.arraycopy(packet, pos, serverNameBytes, 0, nameLength)
            
            return String(serverNameBytes, Charsets.UTF_8)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing SNI extension", e)
            return null
        }
    }
    
    private fun checkSNIAnomalies(serverName: String, anomalies: MutableList<String>) {
        // Check for suspicious patterns
        if (serverName.contains("bit.ly") || serverName.contains("tinyurl")) {
            anomalies.add("URL shortener in SNI")
        }
        
        if (serverName.length > 253) { // Max DNS name length
            anomalies.add("SNI too long")
        }
        
        if (serverName.contains("..") || serverName.startsWith(".") || serverName.endsWith(".")) {
            anomalies.add("Invalid SNI format")
        }
        
        // Check for IP address instead of domain
        if (isIPAddress(serverName)) {
            anomalies.add("IP address in SNI (unusual)")
        }
        
        // Check for suspicious TLDs
        val suspiciousTLDs = listOf(".tk", ".ml", ".ga", ".cf")
        if (suspiciousTLDs.any { serverName.endsWith(it, ignoreCase = true) }) {
            anomalies.add("Suspicious TLD in SNI")
        }
    }
    
    private fun isIPAddress(host: String): Boolean {
        return try {
            val parts = host.split(".")
            parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Analyze certificate for anomalies
     */
    fun analyzeCertificate(certificate: java.security.cert.X509Certificate): CertificateAnalysis {
        val anomalies = mutableListOf<String>()
        
        try {
            // Check validity period
            val now = System.currentTimeMillis()
            val notBefore = certificate.notBefore.time
            val notAfter = certificate.notAfter.time
            
            if (now < notBefore) {
                anomalies.add("Certificate not yet valid")
            }
            
            if (now > notAfter) {
                anomalies.add("Certificate expired")
            }
            
            val validityDays = (notAfter - notBefore) / (1000 * 60 * 60 * 24)
            if (validityDays > 365 * 2) {
                anomalies.add("Unusually long validity period (${validityDays} days)")
            }
            
            // Check issuer
            val issuer = certificate.issuerDN.name
            if (issuer.contains("Unknown") || issuer.contains("Self")) {
                anomalies.add("Self-signed or unknown issuer")
            }
            
            // Check subject
            val subject = certificate.subjectDN.name
            if (subject.isEmpty()) {
                anomalies.add("Empty certificate subject")
            }
            
            // Check for wildcard certificates
            val subjectAlternativeNames = certificate.subjectAlternativeNames
            if (subjectAlternativeNames != null) {
                subjectAlternativeNames.forEach { name ->
                    val nameStr = name.toString()
                    if (nameStr.startsWith("*")) {
                        anomalies.add("Wildcard certificate detected")
                    }
                }
            }
            
            // Check key size
            val publicKey = certificate.publicKey
            if (publicKey is java.security.interfaces.RSAPublicKey) {
                val keySize = publicKey.modulus.bitLength()
                if (keySize < 2048) {
                    anomalies.add("Weak RSA key size: $keySize bits")
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing certificate", e)
            anomalies.add("Error analyzing certificate: ${e.message}")
        }
        
        return CertificateAnalysis(
            isValid = anomalies.isEmpty(),
            anomalies = anomalies,
            issuer = try { certificate.issuerDN.name } catch (e: Exception) { null },
            subject = try { certificate.subjectDN.name } catch (e: Exception) { null },
            validityPeriod = try {
                certificate.notAfter.time - certificate.notBefore.time
            } catch (e: Exception) { null }
        )
    }
    
    /**
     * Check for content size pattern anomalies
     */
    fun checkContentSizePattern(size: Long, contentType: String?): Boolean {
        // Ransomware often downloads small payloads initially
        if (size < 1024 && contentType?.contains("application") == true) {
            return true
        }
        
        // Very large downloads from suspicious domains
        if (size > 100 * 1024 * 1024) { // 100 MB
            return true
        }
        
        return false
    }
}
