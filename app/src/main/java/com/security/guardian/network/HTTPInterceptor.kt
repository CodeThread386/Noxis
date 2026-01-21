package com.security.guardian.network

import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * HTTP/HTTPS request interceptor for ad blocking
 * Extracts URLs and hostnames from HTTP requests and HTTPS SNI
 */
class HTTPInterceptor {
    
    private val TAG = "HTTPInterceptor"
    
    /**
     * Extract HTTP host and URL from packet data
     */
    fun extractHTTPRequest(packet: ByteArray, length: Int): HTTPRequest? {
        if (length < 20) return null
        
        try {
            val data = String(packet, 0, length, Charsets.UTF_8)
            
            // Check if this is an HTTP request
            if (!data.startsWith("GET ") && !data.startsWith("POST ") && 
                !data.startsWith("PUT ") && !data.startsWith("HEAD ")) {
                return null
            }
            
            // Extract Host header
            val hostMatch = Regex("Host:\\s*([^\\r\\n]+)").find(data)
            val host = hostMatch?.groupValues?.get(1)?.trim() ?: return null
            
            // Extract URL path
            val urlMatch = Regex("^(GET|POST|PUT|HEAD)\\s+([^\\s]+)").find(data)
            val path = urlMatch?.groupValues?.get(2) ?: "/"
            
            // Extract full URL
            val fullUrl = if (path.startsWith("http")) {
                path
            } else {
                val scheme = if (data.contains("HTTP/1.1") || data.contains("HTTP/2")) "https" else "http"
                "$scheme://$host$path"
            }
            
            return HTTPRequest(
                host = host,
                path = path,
                fullUrl = fullUrl,
                method = urlMatch?.groupValues?.get(1) ?: "GET"
            )
        } catch (e: Exception) {
            // Not a valid HTTP request or encoding issue
            return null
        }
    }
    
    /**
     * Extract domain from DNS query (if packet is DNS)
     */
    fun extractDNSQuery(packet: ByteArray, length: Int): String? {
        if (length < 12) return null
        
        try {
            val buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN)
            
            // Check DNS header (port 53)
            val flags = buffer.getShort(2).toInt() and 0xFFFF
            
            // Check if this is a DNS query (QR bit = 0)
            if ((flags and 0x8000) != 0) return null // Response, not query
            
            // Extract domain name from DNS query
            val domain = extractDomainFromDNS(buffer, 12)
            return domain
        } catch (e: Exception) {
            return null
        }
    }
    
    private fun extractDomainFromDNS(buffer: ByteBuffer, offset: Int): String? {
        val domainParts = mutableListOf<String>()
        var pos = offset
        
        try {
            while (pos < buffer.limit() && pos < offset + 255) {
                val length = buffer.get(pos).toInt() and 0xFF
                
                if (length == 0) break // End of domain
                if (length >= 0xC0) {
                    // Compression pointer
                    val pointer = ((length and 0x3F) shl 8) or (buffer.get(pos + 1).toInt() and 0xFF)
                    val compressed = extractDomainFromDNS(buffer, pointer)
                    if (compressed != null) domainParts.addAll(compressed.split("."))
                    break
                }
                
                if (length > 63) break // Invalid
                
                val label = ByteArray(length)
                buffer.position(pos + 1)
                buffer.get(label)
                domainParts.add(String(label, Charsets.UTF_8))
                pos += length + 1
            }
            
            return if (domainParts.isNotEmpty()) domainParts.joinToString(".") else null
        } catch (e: Exception) {
            return null
        }
    }
    
    data class HTTPRequest(
        val host: String,
        val path: String,
        val fullUrl: String,
        val method: String
    )
}
