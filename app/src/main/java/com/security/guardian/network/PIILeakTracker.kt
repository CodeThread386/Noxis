package com.security.guardian.network

import android.content.Context
import android.util.Log
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.ThreatEvent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.regex.Pattern

/**
 * Industry-grade PII (Personally Identifiable Information) leak detection
 * Detects SSN, credit cards, emails, passwords, API keys in network traffic
 */
class PIILeakTracker(private val context: Context) {
    
    private val TAG = "PIILeakTracker"
    private val database = RansomwareDatabase.getDatabase(context)
    private val detectedLeaks = mutableListOf<PIILeak>()
    
    data class PIILeak(
        val type: PIIType,
        val value: String, // Masked value
        val domain: String,
        val timestamp: Long,
        val packageName: String?,
        val severity: String
    )
    
    enum class PIIType {
        SSN,
        CREDIT_CARD,
        EMAIL,
        PASSWORD,
        API_KEY,
        PHONE_NUMBER,
        IP_ADDRESS
    }
    
    // Regex patterns for PII detection
    private val ssnPattern = Pattern.compile("\\b\\d{3}-?\\d{2}-?\\d{4}\\b")
    private val creditCardPattern = Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b")
    private val emailPattern = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b")
    private val passwordPattern = Pattern.compile("(password|passwd|pwd)\\s*[:=]\\s*([^\\s]{8,})", Pattern.CASE_INSENSITIVE)
    private val apiKeyPattern = Pattern.compile("(api[_-]?key|apikey|secret[_-]?key)\\s*[:=]\\s*([A-Za-z0-9]{20,})", Pattern.CASE_INSENSITIVE)
    private val phonePattern = Pattern.compile("\\b(\\+?1[-.]?)?\\(?([0-9]{3})\\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\\b")
    private val ipPattern = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b")
    
    /**
     * Scan data for PII leaks
     */
    suspend fun scanForPII(data: ByteArray, domain: String, packageName: String?): List<PIILeak> = withContext(Dispatchers.Default) {
        val leaks = mutableListOf<PIILeak>()
        val dataString = String(data, Charsets.UTF_8)
        
        // Check for SSN
        val ssnMatcher = ssnPattern.matcher(dataString)
        while (ssnMatcher.find()) {
            val ssn = ssnMatcher.group()
            if (isValidSSN(ssn)) {
                leaks.add(createLeak(PIIType.SSN, maskSSN(ssn), domain, packageName))
            }
        }
        
        // Check for credit cards
        val ccMatcher = creditCardPattern.matcher(dataString)
        while (ccMatcher.find()) {
            val cc = ccMatcher.group().replace(Regex("[\\s-]"), "")
            if (isValidCreditCard(cc)) {
                leaks.add(createLeak(PIIType.CREDIT_CARD, maskCreditCard(cc), domain, packageName))
            }
        }
        
        // Check for emails
        val emailMatcher = emailPattern.matcher(dataString)
        while (emailMatcher.find()) {
            val email = emailMatcher.group()
            leaks.add(createLeak(PIIType.EMAIL, email, domain, packageName))
        }
        
        // Check for passwords
        val passwordMatcher = passwordPattern.matcher(dataString)
        while (passwordMatcher.find()) {
            val password = passwordMatcher.group(2)
            leaks.add(createLeak(PIIType.PASSWORD, maskPassword(password), domain, packageName))
        }
        
        // Check for API keys
        val apiKeyMatcher = apiKeyPattern.matcher(dataString)
        while (apiKeyMatcher.find()) {
            val apiKey = apiKeyMatcher.group(2)
            leaks.add(createLeak(PIIType.API_KEY, maskAPIKey(apiKey), domain, packageName))
        }
        
        // Check for phone numbers
        val phoneMatcher = phonePattern.matcher(dataString)
        while (phoneMatcher.find()) {
            val phone = phoneMatcher.group()
            leaks.add(createLeak(PIIType.PHONE_NUMBER, maskPhone(phone), domain, packageName))
        }
        
        // Check for IP addresses (only private/internal IPs are suspicious)
        val ipMatcher = ipPattern.matcher(dataString)
        while (ipMatcher.find()) {
            val ip = ipMatcher.group()
            if (isPrivateIP(ip)) {
                leaks.add(createLeak(PIIType.IP_ADDRESS, ip, domain, packageName))
            }
        }
        
        // Store leaks and create threat events
        if (leaks.isNotEmpty()) {
            detectedLeaks.addAll(leaks)
            storeLeaks(leaks)
        }
        
        leaks
    }
    
    private fun createLeak(type: PIIType, value: String, domain: String, packageName: String?): PIILeak {
        val severity = when (type) {
            PIIType.SSN, PIIType.CREDIT_CARD, PIIType.PASSWORD, PIIType.API_KEY -> "CRITICAL"
            PIIType.EMAIL, PIIType.PHONE_NUMBER -> "HIGH"
            PIIType.IP_ADDRESS -> "MEDIUM"
        }
        
        return PIILeak(
            type = type,
            value = value,
            domain = domain,
            timestamp = System.currentTimeMillis(),
            packageName = packageName,
            severity = severity
        )
    }
    
    private suspend fun storeLeaks(leaks: List<PIILeak>) = withContext(Dispatchers.IO) {
        try {
            leaks.forEach { leak ->
                val threat = ThreatEvent(
                    type = "PII_LEAK",
                    packageName = leak.packageName,
                    description = "${leak.type} detected in traffic to ${leak.domain}: ${leak.value}",
                    severity = leak.severity,
                    confidence = 0.95f,
                    timestamp = leak.timestamp,
                    status = "DETECTED",
                    indicators = listOf(leak.type.name, leak.domain).toString(),
                    evidence = null
                )
                database.threatEventDao().insertThreat(threat)
            }
            Log.w(TAG, "Stored ${leaks.size} PII leaks")
        } catch (e: Exception) {
            Log.e(TAG, "Error storing PII leaks", e)
        }
    }
    
    /**
     * Get all detected PII leaks
     */
    fun getAllLeaks(): List<PIILeak> {
        return detectedLeaks.toList()
    }
    
    /**
     * Get leaks by type
     */
    fun getLeaksByType(type: PIIType): List<PIILeak> {
        return detectedLeaks.filter { it.type == type }
    }
    
    /**
     * Get leaks by domain
     */
    fun getLeaksByDomain(domain: String): List<PIILeak> {
        return detectedLeaks.filter { it.domain == domain }
    }
    
    /**
     * Get leak statistics
     */
    fun getLeakStats(): PIILeakStats {
        val total = detectedLeaks.size
        val byType = detectedLeaks.groupBy { it.type }.mapValues { it.value.size }
        val bySeverity = detectedLeaks.groupBy { it.severity }.mapValues { it.value.size }
        
        return PIILeakStats(
            totalLeaks = total,
            leaksByType = byType,
            leaksBySeverity = bySeverity,
            uniqueDomains = detectedLeaks.map { it.domain }.distinct().size
        )
    }
    
    data class PIILeakStats(
        val totalLeaks: Int,
        val leaksByType: Map<PIIType, Int>,
        val leaksBySeverity: Map<String, Int>,
        val uniqueDomains: Int
    )
    
    // Validation and masking functions
    private fun isValidSSN(ssn: String): Boolean {
        val cleaned = ssn.replace(Regex("[^0-9]"), "")
        if (cleaned.length != 9) return false
        // Check for obvious invalid patterns
        if (cleaned == "000000000" || cleaned.startsWith("000") || cleaned.substring(3, 5) == "00") {
            return false
        }
        return true
    }
    
    private fun isValidCreditCard(cc: String): Boolean {
        // Luhn algorithm check
        val digits = cc.map { it.toString().toInt() }
        var sum = 0
        var alternate = false
        for (i in digits.size - 1 downTo 0) {
            var n = digits[i]
            if (alternate) {
                n *= 2
                if (n > 9) n -= 9
            }
            sum += n
            alternate = !alternate
        }
        return sum % 10 == 0
    }
    
    private fun isPrivateIP(ip: String): Boolean {
        val parts = ip.split(".").map { it.toIntOrNull() ?: return false }
        if (parts.size != 4) return false
        return when {
            parts[0] == 10 -> true
            parts[0] == 172 && parts[1] in 16..31 -> true
            parts[0] == 192 && parts[1] == 168 -> true
            parts[0] == 127 -> true
            else -> false
        }
    }
    
    private fun maskSSN(ssn: String): String {
        val cleaned = ssn.replace(Regex("[^0-9]"), "")
        return "XXX-XX-${cleaned.takeLast(4)}"
    }
    
    private fun maskCreditCard(cc: String): String {
        val cleaned = cc.replace(Regex("[^0-9]"), "")
        return "****-****-****-${cleaned.takeLast(4)}"
    }
    
    private fun maskPassword(password: String): String {
        return "*".repeat(minOf(password.length, 8))
    }
    
    private fun maskAPIKey(key: String): String {
        return "${key.take(4)}...${key.takeLast(4)}"
    }
    
    private fun maskPhone(phone: String): String {
        val cleaned = phone.replace(Regex("[^0-9]"), "")
        return "XXX-XXX-${cleaned.takeLast(4)}"
    }
}
