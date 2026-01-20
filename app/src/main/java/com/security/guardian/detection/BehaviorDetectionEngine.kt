package com.security.guardian.detection

import android.content.Context
import com.security.guardian.ml.RansomwareClassifier
import java.io.File
import java.security.MessageDigest
import kotlin.math.log2

/**
 * Core behavior-based ransomware detection engine
 * Detects suspicious patterns: rapid encryption, mass renames, entropy spikes
 * Now integrated with ML classifier for enhanced detection
 */
class BehaviorDetectionEngine(private val context: Context) {
    
    private val mlClassifier = RansomwareClassifier(context)
    private val trustedAppChecker = TrustedAppChecker(context)
    
    data class DetectionResult(
        val suspicious: Boolean,
        val confidence: Float, // 0.0 to 1.0
        val indicators: List<String>,
        val threatLevel: ThreatLevel
    )
    
    enum class ThreatLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    data class FileChangeEvent(
        val path: String,
        val eventType: EventType,
        val timestamp: Long,
        val fileSize: Long = 0,
        val entropy: Double? = null
    )
    
    enum class EventType {
        CREATED, MODIFIED, DELETED, RENAMED
    }
    
    private val recentEvents = mutableListOf<FileChangeEvent>()
    private val maxEventHistory = 1000
    private val timeWindowMs = 60000L // 1 minute window
    
    /**
     * Analyze file change events for ransomware patterns
     */
    fun analyzeBehavior(events: List<FileChangeEvent>): DetectionResult {
        recentEvents.addAll(events)
        if (recentEvents.size > maxEventHistory) {
            recentEvents.removeAt(0)
        }
        
        val indicators = mutableListOf<String>()
        var confidence = 0.0f
        
        val currentTime = System.currentTimeMillis()
        val timeWindowStart = currentTime - timeWindowMs
        
        // Pattern 1: Rapid mass file modifications (INCREASED THRESHOLD)
        val recentModifications = recentEvents.filter { 
            it.eventType == EventType.MODIFIED && 
            it.timestamp >= timeWindowStart
        }
        // Increased threshold from 50 to 100 files per minute (more realistic)
        if (recentModifications.size > 100) {
            indicators.add("Mass file modifications detected (${recentModifications.size} files in 1 minute)")
            confidence += 0.4f
        }
        
        // Pattern 2: Extension changes (e.g., .doc -> .locked) (INCREASED THRESHOLD)
        val extensionChanges = detectExtensionChanges(recentEvents.filter { it.timestamp >= timeWindowStart })
        // Increased threshold from 10 to 20 extension changes
        if (extensionChanges > 20) {
            indicators.add("Suspicious extension changes detected ($extensionChanges files)")
            confidence += 0.5f
        }
        
        // Pattern 3: High entropy in modified files (encryption indicator) (INCREASED THRESHOLD)
        val highEntropyFiles = recentModifications.filter { 
            it.entropy != null && it.entropy > 7.8 // Increased from 7.5 to 7.8
        }
        // Increased threshold from 20 to 50 high entropy files
        if (highEntropyFiles.size > 50) {
            indicators.add("High entropy detected in ${highEntropyFiles.size} files (possible encryption)")
            confidence += 0.6f
        }
        
        // Pattern 4: Rapid file creation followed by modification (STRICTER)
        val createModifyPattern = detectCreateModifyPattern(recentEvents.filter { it.timestamp >= timeWindowStart })
        if (createModifyPattern) {
            indicators.add("Rapid create-modify pattern detected (ransomware behavior)")
            confidence += 0.4f
        }
        
        // Pattern 5: Mass deletions (INCREASED THRESHOLD)
        val deletions = recentEvents.filter { 
            it.eventType == EventType.DELETED && 
            it.timestamp >= timeWindowStart
        }
        // Increased threshold from 30 to 50 deletions
        if (deletions.size > 50) {
            indicators.add("Mass file deletions detected (${deletions.size} files)")
            confidence += 0.3f
        }
        
        confidence = confidence.coerceIn(0.0f, 1.0f)
        
        // Enhance with ML classification
        val mlFeatures = RansomwareClassifier.BehaviorFeatures(
            fileModificationsPerMinute = recentModifications.size.toFloat(),
            extensionChanges = extensionChanges.toFloat(),
            highEntropyFiles = highEntropyFiles.size.toFloat(),
            massDeletions = deletions.size.toFloat(),
            createModifyPattern = if (createModifyPattern) 1f else 0f,
            suspiciousPermissions = 0f, // Would need package context
            overlayDetected = 0f, // Would need accessibility context
            networkAnomaly = 0f, // Would need network context
            cpuUsage = 0f, // Would need UsageStats
            ioOperations = recentModifications.size.toFloat(),
            fileSizeChanges = recentModifications.sumOf { it.fileSize }.toFloat(),
            renameOperations = extensionChanges.toFloat(),
            encryptionIndicators = highEntropyFiles.size.toFloat(),
            ransomNoteDetected = 0f, // Checked separately
            suspiciousDomains = 0f, // Would need network context
            downloadAnomaly = 0f, // Would need download context
            processAnomaly = 0f, // Would need process context
            memoryAnomaly = 0f, // Would need memory context
            timeOfDay = (System.currentTimeMillis() % (24 * 60 * 60 * 1000)).toFloat() / (24 * 60 * 60 * 1000),
            userInteraction = 0.5f // Default assumption
        )
        
        val mlResult = mlClassifier.classify(mlFeatures)
        
        // Combine heuristic and ML confidence
        val combinedConfidence = (confidence * 0.6f + mlResult.confidence * 0.4f).coerceIn(0.0f, 1.0f)
        
        // Extract package name from events to check if it's a trusted app
        val packageName = extractPackageNameFromEvents(recentEvents)
        val isTrusted = packageName != null && trustedAppChecker.isTrustedApp(packageName)
        
        // Adjust confidence based on trust level
        val adjustedConfidence = if (isTrusted) {
            // Reduce confidence significantly for trusted apps (70% reduction)
            // Only flag trusted apps if confidence is VERY high (0.8+)
            combinedConfidence * 0.3f
        } else {
            combinedConfidence
        }
        
        // INCREASED THRESHOLD: Only mark as suspicious if confidence is HIGH (0.5+) or ML says ransomware
        // For trusted apps, require even higher confidence (0.8+) to prevent false positives
        val threshold = if (isTrusted) 0.8f else 0.5f
        val isSuspicious = adjustedConfidence >= threshold || 
                          (mlResult.isRansomware && mlResult.confidence >= 0.7f && !isTrusted)
        
        // Log if we're filtering out a trusted app
        if (isTrusted && combinedConfidence >= 0.5f && adjustedConfidence < threshold) {
            android.util.Log.d("BehaviorDetectionEngine", 
                "Filtered out trusted app $packageName (confidence: $combinedConfidence -> $adjustedConfidence)")
        }
        
        val threatLevel = when {
            combinedConfidence >= 0.7f -> ThreatLevel.CRITICAL
            combinedConfidence >= 0.5f -> ThreatLevel.HIGH
            combinedConfidence >= 0.3f -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        if (mlResult.isRansomware) {
            indicators.add("ML Classifier: Ransomware detected (confidence: ${mlResult.confidence})")
        }
        
        return DetectionResult(
            suspicious = isSuspicious,
            confidence = adjustedConfidence,
            indicators = indicators,
            threatLevel = threatLevel
        )
    }
    
    /**
     * Calculate Shannon entropy of file content
     */
    fun calculateEntropy(file: File): Double? {
        return try {
            if (!file.exists() || file.length() == 0L) return null
            
            val bytes = file.readBytes()
            if (bytes.isEmpty()) return null
            
            val frequency = IntArray(256)
            bytes.forEach { byte ->
                frequency[byte.toInt() and 0xFF]++
            }
            
            var entropy = 0.0
            val length = bytes.size.toDouble()
            
            for (count in frequency) {
                if (count > 0) {
                    val probability = count / length
                    entropy -= probability * log2(probability)
                }
            }
            
            entropy
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Extract package name from file events (if possible)
     */
    private fun extractPackageNameFromEvents(events: List<FileChangeEvent>): String? {
        // Try to extract package name from file paths
        // Common patterns: /data/data/com.package.name/, /storage/emulated/0/Android/data/com.package.name/
        val paths = events.map { it.path }
        val packagePattern = Regex("/(data/data|Android/data)/([^/]+)/")
        
        paths.forEach { path ->
            val match = packagePattern.find(path)
            if (match != null) {
                val packageName = match.groupValues[2]
                // Validate it looks like a package name
                if (packageName.matches(Regex("^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_.]*$"))) {
                    return packageName
                }
            }
        }
        return null
    }
    
    private fun detectExtensionChanges(events: List<FileChangeEvent>): Int {
        val renamedFiles = events.filter { it.eventType == EventType.RENAMED }
        // Simplified: count renames that might indicate extension changes
        return renamedFiles.size
    }
    
    private fun detectCreateModifyPattern(events: List<FileChangeEvent>): Boolean {
        val creates = events.filter { it.eventType == EventType.CREATED }
        val modifies = events.filter { it.eventType == EventType.MODIFIED }
        
        // STRICTER: Check if many files were created and then modified quickly
        // This is a strong ransomware indicator
        // Increased thresholds: need at least 30 creates and 30 modifies, total 80+ events
        return creates.size > 30 && modifies.size > 30 && creates.size + modifies.size > 80
    }
    
    /**
     * Check if file content matches known ransomware patterns
     */
    fun checkRansomNotePattern(file: File): Boolean {
        return try {
            if (!file.exists() || file.length() > 1024 * 1024) return false // Skip large files
            
            val content = file.readText(Charsets.UTF_8).lowercase()
            val ransomKeywords = listOf(
                "your files have been encrypted",
                "pay bitcoin",
                "decrypt your files",
                "ransom",
                "payment required",
                "your data is locked"
            )
            
            ransomKeywords.any { keyword -> content.contains(keyword) }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get file magic bytes for type detection
     */
    fun getFileMagicBytes(file: File): ByteArray? {
        return try {
            if (!file.exists() || file.length() < 4) return null
            file.inputStream().use { 
                val bytes = ByteArray(4)
                it.read(bytes)
                bytes
            }
        } catch (e: Exception) {
            null
        }
    }
}
