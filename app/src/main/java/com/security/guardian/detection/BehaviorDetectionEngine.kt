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
        
        // Pattern 1: Rapid mass file modifications
        val recentModifications = recentEvents.filter { 
            it.eventType == EventType.MODIFIED && 
            System.currentTimeMillis() - it.timestamp < timeWindowMs 
        }
        if (recentModifications.size > 50) {
            indicators.add("Mass file modifications detected (${recentModifications.size} files in 1 minute)")
            confidence += 0.3f
        }
        
        // Pattern 2: Extension changes (e.g., .doc -> .locked)
        val extensionChanges = detectExtensionChanges(recentEvents)
        if (extensionChanges > 10) {
            indicators.add("Suspicious extension changes detected ($extensionChanges files)")
            confidence += 0.4f
        }
        
        // Pattern 3: High entropy in modified files (encryption indicator)
        val highEntropyFiles = recentModifications.filter { 
            it.entropy != null && it.entropy > 7.5 
        }
        if (highEntropyFiles.size > 20) {
            indicators.add("High entropy detected in ${highEntropyFiles.size} files (possible encryption)")
            confidence += 0.5f
        }
        
        // Pattern 4: Rapid file creation followed by modification
        val createModifyPattern = detectCreateModifyPattern(recentEvents)
        if (createModifyPattern) {
            indicators.add("Rapid create-modify pattern detected (ransomware behavior)")
            confidence += 0.3f
        }
        
        // Pattern 5: Mass deletions
        val deletions = recentEvents.filter { 
            it.eventType == EventType.DELETED && 
            System.currentTimeMillis() - it.timestamp < timeWindowMs 
        }
        if (deletions.size > 30) {
            indicators.add("Mass file deletions detected (${deletions.size} files)")
            confidence += 0.2f
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
        val isSuspicious = confidence >= 0.3f || mlResult.isRansomware
        
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
            confidence = combinedConfidence,
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
    
    private fun detectExtensionChanges(events: List<FileChangeEvent>): Int {
        val renamedFiles = events.filter { it.eventType == EventType.RENAMED }
        // Simplified: count renames that might indicate extension changes
        return renamedFiles.size
    }
    
    private fun detectCreateModifyPattern(events: List<FileChangeEvent>): Boolean {
        val recentWindow = events.filter { 
            System.currentTimeMillis() - it.timestamp < timeWindowMs 
        }
        
        val creates = recentWindow.filter { it.eventType == EventType.CREATED }
        val modifies = recentWindow.filter { it.eventType == EventType.MODIFIED }
        
        // If many files are created and then quickly modified, it's suspicious
        return creates.size > 20 && modifies.size > 20 && 
               creates.size.toFloat() / modifies.size.toFloat() > 0.5f
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
