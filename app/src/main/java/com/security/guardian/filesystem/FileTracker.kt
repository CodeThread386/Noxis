package com.security.guardian.filesystem

import android.content.Context
import android.os.Environment
import android.util.Log
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.ThreatEvent
import com.security.guardian.detection.BehaviorDetectionEngine
import com.security.guardian.notification.ThreatNotificationService
import kotlinx.coroutines.*
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * Industry-grade file tracking and ransomware scanning system
 * Tracks all downloaded files and periodically scans existing files for ransomware
 */
class FileTracker(
    private val context: Context,
    private val database: RansomwareDatabase,
    private val detectionEngine: BehaviorDetectionEngine,
    private val notificationService: ThreatNotificationService
) {
    
    private val TAG = "FileTracker"
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    // Tracked files: file path -> FileMetadata
    private val trackedFiles = ConcurrentHashMap<String, FileMetadata>()
    
    // Directories to scan for existing files
    private val scanDirectories = listOf(
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM),
    )
    
    data class FileMetadata(
        val filePath: String,
        val fileName: String,
        val fileSize: Long,
        val fileHash: String, // SHA-256 hash
        val firstSeen: Long,
        val lastScanned: Long,
        val scanCount: Int,
        val isSuspicious: Boolean = false,
        val threatLevel: String = "SAFE",
        val indicators: List<String> = emptyList()
    )
    
    /**
     * Track a newly downloaded file
     */
    suspend fun trackDownloadedFile(file: File, source: String? = null) = withContext(Dispatchers.IO) {
        try {
            if (!file.exists() || file.length() == 0L) return@withContext
            
            val filePath = file.absolutePath
            val fileHash = calculateFileHash(file)
            
            // Check if file already tracked
            if (trackedFiles.containsKey(filePath)) {
                Log.d(TAG, "File already tracked: $filePath")
                return@withContext
            }
            
            // Immediate ransomware scan
            val scanResult = scanFileForRansomware(file, fileHash)
            
            val metadata = FileMetadata(
                filePath = filePath,
                fileName = file.name,
                fileSize = file.length(),
                fileHash = fileHash,
                firstSeen = System.currentTimeMillis(),
                lastScanned = System.currentTimeMillis(),
                scanCount = 1,
                isSuspicious = scanResult.isSuspicious,
                threatLevel = scanResult.threatLevel,
                indicators = scanResult.indicators
            )
            
            trackedFiles[filePath] = metadata
            
            // If suspicious, create threat event
            if (scanResult.isSuspicious) {
                createThreatEvent(file, scanResult, source)
            }
            
            Log.d(TAG, "Tracked file: ${file.name} (${file.length()} bytes, suspicious: ${scanResult.isSuspicious})")
        } catch (e: Exception) {
            Log.e(TAG, "Error tracking file: ${file.absolutePath}", e)
        }
    }
    
    /**
     * Scan file for ransomware indicators
     */
    private fun scanFileForRansomware(file: File, fileHash: String): ScanResult {
        val indicators = mutableListOf<String>()
        var threatLevel = "SAFE"
        var isSuspicious = false
        
        // Check 1: Entropy analysis (high entropy = encryption)
        val entropy = detectionEngine.calculateEntropy(file)
        if (entropy != null && entropy > 7.8) {
            indicators.add("High entropy detected (${String.format("%.2f", entropy)}) - possible encryption")
            threatLevel = "HIGH"
            isSuspicious = true
        }
        
        // Check 2: Magic bytes - check for executable files
        val magicBytes = detectionEngine.getFileMagicBytes(file)
        if (magicBytes != null && isExecutableFile(magicBytes)) {
            indicators.add("Executable file detected (magic bytes: ${magicBytes.joinToString { "%02x".format(it) }})")
            threatLevel = "MEDIUM"
            isSuspicious = true
        }
        
        // Check 3: Ransom note detection
        if (detectionEngine.checkRansomNotePattern(file)) {
            indicators.add("Ransom note pattern detected")
            threatLevel = "CRITICAL"
            isSuspicious = true
        }
        
        // Check 4: Suspicious filename
        if (isSuspiciousFilename(file.name)) {
            indicators.add("Suspicious filename: ${file.name}")
            if (threatLevel == "SAFE") threatLevel = "MEDIUM"
            isSuspicious = true
        }
        
        // Check 5: Extension mismatch (e.g., .pdf.exe)
        if (hasSuspiciousExtension(file.name)) {
            indicators.add("Suspicious file extension")
            if (threatLevel == "SAFE") threatLevel = "MEDIUM"
            isSuspicious = true
        }
        
        // Check 6: File size anomalies (very small or very large for type)
        val sizeAnomaly = checkSizeAnomaly(file)
        if (sizeAnomaly != null) {
            indicators.add(sizeAnomaly)
            if (threatLevel == "SAFE") threatLevel = "LOW"
        }
        
        return ScanResult(
            isSuspicious = isSuspicious,
            threatLevel = threatLevel,
            indicators = indicators,
            entropy = entropy,
            fileHash = fileHash
        )
    }
    
    /**
     * Periodically scan all existing files in monitored directories
     */
    fun startPeriodicScanning(intervalMinutes: Long = 60) {
        scope.launch {
            while (isActive) {
                try {
                    Log.d(TAG, "Starting periodic file scan...")
                    scanAllExistingFiles()
                    delay(intervalMinutes * 60 * 1000) // Wait for next scan
                } catch (e: Exception) {
                    Log.e(TAG, "Error in periodic scan", e)
                    delay(intervalMinutes * 60 * 1000) // Continue even if error
                }
            }
        }
    }
    
    /**
     * Scan all existing files in monitored directories
     */
    private suspend fun scanAllExistingFiles() = withContext(Dispatchers.IO) {
        var filesScanned = 0
        var threatsFound = 0
        
        scanDirectories.forEach { directory ->
            if (directory.exists() && directory.isDirectory) {
                try {
                    directory.listFiles()?.forEach { file ->
                        if (file.isFile && file.canRead()) {
                            try {
                                filesScanned++
                                val fileHash = calculateFileHash(file)
                                val existingMetadata = trackedFiles[file.absolutePath]
                                
                                // Only scan if file changed or never scanned before
                                val shouldScan = existingMetadata == null || 
                                               existingMetadata.fileHash != fileHash ||
                                               (System.currentTimeMillis() - existingMetadata.lastScanned) > (24 * 60 * 60 * 1000) // Re-scan after 24h
                                
                                if (shouldScan) {
                                    val scanResult = scanFileForRansomware(file, fileHash)
                                    
                                    val metadata = FileMetadata(
                                        filePath = file.absolutePath,
                                        fileName = file.name,
                                        fileSize = file.length(),
                                        fileHash = fileHash,
                                        firstSeen = existingMetadata?.firstSeen ?: System.currentTimeMillis(),
                                        lastScanned = System.currentTimeMillis(),
                                        scanCount = (existingMetadata?.scanCount ?: 0) + 1,
                                        isSuspicious = scanResult.isSuspicious,
                                        threatLevel = scanResult.threatLevel,
                                        indicators = scanResult.indicators
                                    )
                                    
                                    trackedFiles[file.absolutePath] = metadata
                                    
                                    if (scanResult.isSuspicious) {
                                        threatsFound++
                                        createThreatEvent(file, scanResult, null)
                                    }
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Error scanning file: ${file.absolutePath}", e)
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error scanning directory: ${directory.absolutePath}", e)
                }
            }
        }
        
        Log.d(TAG, "Periodic scan complete: Scanned $filesScanned files, found $threatsFound threats")
    }
    
    /**
     * Calculate SHA-256 hash of file
     */
    private fun calculateFileHash(file: File): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } > 0) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Error calculating hash", e)
            ""
        }
    }
    
    private fun isExecutableFile(magicBytes: ByteArray): Boolean {
        if (magicBytes.size < 4) return false
        
        // PE executable (Windows)
        if (magicBytes[0] == 0x4D.toByte() && magicBytes[1] == 0x5A.toByte()) return true
        // ELF executable (Linux/Android)
        if (magicBytes[0] == 0x7F.toByte() && magicBytes[1] == 0x45.toByte() && 
            magicBytes[2] == 0x4C.toByte() && magicBytes[3] == 0x46.toByte()) return true
        // Java class file
        if (magicBytes[0] == 0xCA.toByte() && magicBytes[1] == 0xFE.toByte() && 
            magicBytes[2] == 0xBA.toByte() && magicBytes[3] == 0xBE.toByte()) return true
        
        return false
    }
    
    private fun isSuspiciousFilename(filename: String): Boolean {
        val suspiciousPatterns = listOf(
            "decrypt",
            "readme",
            "how_to",
            "recover",
            "encrypted",
            "locked",
            "ransom",
            "bitcoin",
            "payment",
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".com"
        )
        val lowerFilename = filename.lowercase()
        return suspiciousPatterns.any { lowerFilename.contains(it) }
    }
    
    private fun hasSuspiciousExtension(filename: String): Boolean {
        val suspiciousExtensions = listOf(
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar",
            ".apk", ".deb", ".rpm" // Executable packages (if in wrong location)
        )
        val lowerFilename = filename.lowercase()
        return suspiciousExtensions.any { lowerFilename.endsWith(it) } &&
               // Check for double extension (e.g., .pdf.exe)
               filename.split(".").size > 2
    }
    
    private fun checkSizeAnomaly(file: File): String? {
        val extension = file.name.substringAfterLast('.', "").lowercase()
        val size = file.length()
        
        return when {
            // Very small files might be droppers
            size < 1024 && extension !in listOf("txt", "json", "xml") -> {
                "Unusually small file size for type"
            }
            // Very large text files (ransom notes are usually small)
            size > 10 * 1024 * 1024 && extension in listOf("txt", "html", "htm") -> {
                "Unusually large file size for text file"
            }
            else -> null
        }
    }
    
    private fun createThreatEvent(file: File, scanResult: ScanResult, source: String?) {
        scope.launch {
            try {
                val threat = ThreatEvent(
                    type = "FILE_RANSOMWARE_DETECTED",
                    packageName = source,
                    description = "Ransomware indicators detected in file: ${file.name}. ${scanResult.indicators.joinToString(", ")}",
                    severity = scanResult.threatLevel,
                    confidence = when (scanResult.threatLevel) {
                        "CRITICAL" -> 0.95f
                        "HIGH" -> 0.85f
                        "MEDIUM" -> 0.70f
                        "LOW" -> 0.50f
                        else -> 0.30f
                    },
                    timestamp = System.currentTimeMillis(),
                    status = "DETECTED",
                    indicators = scanResult.indicators.toString()
                )
                
                database.threatEventDao().insertThreat(threat)
                notificationService.notifyThreat(threat)
                
                Log.w(TAG, "Threat detected in file: ${file.name} - ${scanResult.indicators.joinToString()}")
            } catch (e: Exception) {
                Log.e(TAG, "Error creating threat event", e)
            }
        }
    }
    
    /**
     * Get all tracked files
     */
    fun getTrackedFiles(): List<FileMetadata> = trackedFiles.values.toList()
    
    /**
     * Get suspicious files
     */
    fun getSuspiciousFiles(): List<FileMetadata> = trackedFiles.values.filter { it.isSuspicious }
    
    /**
     * Get tracking statistics
     */
    fun getStats(): FileTrackingStats {
        val totalFiles = trackedFiles.size
        val suspiciousFiles = trackedFiles.values.count { it.isSuspicious }
        val totalScans = trackedFiles.values.sumOf { it.scanCount }
        
        return FileTrackingStats(
            totalFiles = totalFiles,
            suspiciousFiles = suspiciousFiles,
            totalScans = totalScans,
            lastScanTime = trackedFiles.values.maxOfOrNull { it.lastScanned } ?: 0L
        )
    }
    
    data class ScanResult(
        val isSuspicious: Boolean,
        val threatLevel: String, // SAFE, LOW, MEDIUM, HIGH, CRITICAL
        val indicators: List<String>,
        val entropy: Double?,
        val fileHash: String
    )
    
    data class FileTrackingStats(
        val totalFiles: Int,
        val suspiciousFiles: Int,
        val totalScans: Int,
        val lastScanTime: Long
    )
}
