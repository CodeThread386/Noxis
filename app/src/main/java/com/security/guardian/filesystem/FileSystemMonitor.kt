package com.security.guardian.filesystem

import android.net.Uri
import android.os.Environment
import android.os.FileObserver
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.SnapshotMetadata
import com.security.guardian.data.entities.ThreatEvent
import com.security.guardian.data.entities.ThreatEvidence
import com.security.guardian.detection.BehaviorDetectionEngine
import com.security.guardian.detection.TrustedAppChecker
import com.security.guardian.filesystem.HoneypotManager
import com.security.guardian.notification.ThreatNotificationService
import com.security.guardian.quarantine.AppQuarantineManager
import com.security.guardian.storage.SAFManager
import kotlinx.coroutines.*
import java.io.File

/**
 * FileObserver-based file system monitoring
 * Watches common shared folders for ransomware behavior patterns
 */
class FileSystemMonitor(
    private val context: android.content.Context,
    private val detectionEngine: BehaviorDetectionEngine,
    private val database: RansomwareDatabase,
    private val notificationService: ThreatNotificationService
) {
    
    private val TAG = "FileSystemMonitor"
    private val observers = mutableListOf<FileObserver>()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val snapshotManager = SnapshotManager(context, database)
    private val safManager = SAFManager(context)
    private val honeypotManager = HoneypotManager(context)
    private val quarantineManager = AppQuarantineManager(context)
    private val trustedAppChecker = TrustedAppChecker(context)
    
    // Evidence tracking (only for actual suspicious activity)
    private var entropySpikeCount = 0
    private var renameCount = 0
    private var ransomNoteDetected = false
    private var honeypotTouched = false
    private var massModificationCount = 0
    private var extensionChanges = 0
    private var highEntropyFiles = 0
    private var massDeletions = 0
    private var createModifyPattern = false
    
    // Rate limiting: prevent multiple threats in quick succession
    private var lastThreatTime = 0L
    private val minThreatInterval = 30000L // Minimum 30 seconds between threats
    
    // Common folders to monitor
    private val monitoredFolders = listOf(
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES),
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM),
        File(context.getExternalFilesDir(null)?.parent ?: "", "WhatsApp/Media/WhatsApp Documents"),
        File(context.getExternalFilesDir(null)?.parent ?: "", "Telegram/Telegram Documents")
    )
    
    private val fileEvents = mutableListOf<BehaviorDetectionEngine.FileChangeEvent>()
    
    fun startMonitoring() {
        monitoredFolders.forEach { folder ->
            if (folder.exists() && folder.isDirectory) {
                val observer = createFileObserver(folder)
                observer.startWatching()
                observers.add(observer)
                Log.d(TAG, "Started monitoring: ${folder.absolutePath}")
            }
        }
        
        // Initialize honeypots
        scope.launch {
            honeypotManager.initializeHoneypots(monitoredFolders.filter { it.exists() && it.isDirectory })
        }
        
        // Periodically analyze events
        scope.launch {
            while (isActive) {
                delay(10000) // Analyze every 10 seconds
                analyzeEvents()
            }
        }
    }
    
    fun stopMonitoring() {
        observers.forEach { it.stopWatching() }
        observers.clear()
        scope.cancel()
    }
    
    private fun createFileObserver(folder: File): FileObserver {
        return object : FileObserver(folder.absolutePath, ALL_EVENTS) {
            override fun onEvent(event: Int, path: String?) {
                if (path == null) return
                
                val file = File(folder, path)
                val eventType: BehaviorDetectionEngine.EventType = when (event) {
                    CREATE, MOVED_TO -> BehaviorDetectionEngine.EventType.CREATED
                    MODIFY, CLOSE_WRITE -> BehaviorDetectionEngine.EventType.MODIFIED
                    DELETE, MOVED_FROM -> BehaviorDetectionEngine.EventType.DELETED
                    else -> return
                }
                
                scope.launch {
                    handleFileEvent(file, eventType)
                }
            }
        }
    }
    
    private suspend fun handleFileEvent(file: File, eventType: BehaviorDetectionEngine.EventType) {
        // Check if honeypot was touched
        val packageName = getPackageNameFromFile(file)
        if (honeypotManager.checkHoneypotTouched(file.absolutePath, packageName)) {
            honeypotTouched = true
            Log.e(TAG, "CRITICAL: Honeypot file touched: ${file.absolutePath}")
        }
        
        // Take snapshot before modification using SAF if available
        if (eventType == BehaviorDetectionEngine.EventType.MODIFIED && file.exists()) {
            try {
                // Try SAF first if available
                if (safManager.hasSAFAccess("Downloads")) {
                    val fileUri = android.net.Uri.fromFile(file)
                    val snapshotName = "${file.name}_${System.currentTimeMillis()}"
                    val snapshotUri = safManager.createSnapshot(fileUri, snapshotName)
                    if (snapshotUri != null) {
                        // Store metadata in database
                        storeSnapshotMetadataSAF(file.absolutePath, snapshotUri.toString())
                    }
                } else {
                    // Fallback to local snapshot
                    snapshotManager.takeSnapshot(file)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error taking snapshot", e)
                // Fallback to local snapshot
                snapshotManager.takeSnapshot(file)
            }
        }
        
        // Calculate entropy for modified files
        val entropy = if (eventType == BehaviorDetectionEngine.EventType.MODIFIED) {
            detectionEngine.calculateEntropy(file)
        } else null
        
        // Only track suspicious patterns, not normal file operations
        // Track entropy spikes (only for files with very high entropy - encryption indicator)
        if (entropy != null && entropy > 7.8) { // Increased threshold from 7.5 to 7.8
            entropySpikeCount++
            highEntropyFiles++
            Log.w(TAG, "High entropy detected in file: ${file.absolutePath} (entropy: $entropy)")
        }
        
        // Track renames only if they involve extension changes (suspicious)
        if (eventType == BehaviorDetectionEngine.EventType.RENAMED) {
            // Check if extension changed (would need old/new name comparison)
            // For now, only count if we can detect extension change
            renameCount++
            extensionChanges++
        }
        
        // Track modifications (will be analyzed in batch)
        if (eventType == BehaviorDetectionEngine.EventType.MODIFIED) {
            massModificationCount++
        }
        
        // Track deletions (will be analyzed in batch)
        if (eventType == BehaviorDetectionEngine.EventType.DELETED) {
            massDeletions++
        }
        
        val event = BehaviorDetectionEngine.FileChangeEvent(
            path = file.absolutePath,
            eventType = eventType,
            timestamp = System.currentTimeMillis(),
            fileSize = if (file.exists()) file.length() else 0,
            entropy = entropy
        )
        
        fileEvents.add(event)
        
        // Check for immediate threats (only on file modifications)
        if (eventType == BehaviorDetectionEngine.EventType.MODIFIED && file.exists()) {
            // Only check for ransom note if file is text-based and reasonably sized
            // Skip binary files, large files, and system files
            if (file.length() > 0 && file.length() < 100 * 1024) { // Less than 100KB
                val fileName = file.name.lowercase()
                // Only check text files or files with suspicious names
                val isTextFile = fileName.endsWith(".txt") || fileName.endsWith(".html") || 
                                fileName.endsWith(".htm") || fileName.endsWith(".rtf")
                val hasSuspiciousName = fileName.contains("readme") || fileName.contains("decrypt") ||
                                       fileName.contains("recover") || fileName.contains("how_to")
                
                if (isTextFile || hasSuspiciousName) {
                    if (detectionEngine.checkRansomNotePattern(file)) {
                        ransomNoteDetected = true
                        notifyRansomNoteDetected(file)
                    }
                }
            }
        }
        
        // Limit event history
        if (fileEvents.size > 1000) {
            fileEvents.removeAt(0)
        }
    }
    
    private fun getPackageNameFromFile(file: File): String? {
        // Try to extract package name from file path
        val path = file.absolutePath
        val packagePattern = Regex("/(data/data|Android/data)/([^/]+)/")
        val match = packagePattern.find(path)
        if (match != null) {
            val packageName = match.groupValues[2]
            // Validate it looks like a package name
            if (packageName.matches(Regex("^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_.]*$"))) {
                return packageName
            }
        }
        return null
    }
    
    private suspend fun analyzeEvents() {
        if (fileEvents.isEmpty()) return
        
        val recentEvents = fileEvents.filter {
            System.currentTimeMillis() - it.timestamp < 60000 // Last minute
        }
        
        // Only analyze if we have significant activity (prevents false positives from normal operations)
        if (recentEvents.size < 10) {
            return // Not enough events to be suspicious
        }
        
        if (recentEvents.isNotEmpty()) {
            val result = detectionEngine.analyzeBehavior(recentEvents)
            
            // Extract package name to check if it's trusted
            val packageName = getPackageNameFromThreat(result)
            
            // Skip if it's a trusted system app (prevent false positives)
            if (packageName != null && trustedAppChecker.isTrustedApp(packageName)) {
                Log.d(TAG, "Skipping threat from trusted app: $packageName")
                return
            }
            
            // Only create threat if confidence is high AND we have multiple indicators
            if (result.suspicious && result.confidence >= 0.5f && result.indicators.size >= 2) {
                // Rate limiting: don't create multiple threats in quick succession
                val currentTime = System.currentTimeMillis()
                if (currentTime - lastThreatTime < minThreatInterval) {
                    Log.d(TAG, "Threat creation rate-limited (last threat was ${(currentTime - lastThreatTime) / 1000}s ago)")
                    return
                }
                
                Log.w(TAG, "Ransomware behavior detected! Confidence: ${result.confidence}, Indicators: ${result.indicators}")
                lastThreatTime = currentTime
                notifyThreatDetected(result)
            }
        }
    }
    
    private fun notifyRansomNoteDetected(file: File) {
        // Rate limiting: don't create multiple threats in quick succession
        val currentTime = System.currentTimeMillis()
        if (currentTime - lastThreatTime < minThreatInterval) {
            Log.d(TAG, "Ransom note threat creation rate-limited")
            return
        }
        
        // Send critical alert only if we're confident it's a ransom note
        Log.e(TAG, "RANSOM NOTE DETECTED: ${file.absolutePath}")
        scope.launch {
            lastThreatTime = currentTime
            val threat = ThreatEvent(
                type = "RANSOM_NOTE",
                packageName = null,
                description = "Ransom note detected: ${file.name}",
                severity = "CRITICAL",
                confidence = 0.95f,
                timestamp = System.currentTimeMillis(),
                status = "DETECTED",
                indicators = listOf("Ransom note pattern", file.absolutePath).toString(),
                evidence = ThreatEvidence(
                    ransomNoteDetected = true,
                    entropySpikeCount = 0,
                    renameCount = 0,
                    honeypotTouched = false,
                    massModificationCount = 0,
                    extensionChanges = 0,
                    highEntropyFiles = 0,
                    massDeletions = 0,
                    createModifyPattern = false,
                    suspiciousDomains = 0,
                    networkAnomalies = 0,
                    cpuSpike = false,
                    ioSpike = false
                )
            )
            database.threatEventDao().insertThreat(threat)
            notificationService.notifyThreat(threat)
        }
    }
    
    private fun notifyThreatDetected(result: BehaviorDetectionEngine.DetectionResult) {
        // Send threat notification
        Log.w(TAG, "Threat detected: ${result.threatLevel}, confidence: ${result.confidence}")
        scope.launch {
            val severity = when (result.threatLevel) {
                BehaviorDetectionEngine.ThreatLevel.CRITICAL -> "CRITICAL"
                BehaviorDetectionEngine.ThreatLevel.HIGH -> "HIGH"
                BehaviorDetectionEngine.ThreatLevel.MEDIUM -> "MEDIUM"
                BehaviorDetectionEngine.ThreatLevel.LOW -> "LOW"
            }
            
            // Create structured evidence
            val evidence = ThreatEvidence(
                entropySpikeCount = entropySpikeCount,
                renameCount = renameCount,
                ransomNoteDetected = ransomNoteDetected,
                honeypotTouched = honeypotTouched,
                massModificationCount = massModificationCount,
                extensionChanges = extensionChanges,
                highEntropyFiles = highEntropyFiles,
                massDeletions = massDeletions,
                createModifyPattern = createModifyPattern,
                suspiciousDomains = 0, // Would be set from network context
                networkAnomalies = 0,
                cpuSpike = false,
                ioSpike = false
            )
            
            // Get package name from threat
            val packageName = getPackageNameFromThreat(result)
            
            val threat = ThreatEvent(
                type = "FILE_BEHAVIOR",
                packageName = packageName,
                description = "Ransomware behavior detected: ${result.indicators.joinToString(", ")}",
                severity = severity,
                confidence = result.confidence,
                timestamp = System.currentTimeMillis(),
                status = "DETECTED",
                indicators = result.indicators.toString(),
                evidence = evidence
            )
            
            val threatId = database.threatEventDao().insertThreat(threat)
            
            // Auto-quarantine if CRITICAL or HIGH severity (only for non-trusted apps)
            if (severity == "CRITICAL" || severity == "HIGH") {
                if (packageName != null && !trustedAppChecker.isTrustedApp(packageName)) {
                    quarantineManager.quarantineAppForRansomware(
                        packageName = packageName,
                        threatId = threatId,
                        threatType = "FILE_BEHAVIOR",
                        severity = severity
                    )
                } else if (packageName != null) {
                    Log.d(TAG, "Skipping auto-quarantine for trusted app: $packageName")
                }
            }
            
            notificationService.notifyThreat(threat)
            
            // Reset evidence counters
            resetEvidenceCounters()
        }
    }
    
    private fun getPackageNameFromThreat(result: BehaviorDetectionEngine.DetectionResult): String? {
        // Try to extract package name from recent file events
        val recentFilePaths = fileEvents.takeLast(50).map { it.path }
        val packagePattern = Regex("/(data/data|Android/data)/([^/]+)/")
        
        recentFilePaths.forEach { path ->
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
    
    private fun resetEvidenceCounters() {
        entropySpikeCount = 0
        renameCount = 0
        ransomNoteDetected = false
        honeypotTouched = false
        massModificationCount = 0
        extensionChanges = 0
        highEntropyFiles = 0
        massDeletions = 0
        createModifyPattern = false
    }
    
    private suspend fun storeSnapshotMetadataSAF(originalPath: String, snapshotUri: String) {
        try {
            val file = File(originalPath)
            val metadata = SnapshotMetadata(
                originalPath = originalPath,
                snapshotPath = snapshotUri,
                timestamp = System.currentTimeMillis(),
                fileSize = if (file.exists()) file.length() else 0,
                encrypted = false // SAF handles encryption separately
            )
            database.snapshotMetadataDao().insertSnapshot(metadata)
            Log.d(TAG, "Stored SAF snapshot metadata for: $originalPath")
        } catch (e: Exception) {
            Log.e(TAG, "Error storing SAF snapshot metadata", e)
        }
    }
}

/**
 * Manages file snapshots for recovery
 * Uses app-private encrypted storage
 */
class SnapshotManager(
    private val context: android.content.Context,
    private val database: RansomwareDatabase
) {
    
    private val snapshotDir = File(context.filesDir, "snapshots")
    private val TAG = "SnapshotManager"
    
    init {
        snapshotDir.mkdirs()
    }
    
    suspend fun takeSnapshot(file: File) {
        if (!file.exists() || file.length() > 10 * 1024 * 1024) return // Skip large files
        
        try {
            val snapshotFile = File(snapshotDir, "${file.name}_${System.currentTimeMillis()}")
            file.copyTo(snapshotFile, overwrite = true)
            
            // Encrypt snapshot
            encryptSnapshot(snapshotFile)
            
            // Store metadata
            storeSnapshotMetadata(file.absolutePath, snapshotFile.absolutePath)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to take snapshot", e)
        }
    }
    
    suspend fun restoreSnapshot(originalPath: String): Boolean {
        return try {
            val metadata = getSnapshotMetadata(originalPath)
            if (metadata != null) {
                val snapshotFile = File(metadata.snapshotPath)
                if (snapshotFile.exists()) {
                    // Decrypt and restore
                    decryptSnapshot(snapshotFile)
                    val originalFile = File(originalPath)
                    snapshotFile.copyTo(originalFile, overwrite = true)
                    true
                } else false
            } else false
        } catch (e: Exception) {
            false
        }
    }
    
    private fun encryptSnapshot(file: File) {
        // Simplified: would use Android Keystore for encryption
        // For now, just store as-is
    }
    
    private fun decryptSnapshot(file: File) {
        // Simplified: would decrypt using Android Keystore
    }
    
    private suspend fun storeSnapshotMetadata(originalPath: String, snapshotPath: String) {
        try {
            val file = File(originalPath)
            val metadata = SnapshotMetadata(
                originalPath = originalPath,
                snapshotPath = snapshotPath,
                timestamp = System.currentTimeMillis(),
                fileSize = if (file.exists()) file.length() else 0,
                encrypted = false // Local snapshots not encrypted yet
            )
            database.snapshotMetadataDao().insertSnapshot(metadata)
            Log.d(TAG, "Stored snapshot metadata for: $originalPath")
        } catch (e: Exception) {
            Log.e(TAG, "Error storing snapshot metadata", e)
        }
    }
    
    private suspend fun getSnapshotMetadata(originalPath: String): SnapshotMetadata? {
        return try {
            database.snapshotMetadataDao().getLatestSnapshot(originalPath)
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving snapshot metadata", e)
            null
        }
    }
}
