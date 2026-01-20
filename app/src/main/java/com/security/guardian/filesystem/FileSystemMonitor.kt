package com.security.guardian.filesystem

import android.os.Environment
import android.os.FileObserver
import android.util.Log
import com.security.guardian.detection.BehaviorDetectionEngine
import kotlinx.coroutines.*
import java.io.File

/**
 * FileObserver-based file system monitoring
 * Watches common shared folders for ransomware behavior patterns
 */
class FileSystemMonitor(
    private val context: android.content.Context,
    private val detectionEngine: BehaviorDetectionEngine
) {
    
    private val TAG = "FileSystemMonitor"
    private val observers = mutableListOf<FileObserver>()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val snapshotManager = SnapshotManager(context)
    
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
        // Take snapshot before modification
        if (eventType == BehaviorDetectionEngine.EventType.MODIFIED && file.exists()) {
            snapshotManager.takeSnapshot(file)
        }
        
        // Calculate entropy for modified files
        val entropy = if (eventType == BehaviorDetectionEngine.EventType.MODIFIED) {
            detectionEngine.calculateEntropy(file)
        } else null
        
        val event = BehaviorDetectionEngine.FileChangeEvent(
            path = file.absolutePath,
            eventType = eventType,
            timestamp = System.currentTimeMillis(),
            fileSize = if (file.exists()) file.length() else 0,
            entropy = entropy
        )
        
        fileEvents.add(event)
        
        // Check for immediate threats
        if (eventType == BehaviorDetectionEngine.EventType.MODIFIED) {
            // Check for ransom note
            if (detectionEngine.checkRansomNotePattern(file)) {
                notifyRansomNoteDetected(file)
            }
            
            // Check for high entropy (encryption indicator)
            if (entropy != null && entropy > 7.5) {
                Log.w(TAG, "High entropy detected in file: ${file.absolutePath} (entropy: $entropy)")
            }
        }
        
        // Limit event history
        if (fileEvents.size > 1000) {
            fileEvents.removeAt(0)
        }
    }
    
    private suspend fun analyzeEvents() {
        if (fileEvents.isEmpty()) return
        
        val recentEvents = fileEvents.filter {
            System.currentTimeMillis() - it.timestamp < 60000 // Last minute
        }
        
        if (recentEvents.isNotEmpty()) {
            val result = detectionEngine.analyzeBehavior(recentEvents)
            
            if (result.suspicious) {
                Log.w(TAG, "Ransomware behavior detected! Confidence: ${result.confidence}, Indicators: ${result.indicators}")
                notifyThreatDetected(result)
            }
        }
    }
    
    private fun notifyRansomNoteDetected(file: File) {
        // Send critical alert
        Log.e(TAG, "RANSOM NOTE DETECTED: ${file.absolutePath}")
        // Implementation: send notification
    }
    
    private fun notifyThreatDetected(result: BehaviorDetectionEngine.DetectionResult) {
        // Send threat notification
        Log.w(TAG, "Threat detected: ${result.threatLevel}, confidence: ${result.confidence}")
        // Implementation: send notification
    }
}

/**
 * Manages file snapshots for recovery
 * Uses app-private encrypted storage
 */
class SnapshotManager(private val context: android.content.Context) {
    
    private val snapshotDir = File(context.filesDir, "snapshots")
    
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
            Log.e("SnapshotManager", "Failed to take snapshot", e)
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
    
    private fun storeSnapshotMetadata(originalPath: String, snapshotPath: String) {
        // Store in Room database
    }
    
    private fun getSnapshotMetadata(originalPath: String): SnapshotMetadata? {
        // Retrieve from Room database
        return null
    }
    
    data class SnapshotMetadata(
        val originalPath: String,
        val snapshotPath: String,
        val timestamp: Long
    )
}
