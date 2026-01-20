package com.security.guardian.download

import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.Cursor
import android.net.Uri
import android.os.Environment
import android.provider.DocumentsContract
import androidx.documentfile.provider.DocumentFile
import com.security.guardian.detection.BehaviorDetectionEngine
import kotlinx.coroutines.*
import java.io.File

/**
 * Monitors DownloadManager queue and inspects downloaded files
 * Detects suspicious downloads before they execute
 */
class DownloadMonitor(private val context: Context) {
    
    private val downloadManager = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
    private val detectionEngine = BehaviorDetectionEngine(context)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    private val downloadReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == DownloadManager.ACTION_DOWNLOAD_COMPLETE) {
                val downloadId = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L)
                if (downloadId != -1L) {
                    scope.launch {
                        inspectDownload(downloadId)
                    }
                }
            }
        }
    }
    
    fun startMonitoring() {
        val filter = IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE)
        context.registerReceiver(downloadReceiver, filter)
        
        // Also monitor active downloads periodically
        scope.launch {
            while (isActive) {
                monitorActiveDownloads()
                delay(5000) // Check every 5 seconds
            }
        }
    }
    
    fun stopMonitoring() {
        try {
            context.unregisterReceiver(downloadReceiver)
        } catch (e: Exception) {
            // Receiver not registered
        }
        scope.cancel()
    }
    
    private suspend fun monitorActiveDownloads() {
        val query = DownloadManager.Query()
        query.setFilterByStatus(DownloadManager.STATUS_RUNNING or DownloadManager.STATUS_PENDING)
        
        val cursor: Cursor = downloadManager.query(query)
        while (cursor.moveToNext()) {
            val downloadId = cursor.getLong(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_ID))
            val uri = cursor.getString(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_URI))
            
            // Check destination domain
            if (uri != null) {
                val domain = extractDomain(uri)
                if (domain != null && isSuspiciousDomain(domain)) {
                    // Cancel download
                    downloadManager.remove(downloadId)
                    notifySuspiciousDownload(uri, "Suspicious domain: $domain")
                }
            }
        }
        cursor.close()
    }
    
    private suspend fun inspectDownload(downloadId: Long) {
        val query = DownloadManager.Query().setFilterById(downloadId)
        val cursor: Cursor = downloadManager.query(query)
        
        if (cursor.moveToFirst()) {
            val uriString = cursor.getString(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_LOCAL_URI))
            val mimeType = cursor.getString(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_MEDIA_TYPE))
            val title = cursor.getString(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_TITLE))
            
            if (uriString != null) {
                val uri = Uri.parse(uriString)
                val file = getFileFromUri(uri)
                
                if (file != null && file.exists()) {
                    val suspicious = analyzeDownloadedFile(file, title)
                    if (suspicious) {
                        handleSuspiciousFile(file, title)
                    }
                }
            }
        }
        cursor.close()
    }
    
    private fun analyzeDownloadedFile(file: File, filename: String): Boolean {
        // Check 1: File extension vs content mismatch
        val extensionMismatch = checkExtensionMismatch(file, filename)
        if (extensionMismatch) return true
        
        // Check 2: Magic bytes analysis
        val magicBytes = detectionEngine.getFileMagicBytes(file)
        if (magicBytes != null && isSuspiciousMagic(magicBytes)) {
            return true
        }
        
        // Check 3: Entropy check (high entropy = possible encryption)
        val entropy = detectionEngine.calculateEntropy(file)
        if (entropy != null && entropy > 7.5) {
            return true
        }
        
        // Check 4: Ransom note detection
        if (detectionEngine.checkRansomNotePattern(file)) {
            return true
        }
        
        // Check 5: Suspicious filename patterns
        if (isSuspiciousFilename(filename)) {
            return true
        }
        
        return false
    }
    
    private fun checkExtensionMismatch(file: File, filename: String): Boolean {
        val extension = filename.substringAfterLast('.', "")
        val magicBytes = detectionEngine.getFileMagicBytes(file) ?: return false
        
        // Check if magic bytes match extension
        return when (extension.lowercase()) {
            "pdf" -> !magicBytes.contentEquals(byteArrayOf(0x25.toByte(), 0x50.toByte(), 0x44.toByte(), 0x46.toByte()))
            "zip" -> !magicBytes.contentEquals(byteArrayOf(0x50.toByte(), 0x4B.toByte(), 0x03.toByte(), 0x04.toByte()))
            "jpg", "jpeg" -> !magicBytes.contentEquals(byteArrayOf((-1).toByte(), (-40).toByte(), (-1).toByte(), (-32).toByte()))
            "png" -> !magicBytes.contentEquals(byteArrayOf((-119).toByte(), 0x50.toByte(), 0x4E.toByte(), 0x47.toByte()))
            else -> false
        }
    }
    
    private fun isSuspiciousMagic(magic: ByteArray): Boolean {
        // Executable files are suspicious
        val executableSignatures = listOf(
            byteArrayOf(0x4D.toByte(), 0x5A.toByte()), // PE
            byteArrayOf(0x7F.toByte(), 0x45.toByte(), 0x4C.toByte(), 0x46.toByte()), // ELF
            byteArrayOf((-54).toByte(), (-2).toByte(), (-70).toByte(), (-66).toByte()) // Java class
        )
        return executableSignatures.any { signature ->
            magic.size >= signature.size && 
            magic.sliceArray(0 until signature.size).contentEquals(signature)
        }
    }
    
    private fun isSuspiciousFilename(filename: String): Boolean {
        val suspiciousPatterns = listOf(
            "decrypt",
            "readme",
            "how_to_recover",
            "recover_files",
            "encrypted"
        )
        return suspiciousPatterns.any { pattern ->
            filename.lowercase().contains(pattern)
        }
    }
    
    private fun isSuspiciousDomain(domain: String): Boolean {
        // Check against threat intelligence
        val suspiciousPatterns = listOf(
            "bit.ly",
            "tinyurl",
            "short.link"
        )
        return suspiciousPatterns.any { domain.contains(it) }
    }
    
    private fun extractDomain(uriString: String): String? {
        return try {
            val uri = Uri.parse(uriString)
            uri.host
        } catch (e: Exception) {
            null
        }
    }
    
    private fun getFileFromUri(uri: Uri): File? {
        return try {
            if (uri.scheme == "file") {
                File(uri.path ?: return null)
            } else if (uri.scheme == "content") {
                // Use SAF or MediaStore
                val filePath = getFilePathFromContentUri(uri)
                if (filePath != null) File(filePath) else null
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    private fun getFilePathFromContentUri(uri: Uri): String? {
        return try {
            if (DocumentsContract.isDocumentUri(context, uri)) {
                val docFile = DocumentFile.fromSingleUri(context, uri)
                // Would need persistent URI access via SAF
                null
            } else {
                // Try MediaStore
                val cursor = context.contentResolver.query(
                    uri, arrayOf(android.provider.MediaStore.MediaColumns.DATA),
                    null, null, null
                )
                cursor?.use {
                    if (it.moveToFirst()) {
                        val index = it.getColumnIndexOrThrow(android.provider.MediaStore.MediaColumns.DATA)
                        it.getString(index)
                    } else null
                }
            }
        } catch (e: Exception) {
            null
        }
    }
    
    private fun handleSuspiciousFile(file: File, filename: String) {
        // Quarantine file
        scope.launch {
            quarantineFile(file)
            notifyThreatDetected(
                type = "SUSPICIOUS_DOWNLOAD",
                description = "Suspicious file downloaded: $filename",
                filePath = file.absolutePath
            )
        }
    }
    
    private suspend fun quarantineFile(file: File) {
        // Move to quarantine directory
        val quarantineDir = File(context.filesDir, "quarantine")
        quarantineDir.mkdirs()
        
        val quarantinedFile = File(quarantineDir, file.name)
        file.copyTo(quarantinedFile, overwrite = true)
        file.delete()
    }
    
    private fun notifySuspiciousDownload(uri: String, reason: String) {
        // Send notification
        // Implementation in notification service
    }
    
    private fun notifyThreatDetected(type: String, description: String, filePath: String) {
        // Send threat notification
        // Implementation in notification service
    }
}
