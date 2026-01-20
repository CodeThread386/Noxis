package com.security.guardian.storage

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import androidx.documentfile.provider.DocumentFile
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * Storage Access Framework (SAF) manager for file operations
 * Handles persistent URI access, file deletion, quarantine, and restoration
 */
class SAFManager(private val context: Context) {
    
    private val TAG = "SAFManager"
    private val prefs = context.getSharedPreferences("saf_manager", Context.MODE_PRIVATE)
    
    /**
     * Request persistent access to a directory tree
     */
    fun requestDirectoryAccess(activity: android.app.Activity, requestCode: Int, initialUri: Uri? = null) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            if (initialUri != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                putExtra(DocumentsContract.EXTRA_INITIAL_URI, initialUri)
            }
        }
        activity.startActivityForResult(intent, requestCode)
    }
    
    /**
     * Save persistent URI access
     */
    fun savePersistentUri(uri: Uri, directoryName: String) {
        val uriString = uri.toString()
        prefs.edit().putString("saf_uri_$directoryName", uriString).apply()
        
        // Take persistable URI permission
        val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                       Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        context.contentResolver.takePersistableUriPermission(uri, takeFlags)
        
        Log.d(TAG, "Saved persistent URI for $directoryName: $uriString")
    }
    
    /**
     * Get persistent URI for a directory
     */
    fun getPersistentUri(directoryName: String): Uri? {
        val uriString = prefs.getString("saf_uri_$directoryName", null)
        return if (uriString != null) {
            Uri.parse(uriString)
        } else {
            null
        }
    }
    
    /**
     * Get DocumentFile for a directory using persistent URI
     */
    fun getDocumentFile(directoryName: String): DocumentFile? {
        val uri = getPersistentUri(directoryName) ?: return null
        return DocumentFile.fromTreeUri(context, uri)
    }
    
    /**
     * Delete file using SAF
     */
    suspend fun deleteFile(uri: Uri): Boolean = withContext(Dispatchers.IO) {
        return@withContext try {
            val documentFile = DocumentFile.fromSingleUri(context, uri)
            if (documentFile != null && documentFile.exists()) {
                documentFile.delete()
            } else {
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting file via SAF", e)
            false
        }
    }
    
    /**
     * Quarantine file by moving it to quarantine directory
     */
    suspend fun quarantineFile(sourceUri: Uri, fileName: String): Uri? = withContext(Dispatchers.IO) {
        return@withContext try {
            val downloadsDir = getDocumentFile("Downloads")
            val quarantineDir = getOrCreateQuarantineDirectory()
            
            if (quarantineDir == null) {
                Log.e(TAG, "Cannot access quarantine directory")
                return@withContext null
            }
            
            // Copy file to quarantine
            val sourceFile = DocumentFile.fromSingleUri(context, sourceUri)
            if (sourceFile == null || !sourceFile.exists()) {
                Log.e(TAG, "Source file does not exist")
                return@withContext null
            }
            
            val quarantinedFile = quarantineDir.createFile(
                sourceFile.type ?: "application/octet-stream",
                "${System.currentTimeMillis()}_$fileName"
            )
            
            if (quarantinedFile == null) {
                Log.e(TAG, "Failed to create quarantined file")
                return@withContext null
            }
            
            // Copy file content
            copyFileContent(sourceUri, quarantinedFile.uri)
            
            // Delete original
            sourceFile.delete()
            
            quarantinedFile.uri
        } catch (e: Exception) {
            Log.e(TAG, "Error quarantining file", e)
            null
        }
    }
    
    /**
     * Restore file from quarantine
     */
    suspend fun restoreFile(quarantineUri: Uri, originalPath: String): Boolean = withContext(Dispatchers.IO) {
        return@withContext try {
            val quarantineFile = DocumentFile.fromSingleUri(context, quarantineUri)
            if (quarantineFile == null || !quarantineFile.exists()) {
                return@withContext false
            }
            
            // Get destination directory
            val downloadsDir = getDocumentFile("Downloads")
            if (downloadsDir == null) {
                Log.e(TAG, "Cannot access Downloads directory")
                return@withContext false
            }
            
            val fileName = File(originalPath).name
            val restoredFile = downloadsDir.createFile(
                quarantineFile.type ?: "application/octet-stream",
                fileName
            )
            
            if (restoredFile == null) {
                return@withContext false
            }
            
            // Copy content back
            copyFileContent(quarantineUri, restoredFile.uri)
            
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error restoring file", e)
            false
        }
    }
    
    /**
     * Create snapshot of file using SAF
     */
    suspend fun createSnapshot(sourceUri: Uri, snapshotName: String): Uri? = withContext(Dispatchers.IO) {
        return@withContext try {
            val sourceFile = DocumentFile.fromSingleUri(context, sourceUri)
            if (sourceFile == null || !sourceFile.exists()) {
                return@withContext null
            }
            
            // Get or create snapshots directory
            val snapshotsDir = getOrCreateSnapshotsDirectory()
            if (snapshotsDir == null) {
                Log.e(TAG, "Cannot access snapshots directory")
                return@withContext null
            }
            
            val snapshotFile = snapshotsDir.createFile(
                sourceFile.type ?: "application/octet-stream",
                snapshotName
            )
            
            if (snapshotFile == null) {
                return@withContext null
            }
            
            // Copy file content
            copyFileContent(sourceUri, snapshotFile.uri)
            
            snapshotFile.uri
        } catch (e: Exception) {
            Log.e(TAG, "Error creating snapshot", e)
            null
        }
    }
    
    private suspend fun getOrCreateQuarantineDirectory(): DocumentFile? = withContext(Dispatchers.IO) {
        val downloadsDir = getDocumentFile("Downloads")
        if (downloadsDir == null) return@withContext null
        
        // Try to find existing quarantine directory
        val existing = downloadsDir.findFile("RansomwareGuard_Quarantine")
        if (existing != null && existing.isDirectory) {
            return@withContext existing
        }
        
        // Create new quarantine directory
        return@withContext downloadsDir.createDirectory("RansomwareGuard_Quarantine")
    }
    
    private suspend fun getOrCreateSnapshotsDirectory(): DocumentFile? = withContext(Dispatchers.IO) {
        val downloadsDir = getDocumentFile("Downloads")
        if (downloadsDir == null) return@withContext null
        
        // Try to find existing snapshots directory
        val existing = downloadsDir.findFile("RansomwareGuard_Snapshots")
        if (existing != null && existing.isDirectory) {
            return@withContext existing
        }
        
        // Create new snapshots directory
        return@withContext downloadsDir.createDirectory("RansomwareGuard_Snapshots")
    }
    
    private suspend fun copyFileContent(sourceUri: Uri, destUri: Uri): Boolean = withContext(Dispatchers.IO) {
        return@withContext try {
            context.contentResolver.openInputStream(sourceUri)?.use { input ->
                context.contentResolver.openOutputStream(destUri)?.use { output ->
                    input.copyTo(output)
                    true
                } ?: false
            } ?: false
        } catch (e: Exception) {
            Log.e(TAG, "Error copying file content", e)
            false
        }
    }
    
    /**
     * List files in a directory using SAF
     */
    suspend fun listFiles(directoryUri: Uri): List<DocumentFile> = withContext(Dispatchers.IO) {
        return@withContext try {
            val dir = DocumentFile.fromTreeUri(context, directoryUri)
            if (dir != null && dir.isDirectory) {
                dir.listFiles().toList()
            } else {
                emptyList()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error listing files", e)
            emptyList()
        }
    }
    
    /**
     * Check if SAF access is available for a directory
     */
    fun hasSAFAccess(directoryName: String): Boolean {
        return getPersistentUri(directoryName) != null
    }
    
    /**
     * Request SAF access for common directories
     */
    fun requestCommonDirectories(activity: android.app.Activity) {
        // Request Downloads directory
        val downloadsUri = android.os.Environment.getExternalStoragePublicDirectory(
            android.os.Environment.DIRECTORY_DOWNLOADS
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            requestDirectoryAccess(activity, REQUEST_DOWNLOADS, 
                android.net.Uri.fromFile(downloadsUri))
        } else {
            requestDirectoryAccess(activity, REQUEST_DOWNLOADS)
        }
    }
    
    companion object {
        const val REQUEST_DOWNLOADS = 1001
        const val REQUEST_DOCUMENTS = 1002
        const val REQUEST_PICTURES = 1003
    }
}
