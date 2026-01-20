package com.security.guardian.filesystem

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileWriter
import java.util.Random

/**
 * Industry-grade honeypot file system for early ransomware detection
 * Creates decoy files that legitimate apps should never touch
 */
class HoneypotManager(private val context: Context) {
    
    private val TAG = "HoneypotManager"
    private val honeypotFiles = mutableListOf<HoneypotFile>()
    private val random = Random()
    
    data class HoneypotFile(
        val path: String,
        val name: String,
        val category: HoneypotCategory,
        val createdAt: Long,
        var lastChecked: Long,
        var touched: Boolean = false,
        var touchedBy: String? = null
    )
    
    enum class HoneypotCategory {
        DOCUMENTS, // .doc, .pdf, .txt files
        IMAGES,    // .jpg, .png files
        VIDEOS,    // .mp4, .avi files
        ARCHIVES,  // .zip, .rar files
        DATABASE   // .db, .sqlite files
    }
    
    /**
     * Initialize honeypot files in monitored directories
     */
    suspend fun initializeHoneypots(monitoredDirectories: List<File>) = withContext(Dispatchers.IO) {
        try {
            monitoredDirectories.forEach { directory ->
                if (directory.exists() && directory.isDirectory) {
                    createHoneypotsInDirectory(directory)
                }
            }
            Log.d(TAG, "Initialized ${honeypotFiles.size} honeypot files")
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing honeypots", e)
        }
    }
    
    /**
     * Create honeypot files in a directory
     */
    private suspend fun createHoneypotsInDirectory(directory: File) = withContext(Dispatchers.IO) {
        try {
            // Create 3-5 honeypot files per directory
            val count = 3 + random.nextInt(3)
            
            repeat(count) {
                val category = HoneypotCategory.values().random()
                val honeypotFile = createHoneypotFile(directory, category)
                if (honeypotFile != null) {
                    honeypotFiles.add(honeypotFile)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating honeypots in ${directory.absolutePath}", e)
        }
    }
    
    /**
     * Create a single honeypot file
     */
    private fun createHoneypotFile(directory: File, category: HoneypotCategory): HoneypotFile? {
        return try {
            val (name, extension, content) = when (category) {
                HoneypotCategory.DOCUMENTS -> {
                    val docTypes = listOf(
                        Triple("important_document", ".doc", generateDocumentContent()),
                        Triple("confidential_report", ".pdf", generateDocumentContent()),
                        Triple("private_notes", ".txt", generateDocumentContent())
                    )
                    docTypes.random()
                }
                HoneypotCategory.IMAGES -> {
                    val imgTypes = listOf(
                        Triple("family_photo", ".jpg", generateImageHeader()),
                        Triple("vacation_pic", ".png", generateImageHeader())
                    )
                    imgTypes.random()
                }
                HoneypotCategory.VIDEOS -> {
                    Triple("home_video", ".mp4", generateVideoHeader())
                }
                HoneypotCategory.ARCHIVES -> {
                    Triple("backup_files", ".zip", generateArchiveHeader())
                }
                HoneypotCategory.DATABASE -> {
                    Triple("user_data", ".db", generateDatabaseHeader())
                }
            }
            
            val fileName = "${name}_${System.currentTimeMillis()}${extension}"
            val file = File(directory, fileName)
            
            // Write honeypot content
            when (content) {
                is String -> file.writeText(content)
                is ByteArray -> file.writeBytes(content)
                else -> return null
            }
            
            // Set file permissions to be accessible but not obvious
            file.setReadable(true, false)
            file.setWritable(true, false)
            
            HoneypotFile(
                path = file.absolutePath,
                name = fileName,
                category = category,
                createdAt = System.currentTimeMillis(),
                lastChecked = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error creating honeypot file", e)
            null
        }
    }
    
    /**
     * Check if a file path matches any honeypot
     */
    fun checkHoneypotTouched(filePath: String, packageName: String?): Boolean {
        val honeypot = honeypotFiles.find { it.path == filePath }
        if (honeypot != null && !honeypot.touched) {
            honeypot.touched = true
            honeypot.touchedBy = packageName
            honeypot.lastChecked = System.currentTimeMillis()
            Log.w(TAG, "HONEYPOT TOUCHED: ${honeypot.name} by $packageName")
            return true
        }
        return false
    }
    
    /**
     * Get all touched honeypots
     */
    fun getTouchedHoneypots(): List<HoneypotFile> {
        return honeypotFiles.filter { it.touched }
    }
    
    /**
     * Get honeypot statistics
     */
    fun getHoneypotStats(): HoneypotStats {
        val total = honeypotFiles.size
        val touched = honeypotFiles.count { it.touched }
        return HoneypotStats(
            totalHoneypots = total,
            touchedHoneypots = touched,
            untouchedHoneypots = total - touched
        )
    }
    
    /**
     * Recreate touched honeypots
     */
    suspend fun recreateTouchedHoneypots() = withContext(Dispatchers.IO) {
        val touched = honeypotFiles.filter { it.touched }
        touched.forEach { honeypot ->
            try {
                val file = File(honeypot.path)
                val directory = file.parentFile
                if (directory != null && directory.exists()) {
                    // Remove old honeypot
                    honeypotFiles.remove(honeypot)
                    file.delete()
                    
                    // Create new one
                    val newHoneypot = createHoneypotFile(directory, honeypot.category)
                    if (newHoneypot != null) {
                        honeypotFiles.add(newHoneypot)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error recreating honeypot", e)
            }
        }
    }
    
    data class HoneypotStats(
        val totalHoneypots: Int,
        val touchedHoneypots: Int,
        val untouchedHoneypots: Int
    )
    
    // Content generators for honeypot files
    private fun generateDocumentContent(): String {
        return """
            This is an important document containing sensitive information.
            Please do not modify or delete this file.
            Created: ${System.currentTimeMillis()}
        """.trimIndent()
    }
    
    private fun generateImageHeader(): ByteArray {
        // Fake JPEG header
        return byteArrayOf(
            0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(),
            0x00.toByte(), 0x10.toByte(), 0x4A.toByte(), 0x46.toByte()
        )
    }
    
    private fun generateVideoHeader(): ByteArray {
        // Fake MP4 header
        return byteArrayOf(
            0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x20.toByte(),
            0x66.toByte(), 0x74.toByte(), 0x79.toByte(), 0x70.toByte()
        )
    }
    
    private fun generateArchiveHeader(): ByteArray {
        // Fake ZIP header
        return byteArrayOf(
            0x50.toByte(), 0x4B.toByte(), 0x03.toByte(), 0x04.toByte()
        )
    }
    
    private fun generateDatabaseHeader(): ByteArray {
        // Fake SQLite header
        return "SQLite format 3".toByteArray()
    }
}
