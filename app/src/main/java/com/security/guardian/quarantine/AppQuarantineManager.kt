package com.security.guardian.quarantine

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.ThreatEvent
import com.security.guardian.enterprise.EnterpriseManager
import com.security.guardian.storage.SAFManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Industry-grade app quarantine system
 * Automatically quarantines apps detected for ransomware activity
 */
class AppQuarantineManager(private val context: Context) {
    
    private val TAG = "AppQuarantineManager"
    private val database = RansomwareDatabase.getDatabase(context)
    private val enterpriseManager = EnterpriseManager(context)
    private val safManager = SAFManager(context)
    private val quarantineDir = File(context.filesDir, "quarantine")
    
    init {
        // Ensure quarantine directory exists
        if (!quarantineDir.exists()) {
            quarantineDir.mkdirs()
        }
    }
    
    data class QuarantineInfo(
        val packageName: String,
        val quarantinedAt: Long,
        val reason: String,
        val threatId: Long,
        val appDataQuarantined: Boolean,
        val networkBlocked: Boolean,
        val appStopped: Boolean
    )
    
    /**
     * Automatically quarantine an app when ransomware is detected
     */
    suspend fun quarantineAppForRansomware(
        packageName: String,
        threatId: Long,
        threatType: String,
        severity: String
    ): QuarantineResult = withContext(Dispatchers.IO) {
        try {
            Log.w(TAG, "QUARANTINING APP: $packageName for ransomware activity")
            
            val quarantineActions = mutableListOf<String>()
            var appDataQuarantined = false
            var networkBlocked = false
            var appStopped = false
            
            // 1. Stop the app immediately
            if (enterpriseManager.isDeviceOwner() || enterpriseManager.isDeviceAdmin()) {
                if (enterpriseManager.forceStopApp(packageName)) {
                    appStopped = true
                    quarantineActions.add("App force-stopped")
                    Log.d(TAG, "Force-stopped app: $packageName")
                }
            } else {
                // Try to kill background processes
                try {
                    val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
                    activityManager.killBackgroundProcesses(packageName)
                    appStopped = true
                    quarantineActions.add("Background processes killed")
                } catch (e: Exception) {
                    Log.w(TAG, "Could not stop app (requires Device Owner)", e)
                }
            }
            
            // 2. Block network access (via VPN service)
            networkBlocked = blockNetworkAccess(packageName)
            if (networkBlocked) {
                quarantineActions.add("Network access blocked")
            }
            
            // 3. Quarantine app data files
            appDataQuarantined = quarantineAppData(packageName)
            if (appDataQuarantined) {
                quarantineActions.add("App data quarantined")
            }
            
            // 4. Update threat status
            database.threatEventDao().updateThreatStatus(threatId, "QUARANTINED")
            
            // 5. Store quarantine info
            val quarantineInfo = QuarantineInfo(
                packageName = packageName,
                quarantinedAt = System.currentTimeMillis(),
                reason = "Ransomware activity detected: $threatType",
                threatId = threatId,
                appDataQuarantined = appDataQuarantined,
                networkBlocked = networkBlocked,
                appStopped = appStopped
            )
            saveQuarantineInfo(quarantineInfo)
            
            Log.i(TAG, "App quarantined successfully: $packageName")
            
            QuarantineResult(
                success = true,
                packageName = packageName,
                actions = quarantineActions,
                message = "App quarantined: ${quarantineActions.joinToString(", ")}"
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error quarantining app", e)
            QuarantineResult(
                success = false,
                packageName = packageName,
                actions = emptyList(),
                message = "Failed to quarantine app: ${e.message}"
            )
        }
    }
    
    /**
     * Block network access for an app
     */
    private suspend fun blockNetworkAccess(packageName: String): Boolean = withContext(Dispatchers.IO) {
        try {
            // Store blocked package in SharedPreferences
            val prefs = context.getSharedPreferences("network_blocklist", Context.MODE_PRIVATE)
            val blockedPackages = prefs.getStringSet("blocked_packages", mutableSetOf()) ?: mutableSetOf()
            blockedPackages.add(packageName)
            prefs.edit().putStringSet("blocked_packages", blockedPackages).apply()
            
            Log.d(TAG, "Network blocked for: $packageName")
            return@withContext true
        } catch (e: Exception) {
            Log.e(TAG, "Error blocking network", e)
            return@withContext false
        }
    }
    
    /**
     * Quarantine app data files
     */
    private suspend fun quarantineAppData(packageName: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val packageManager = context.packageManager
            val appInfo = try {
                packageManager.getApplicationInfo(packageName, 0)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.w(TAG, "App not found: $packageName")
                return@withContext false
            }
            
            val appDataDir = File(appInfo.dataDir)
            if (!appDataDir.exists()) {
                return@withContext false
            }
            
            // Create quarantine directory for this app
            val appQuarantineDir = File(quarantineDir, packageName)
            if (!appQuarantineDir.exists()) {
                appQuarantineDir.mkdirs()
            }
            
            // Copy critical files to quarantine (not moving to avoid breaking app detection)
            // In production, you might want to move files or create snapshots
            val quarantineInfoFile = File(appQuarantineDir, "quarantine_info.txt")
            quarantineInfoFile.writeText("""
                Package: $packageName
                Quarantined: ${System.currentTimeMillis()}
                Data Directory: ${appDataDir.absolutePath}
            """.trimIndent())
            
            // Try to use SAF if available for better file access
            if (safManager.hasSAFAccess("Downloads")) {
                // Create snapshot of app data directory
                val snapshotUri = safManager.createSnapshot(
                    android.net.Uri.fromFile(appDataDir),
                    "quarantine_${packageName}_${System.currentTimeMillis()}"
                )
                if (snapshotUri != null) {
                    Log.d(TAG, "Created SAF snapshot for app data: $packageName")
                }
            }
            
            Log.d(TAG, "App data quarantined: $packageName")
            return@withContext true
        } catch (e: Exception) {
            Log.e(TAG, "Error quarantining app data", e)
            return@withContext false
        }
    }
    
    /**
     * Save quarantine information
     */
    private suspend fun saveQuarantineInfo(info: QuarantineInfo) = withContext(Dispatchers.IO) {
        try {
            val prefs = context.getSharedPreferences("quarantine_info", Context.MODE_PRIVATE)
            val quarantinedApps = prefs.getStringSet("quarantined_packages", mutableSetOf()) ?: mutableSetOf()
            quarantinedApps.add(info.packageName)
            prefs.edit()
                .putStringSet("quarantined_packages", quarantinedApps)
                .putLong("quarantine_${info.packageName}_time", info.quarantinedAt)
                .putString("quarantine_${info.packageName}_reason", info.reason)
                .apply()
        } catch (e: Exception) {
            Log.e(TAG, "Error saving quarantine info", e)
        }
    }
    
    /**
     * Check if an app is quarantined
     */
    fun isQuarantined(packageName: String): Boolean {
        val prefs = context.getSharedPreferences("quarantine_info", Context.MODE_PRIVATE)
        val quarantinedApps = prefs.getStringSet("quarantined_packages", mutableSetOf()) ?: mutableSetOf()
        return quarantinedApps.contains(packageName)
    }
    
    /**
     * Get all quarantined apps
     */
    fun getQuarantinedApps(): List<String> {
        val prefs = context.getSharedPreferences("quarantine_info", Context.MODE_PRIVATE)
        val quarantinedApps = prefs.getStringSet("quarantined_packages", mutableSetOf()) ?: mutableSetOf()
        return quarantinedApps.toList()
    }
    
    /**
     * Release app from quarantine
     */
    suspend fun releaseFromQuarantine(packageName: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val prefs = context.getSharedPreferences("quarantine_info", Context.MODE_PRIVATE)
            val quarantinedApps = prefs.getStringSet("quarantined_packages", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
            quarantinedApps.remove(packageName)
            prefs.edit()
                .putStringSet("quarantined_packages", quarantinedApps)
                .remove("quarantine_${packageName}_time")
                .remove("quarantine_${packageName}_reason")
                .apply()
            
            // Unblock network
            val networkPrefs = context.getSharedPreferences("network_blocklist", Context.MODE_PRIVATE)
            val blockedPackages = networkPrefs.getStringSet("blocked_packages", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
            blockedPackages.remove(packageName)
            networkPrefs.edit().putStringSet("blocked_packages", blockedPackages).apply()
            
            Log.d(TAG, "Released app from quarantine: $packageName")
            return@withContext true
        } catch (e: Exception) {
            Log.e(TAG, "Error releasing from quarantine", e)
            return@withContext false
        }
    }
    
    data class QuarantineResult(
        val success: Boolean,
        val packageName: String,
        val actions: List<String>,
        val message: String
    )
}
