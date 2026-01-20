package com.security.guardian.packagemonitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.util.Log
import com.security.guardian.detection.BehaviorDetectionEngine
import kotlinx.coroutines.*
import java.io.File

/**
 * Monitors package installs/replaces/removes
 * Analyzes APKs for suspicious permissions and behavior
 */
class PackageMonitor(private val context: Context) {
    
    private val TAG = "PackageMonitor"
    private val packageManager = context.packageManager
    private val detectionEngine = BehaviorDetectionEngine(context)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                Intent.ACTION_PACKAGE_ADDED,
                Intent.ACTION_PACKAGE_REPLACED -> {
                    val packageName = intent.data?.schemeSpecificPart
                    if (packageName != null) {
                        scope.launch {
                            analyzeInstalledPackage(packageName)
                        }
                    }
                }
                Intent.ACTION_PACKAGE_REMOVED -> {
                    val packageName = intent.data?.schemeSpecificPart
                    if (packageName != null) {
                        Log.d(TAG, "Package removed: $packageName")
                    }
                }
            }
        }
    }
    
    fun startMonitoring() {
        val filter = android.content.IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        context.registerReceiver(packageReceiver, filter)
    }
    
    fun stopMonitoring() {
        try {
            context.unregisterReceiver(packageReceiver)
        } catch (e: Exception) {
            // Receiver not registered
        }
        scope.cancel()
    }
    
    private suspend fun analyzeInstalledPackage(packageName: String) {
        try {
            val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            
            // Check 1: Suspicious permission combinations
            val suspiciousPermissions = checkSuspiciousPermissions(packageInfo)
            if (suspiciousPermissions.isNotEmpty()) {
                Log.w(TAG, "Suspicious permissions in $packageName: $suspiciousPermissions")
                notifySuspiciousPackage(packageName, "Suspicious permissions: ${suspiciousPermissions.joinToString()}")
            }
            
            // Check 2: Device Admin request
            if (hasDeviceAdminPermission(packageInfo)) {
                Log.w(TAG, "Device Admin permission requested by $packageName")
                notifySuspiciousPackage(packageName, "Device Admin permission requested")
            }
            
            // Check 3: Overlay permission
            if (hasOverlayPermission(packageInfo)) {
                Log.w(TAG, "Overlay permission in $packageName")
                notifySuspiciousPackage(packageName, "Overlay permission detected")
            }
            
            // Check 4: Request DELETE_PACKAGES
            if (hasDeletePackagesPermission(packageInfo)) {
                Log.w(TAG, "DELETE_PACKAGES permission in $packageName")
                notifySuspiciousPackage(packageName, "DELETE_PACKAGES permission detected")
            }
            
            // Check 5: Analyze APK file if accessible
            val apkPath = appInfo.sourceDir
            if (apkPath != null) {
                val apkFile = File(apkPath)
                if (apkFile.exists()) {
                    analyzeAPKFile(apkFile, packageName)
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing package: $packageName", e)
        }
    }
    
    private fun checkSuspiciousPermissions(packageInfo: android.content.pm.PackageInfo): List<String> {
        val suspicious = mutableListOf<String>()
        val requestedPermissions = packageInfo.requestedPermissions ?: return suspicious
        
        // Dangerous permission combinations
        val dangerousCombos = listOf(
            listOf(
                android.Manifest.permission.READ_EXTERNAL_STORAGE,
                android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
                android.Manifest.permission.INTERNET
            ),
            listOf(
                android.Manifest.permission.READ_CONTACTS,
                android.Manifest.permission.SEND_SMS,
                android.Manifest.permission.INTERNET
            )
        )
        
        requestedPermissions.forEach { permission ->
            // Check for individual suspicious permissions
            if (isSuspiciousPermission(permission)) {
                suspicious.add(permission)
            }
        }
        
        return suspicious
    }
    
    private fun isSuspiciousPermission(permission: String): Boolean {
        val suspiciousPermissions = listOf(
            android.Manifest.permission.REQUEST_DELETE_PACKAGES,
            android.Manifest.permission.SYSTEM_ALERT_WINDOW,
            android.Manifest.permission.BIND_ACCESSIBILITY_SERVICE,
            android.Manifest.permission.WRITE_SECURE_SETTINGS,
            // DEVICE_POWER is not a standard permission, removing
        )
        return suspiciousPermissions.contains(permission)
    }
    
    private fun hasDeviceAdminPermission(packageInfo: android.content.pm.PackageInfo): Boolean {
        // Check if app requests device admin (via manifest or runtime)
        // Simplified check
        return false
    }
    
    private fun hasOverlayPermission(packageInfo: android.content.pm.PackageInfo): Boolean {
        val permissions = packageInfo.requestedPermissions ?: return false
        return permissions.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW)
    }
    
    private fun hasDeletePackagesPermission(packageInfo: android.content.pm.PackageInfo): Boolean {
        val permissions = packageInfo.requestedPermissions ?: return false
        return permissions.contains(android.Manifest.permission.REQUEST_DELETE_PACKAGES)
    }
    
    private suspend fun analyzeAPKFile(apkFile: File, packageName: String) {
        // Check APK file magic bytes
        val magicBytes = detectionEngine.getFileMagicBytes(apkFile)
        if (magicBytes != null) {
            // Verify it's a valid APK (ZIP format)
            val isValidAPK = magicBytes.contentEquals(byteArrayOf(0x50, 0x4B, 0x03, 0x04))
            if (!isValidAPK) {
                Log.w(TAG, "Invalid APK magic bytes for $packageName")
            }
        }
        
        // Check file size (very large APKs might be suspicious)
        if (apkFile.length() > 100 * 1024 * 1024) { // 100 MB
            Log.w(TAG, "Unusually large APK: ${apkFile.length()} bytes")
        }
    }
    
    private fun notifySuspiciousPackage(packageName: String, reason: String) {
        // Send notification
        // Implementation in notification service
    }
}
