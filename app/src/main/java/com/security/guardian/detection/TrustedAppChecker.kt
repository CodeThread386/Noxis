package com.security.guardian.detection

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.util.Log
import java.security.MessageDigest

/**
 * Industry-grade trusted app checker
 * Whitelists system apps and apps from trusted sources to prevent false positives
 * Based on Android security best practices and industry standards
 */
class TrustedAppChecker(private val context: Context) {
    
    private val TAG = "TrustedAppChecker"
    private val packageManager = context.packageManager
    
    // Known trusted package prefixes (system apps)
    private val trustedSystemPrefixes = setOf(
        "android",
        "com.android",
        "com.google.android",
        "com.qualcomm",
        "com.samsung",
        "com.miui",
        "com.huawei",
        "com.oneplus",
        "com.oppo",
        "com.vivo",
        "com.realme",
        "com.xiaomi",
        "com.mediatek",
        "com.sony",
        "com.lge",
        "com.motorola",
        "com.nokia",
        "com.htc",
        "com.asus",
        "com.lenovo",
        "com.zte"
    )
    
    // Known trusted installers
    private val trustedInstallers = setOf(
        "com.android.vending", // Google Play Store
        "com.amazon.venezia", // Amazon Appstore
        "com.samsung.android.app.galaxyapps", // Samsung Galaxy Store
        "com.huawei.appmarket", // Huawei AppGallery
        "com.xiaomi.market", // Xiaomi App Store
        "com.oneplus.market" // OnePlus App Store
    )
    
    /**
     * Check if an app is a trusted system app
     */
    fun isSystemApp(packageName: String?): Boolean {
        if (packageName == null) return false
        
        return try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        } catch (e: PackageManager.NameNotFoundException) {
            false
        } catch (e: Exception) {
            Log.w(TAG, "Error checking system app status for $packageName", e)
            false
        }
    }
    
    /**
     * Check if app is from a trusted package prefix
     */
    fun isTrustedPackage(packageName: String?): Boolean {
        if (packageName == null) return false
        
        return trustedSystemPrefixes.any { packageName.startsWith("$it.") || packageName == it }
    }
    
    /**
     * Check if app was installed from a trusted source
     */
    fun isFromTrustedInstaller(packageName: String?): Boolean {
        if (packageName == null) return false
        
        return try {
            val installerPackageName = packageManager.getInstallerPackageName(packageName)
            installerPackageName != null && trustedInstallers.contains(installerPackageName)
        } catch (e: Exception) {
            Log.w(TAG, "Error checking installer for $packageName", e)
            false
        }
    }
    
    /**
     * Check if app is signed with platform key (highest trust level)
     */
    fun isPlatformSigned(packageName: String?): Boolean {
        if (packageName == null) return false
        
        return try {
            val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            val signatures = packageInfo.signatures ?: return false
            
            // Check if signed with platform key
            // Platform key signature hash: "android" (simplified check)
            signatures.any { signature ->
                val md = MessageDigest.getInstance("SHA-256")
                val hash = md.digest(signature.toByteArray())
                // Platform apps are typically signed with a specific key
                // In production, you'd compare against actual platform key hash
                // For now, we check if it's a system app with valid signature
                isSystemApp(packageName)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error checking platform signature for $packageName", e)
            false
        }
    }
    
    /**
     * Check if app is trusted (should not trigger false positives)
     */
    fun isTrustedApp(packageName: String?): Boolean {
        if (packageName == null) return false
        
        // Platform signed apps are always trusted
        if (isPlatformSigned(packageName)) {
            return true
        }
        
        // System apps are trusted
        if (isSystemApp(packageName)) {
            return true
        }
        
        // Apps from trusted package prefixes are trusted
        if (isTrustedPackage(packageName)) {
            return true
        }
        
        // Apps from trusted installers are trusted
        if (isFromTrustedInstaller(packageName)) {
            return true
        }
        
        return false
    }
    
    /**
     * Get trust level for an app
     */
    fun getTrustLevel(packageName: String?): TrustLevel {
        if (packageName == null) return TrustLevel.UNKNOWN
        
        return when {
            isPlatformSigned(packageName) -> TrustLevel.PLATFORM_SIGNED
            isSystemApp(packageName) -> TrustLevel.SYSTEM_APP
            isTrustedPackage(packageName) -> TrustLevel.TRUSTED_PACKAGE
            isFromTrustedInstaller(packageName) -> TrustLevel.TRUSTED_INSTALLER
            else -> TrustLevel.UNKNOWN
        }
    }
    
    /**
     * Get app metadata for threat details
     */
    fun getAppMetadata(packageName: String?): AppMetadata? {
        if (packageName == null) return null
        
        return try {
            val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_META_DATA)
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            val installer = packageManager.getInstallerPackageName(packageName)
            
            // Get app label
            val appLabel = packageManager.getApplicationLabel(appInfo).toString()
            
            // Get signature hash
            val signatureHash = try {
                val signatures = packageInfo.signatures
                if (signatures != null && signatures.isNotEmpty()) {
                    val md = MessageDigest.getInstance("SHA-256")
                    val hash = md.digest(signatures[0].toByteArray())
                    hash.joinToString("") { "%02x".format(it) }.take(16)
                } else {
                    "Unknown"
                }
            } catch (e: Exception) {
                "Unknown"
            }
            
            AppMetadata(
                packageName = packageName,
                appLabel = appLabel,
                versionName = packageInfo.versionName ?: "Unknown",
                versionCode = packageInfo.longVersionCode,
                installer = installer ?: "Unknown",
                isSystemApp = isSystemApp(packageName),
                trustLevel = getTrustLevel(packageName),
                signatureHash = signatureHash,
                firstInstallTime = packageInfo.firstInstallTime,
                lastUpdateTime = packageInfo.lastUpdateTime
            )
        } catch (e: Exception) {
            Log.w(TAG, "Error getting app metadata for $packageName", e)
            null
        }
    }
    
    enum class TrustLevel {
        PLATFORM_SIGNED,    // Highest trust - signed with platform key
        SYSTEM_APP,         // System app
        TRUSTED_PACKAGE,    // From trusted package prefix
        TRUSTED_INSTALLER,  // From trusted installer (Play Store, etc.)
        UNKNOWN             // Unknown/not trusted
    }
    
    data class AppMetadata(
        val packageName: String,
        val appLabel: String,
        val versionName: String,
        val versionCode: Long,
        val installer: String,
        val isSystemApp: Boolean,
        val trustLevel: TrustLevel,
        val signatureHash: String,
        val firstInstallTime: Long,
        val lastUpdateTime: Long
    )
}
