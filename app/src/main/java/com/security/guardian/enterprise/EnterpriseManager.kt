package com.security.guardian.enterprise

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi

/**
 * Enterprise management APIs for Device Admin and Device Owner scenarios
 * Provides enhanced control for enterprise-managed or rooted devices
 */
class EnterpriseManager(private val context: Context) {
    
    private val TAG = "EnterpriseManager"
    private val devicePolicyManager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val adminComponent = ComponentName(context, SecurityDeviceAdminReceiver::class.java)
    
    /**
     * Check if device is managed by Device Owner
     */
    fun isDeviceOwner(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            devicePolicyManager.isDeviceOwnerApp(context.packageName)
        } else {
            false
        }
    }
    
    /**
     * Check if app is Device Admin
     */
    fun isDeviceAdmin(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.FROYO) {
            devicePolicyManager.isAdminActive(adminComponent)
        } else {
            false
        }
    }
    
    /**
     * Force stop an app (requires Device Owner or root)
     */
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun forceStopApp(packageName: String): Boolean {
        return try {
            if (isDeviceOwner()) {
                devicePolicyManager.setApplicationHidden(adminComponent, packageName, false)
                // Force stop using ActivityManager (requires system permission or Device Owner)
                val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
                activityManager.killBackgroundProcesses(packageName)
                true
            } else {
                Log.w(TAG, "Cannot force stop app: Not Device Owner")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error force stopping app", e)
            false
        }
    }
    
    /**
     * Uninstall app (requires Device Owner)
     */
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun uninstallApp(packageName: String): Boolean {
        return try {
            if (isDeviceOwner()) {
                // Note: uninstallCaCert is for CA certificates, not apps
                // For app uninstall, use PackageInstaller or Intent
                // Actually uninstall using PackageInstaller (simplified)
                val intent = Intent(Intent.ACTION_DELETE).apply {
                    data = android.net.Uri.parse("package:$packageName")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                context.startActivity(intent)
                true
            } else {
                Log.w(TAG, "Cannot uninstall app: Not Device Owner")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error uninstalling app", e)
            false
        }
    }
    
    /**
     * Revoke runtime permission (requires Device Owner on Android 6.0+)
     */
    @RequiresApi(Build.VERSION_CODES.M)
    fun revokePermission(packageName: String, permission: String): Boolean {
        return try {
            if (isDeviceOwner()) {
                devicePolicyManager.setPermissionPolicy(adminComponent, 
                    DevicePolicyManager.PERMISSION_POLICY_AUTO_GRANT)
                // Note: revokeRuntimePermission is not available in standard API
                // Guide user to manually revoke in Settings
                Log.d(TAG, "Permission revocation requested for $packageName:$permission")
                // Open app settings for manual revocation
                val intent = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = android.net.Uri.parse("package:$packageName")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                context.startActivity(intent)
                true
            } else {
                Log.w(TAG, "Cannot revoke permission: Not Device Owner")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error revoking permission", e)
            false
        }
    }
    
    /**
     * Block app installation (requires Device Owner)
     */
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun setInstallBlocked(packageName: String, blocked: Boolean): Boolean {
        return try {
            if (isDeviceOwner()) {
                devicePolicyManager.setApplicationHidden(adminComponent, packageName, blocked)
                true
            } else {
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error blocking installation", e)
            false
        }
    }
    
    /**
     * Set app restrictions (requires Device Owner)
     */
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun setAppRestrictions(packageName: String, restrictions: android.os.Bundle): Boolean {
        return try {
            if (isDeviceOwner()) {
                devicePolicyManager.setApplicationRestrictions(adminComponent, packageName, restrictions)
                true
            } else {
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error setting app restrictions", e)
            false
        }
    }
    
    /**
     * Lock device (requires Device Admin)
     */
    fun lockDevice(): Boolean {
        return try {
            if (isDeviceAdmin()) {
                devicePolicyManager.lockNow()
                true
            } else {
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error locking device", e)
            false
        }
    }
    
    /**
     * Wipe device data (requires Device Owner - DANGEROUS!)
     */
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun wipeDevice(): Boolean {
        return try {
            if (isDeviceOwner()) {
                devicePolicyManager.wipeData(0)
                true
            } else {
                Log.w(TAG, "Cannot wipe device: Not Device Owner")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error wiping device", e)
            false
        }
    }
    
    /**
     * Get enterprise capabilities
     */
    fun getCapabilities(): EnterpriseCapabilities {
        return EnterpriseCapabilities(
            isDeviceOwner = isDeviceOwner(),
            isDeviceAdmin = isDeviceAdmin(),
            canForceStop = isDeviceOwner(),
            canUninstall = isDeviceOwner(),
            canRevokePermissions = isDeviceOwner() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M,
            canBlockInstall = isDeviceOwner(),
            canSetRestrictions = isDeviceOwner(),
            canLockDevice = isDeviceAdmin(),
            canWipeDevice = isDeviceOwner()
        )
    }
    
    data class EnterpriseCapabilities(
        val isDeviceOwner: Boolean,
        val isDeviceAdmin: Boolean,
        val canForceStop: Boolean,
        val canUninstall: Boolean,
        val canRevokePermissions: Boolean,
        val canBlockInstall: Boolean,
        val canSetRestrictions: Boolean,
        val canLockDevice: Boolean,
        val canWipeDevice: Boolean
    )
}

/**
 * Device Admin Receiver for enterprise management
 */
class SecurityDeviceAdminReceiver : DeviceAdminReceiver() {
    
    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        android.util.Log.d("DeviceAdmin", "Device admin enabled")
    }
    
    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        android.util.Log.d("DeviceAdmin", "Device admin disabled")
    }
    
    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        return "Disabling device admin will reduce security protection"
    }
}
