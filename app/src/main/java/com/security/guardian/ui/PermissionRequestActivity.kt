package com.security.guardian.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.security.guardian.R
import com.security.guardian.storage.SAFManager

/**
 * Activity shown on first launch to request all recommended permissions
 */
class PermissionRequestActivity : AppCompatActivity() {
    
    private lateinit var titleText: TextView
    private lateinit var descriptionText: TextView
    private lateinit var vpnButton: Button
    private lateinit var accessibilityButton: Button
    private lateinit var usageStatsButton: Button
    private lateinit var safButton: Button
    private lateinit var skipButton: Button
    private lateinit var continueButton: Button
    
    private var vpnGranted = false
    private var accessibilityGranted = false
    private var usageStatsGranted = false
    private var safGranted = false
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_permission_request)
        
        setupViews()
        checkCurrentPermissions()
        setupButtons()
    }
    
    private fun setupViews() {
        titleText = findViewById(R.id.permissionTitleText)
        descriptionText = findViewById(R.id.permissionDescriptionText)
        vpnButton = findViewById(R.id.vpnPermissionButton)
        accessibilityButton = findViewById(R.id.accessibilityPermissionButton)
        usageStatsButton = findViewById(R.id.usageStatsPermissionButton)
        safButton = findViewById(R.id.safPermissionButton)
        skipButton = findViewById(R.id.skipButton)
        continueButton = findViewById(R.id.continueButton)
        
        titleText.text = "Recommended Permissions"
        descriptionText.text = """
            For maximum protection, we recommend granting the following permissions:
            
            • VPN: Block malicious network traffic and inspect downloads
            • Accessibility: Detect ransomware overlays and lock-screen hijacking
            • Usage Stats: Monitor abnormal CPU/I/O usage patterns
            • Storage Access: Create snapshots and quarantine suspicious files
            
            You can grant these permissions now or later from Settings.
        """.trimIndent()
    }
    
    private fun checkCurrentPermissions() {
        vpnGranted = isVPNPermissionGranted()
        accessibilityGranted = isAccessibilityServiceEnabled()
        usageStatsGranted = isUsageStatsPermissionGranted()
        safGranted = SAFManager(this).hasSAFAccess("Downloads")
        
        updateButtonStates()
    }
    
    private fun updateButtonStates() {
        vpnButton.text = if (vpnGranted) "✓ VPN Permission Granted" else "Grant VPN Permission"
        vpnButton.isEnabled = !vpnGranted
        
        accessibilityButton.text = if (accessibilityGranted) "✓ Accessibility Permission Granted" else "Grant Accessibility Permission"
        accessibilityButton.isEnabled = !accessibilityGranted
        
        usageStatsButton.text = if (usageStatsGranted) "✓ Usage Stats Permission Granted" else "Grant Usage Stats Permission"
        usageStatsButton.isEnabled = !usageStatsGranted
        
        safButton.text = if (safGranted) "✓ Storage Access Granted" else "Grant Storage Access"
        safButton.isEnabled = !safGranted
        
        // Enable continue button if at least one permission is granted
        continueButton.isEnabled = vpnGranted || accessibilityGranted || usageStatsGranted || safGranted
    }
    
    private fun setupButtons() {
        vpnButton.setOnClickListener {
            requestVPNPermission()
        }
        
        accessibilityButton.setOnClickListener {
            requestAccessibilityPermission()
        }
        
        usageStatsButton.setOnClickListener {
            requestUsageStatsPermission()
        }
        
        safButton.setOnClickListener {
            requestSAFPermission()
        }
        
        skipButton.setOnClickListener {
            markPermissionsShown()
            finish()
            startActivity(Intent(this, MainActivity::class.java))
        }
        
        continueButton.setOnClickListener {
            markPermissionsShown()
            finish()
            startActivity(Intent(this, MainActivity::class.java))
        }
    }
    
    private fun requestVPNPermission() {
        try {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                startActivityForResult(vpnIntent, REQUEST_VPN)
            } else {
                vpnGranted = true
                updateButtonStates()
                android.widget.Toast.makeText(this, "VPN permission already granted", android.widget.Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            android.util.Log.e("PermissionRequest", "Error requesting VPN permission", e)
            android.widget.Toast.makeText(this, "Error requesting VPN permission", android.widget.Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun startVPNService() {
        try {
            val intent = Intent(this, com.security.guardian.network.VPNInterceptionService::class.java).apply {
                action = com.security.guardian.network.VPNInterceptionService.ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (e: Exception) {
            android.util.Log.e("PermissionRequest", "Error starting VPN service", e)
        }
    }
    
    private fun requestAccessibilityPermission() {
        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        startActivity(intent)
        android.widget.Toast.makeText(
            this,
            "Please enable 'RansomwareGuard' in Accessibility settings, then return to this app",
            android.widget.Toast.LENGTH_LONG
        ).show()
    }
    
    private fun requestUsageStatsPermission() {
        val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
        startActivity(intent)
        android.widget.Toast.makeText(
            this,
            "Please enable 'RansomwareGuard' in Usage Access settings, then return to this app",
            android.widget.Toast.LENGTH_LONG
        ).show()
    }
    
    private fun requestSAFPermission() {
        val safManager = SAFManager(this)
        safManager.requestDirectoryAccess(this, SAFManager.REQUEST_DOWNLOADS)
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        when (requestCode) {
            REQUEST_VPN -> {
                if (resultCode == Activity.RESULT_OK) {
                    vpnGranted = true
                    updateButtonStates()
                    android.widget.Toast.makeText(this, "VPN permission granted", android.widget.Toast.LENGTH_SHORT).show()
                    startVPNService()
                }
            }
            SAFManager.REQUEST_DOWNLOADS -> {
                if (resultCode == Activity.RESULT_OK && data != null) {
                    val uri = data.data
                    if (uri != null) {
                        val safManager = SAFManager(this)
                        safManager.savePersistentUri(uri, "Downloads")
                        safGranted = true
                        updateButtonStates()
                        android.widget.Toast.makeText(this, "Storage access granted", android.widget.Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }
    
    override fun onResume() {
        super.onResume()
        // Re-check permissions when returning to activity
        checkCurrentPermissions()
    }
    
    private fun isVPNPermissionGranted(): Boolean {
        val vpnIntent = VpnService.prepare(this)
        return vpnIntent == null
    }
    
    private fun isAccessibilityServiceEnabled(): Boolean {
        val enabledServices = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        )
        return enabledServices?.contains(packageName) == true
    }
    
    private fun isUsageStatsPermissionGranted(): Boolean {
        val appOps = getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
        val mode = appOps.checkOpNoThrow(
            android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
            android.os.Process.myUid(),
            packageName
        )
        return mode == android.app.AppOpsManager.MODE_ALLOWED
    }
    
    private fun markPermissionsShown() {
        val prefs = getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("permissions_shown", true).apply()
    }
    
    companion object {
        private const val REQUEST_VPN = 1001
        
        fun shouldShow(context: Context): Boolean {
            val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
            return !prefs.getBoolean("permissions_shown", false)
        }
    }
}
