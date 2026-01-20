package com.security.guardian.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import android.view.Menu
import android.view.MenuItem
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import com.security.guardian.R
import com.security.guardian.network.VPNInterceptionService
import com.security.guardian.ui.adapters.MainPagerAdapter
import com.security.guardian.viewmodel.RansomwareViewModel

/**
 * Main Activity with tabbed interface
 * Shows: Dashboard, Threats, Recovery, Settings
 */
class MainActivity : AppCompatActivity() {
    
    private lateinit var viewModel: RansomwareViewModel
    private lateinit var viewPager: ViewPager2
    private lateinit var tabLayout: TabLayout
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_main)
            
            viewModel = ViewModelProvider(this)[RansomwareViewModel::class.java]
            
            setupUI()
            // Don't check permissions immediately - let app load first
            // checkPermissions()
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Error in onCreate", e)
            // Show simple error message
            android.widget.Toast.makeText(this, "App initialization error. Please restart.", android.widget.Toast.LENGTH_LONG).show()
        }
    }
    
    private fun setupUI() {
        try {
            viewPager = findViewById(R.id.viewPager)
            tabLayout = findViewById(R.id.tabLayout)
            
            val adapter = MainPagerAdapter(this)
            viewPager.adapter = adapter
            
            TabLayoutMediator(tabLayout, viewPager) { tab, position ->
                tab.text = when (position) {
                    0 -> "Dashboard"
                    1 -> "Threats"
                    2 -> "Recovery"
                    3 -> "Settings"
                    else -> ""
                }
            }.attach()
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Error in setupUI", e)
        }
    }
    
    private fun checkPermissions() {
        // Check VPN permission
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, REQUEST_VPN)
        }
        
        // Check Accessibility permission
        if (!isAccessibilityServiceEnabled()) {
            showAccessibilityPermissionDialog()
        }
    }
    
    private fun isAccessibilityServiceEnabled(): Boolean {
        val enabledServices = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        )
        return enabledServices?.contains(packageName) == true
    }
    
    private fun showAccessibilityPermissionDialog() {
        AlertDialog.Builder(this)
            .setTitle("Accessibility Permission Required")
            .setMessage("This app needs Accessibility permission to detect ransomware overlays and lock-screen hijacking. This permission is used only for security monitoring with your explicit consent.")
            .setPositiveButton("Grant Permission") { _, _ ->
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
            .setNegativeButton("Later", null)
            .show()
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startVPNService()
        }
    }
    
    private fun startVPNService() {
        val intent = Intent(this, VPNInterceptionService::class.java).apply {
            action = VPNInterceptionService.ACTION_START
        }
        startForegroundService(intent)
    }
    
    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        // Menu removed - settings are in Settings tab
        return true
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return super.onOptionsItemSelected(item)
    }
    
    companion object {
        private const val REQUEST_VPN = 1001
    }
}
