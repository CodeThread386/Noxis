package com.security.guardian.ui.fragments

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.security.guardian.R
import com.security.guardian.network.AdBlocker
import com.security.guardian.network.VPNInterceptionService
import com.security.guardian.services.RansomwareProtectionService
import kotlinx.coroutines.launch

class ProtectionControlsFragment : Fragment() {
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_protection_controls, container, false)
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupProtectionToggles(view)
    }
    
    private fun setupProtectionToggles(view: View) {
        val prefs = requireContext().getSharedPreferences("ransomware_guard", Context.MODE_PRIVATE)
        val context = requireContext()
        
        view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.realtimeToggle)?.apply {
            isChecked = prefs.getBoolean("realtime_enabled", true)
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean("realtime_enabled", isChecked).apply()
                // Restart service to apply changes
                restartProtectionService(context)
            }
        }
        
        view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.vpnToggle)?.apply {
            isChecked = prefs.getBoolean("vpn_enabled", false)
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean("vpn_enabled", isChecked).apply()
                if (isChecked) {
                    // Request VPN permission if needed
                    (requireActivity() as? com.security.guardian.ui.MainActivity)?.checkPermissions()
                }
            }
        }
        
        view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.ransomwareToggle)?.apply {
            isChecked = prefs.getBoolean("ransomware_enabled", true)
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean("ransomware_enabled", isChecked).apply()
                restartProtectionService(context)
            }
        }
        
        view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.maxDetectionToggle)?.apply {
            isChecked = prefs.getBoolean("max_detection_enabled", false)
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean("max_detection_enabled", isChecked).apply()
                restartProtectionService(context)
            }
        }
        
        // Universal Ad Blocker toggle - Brave-style with auto VPN start
        val adBlockerToggle = view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.adBlockerToggle)
        val adBlocker = AdBlocker(context)
        adBlockerToggle?.apply {
            isChecked = adBlocker.isEnabled()
            setOnCheckedChangeListener { _, isChecked ->
                adBlocker.setEnabled(isChecked)
                
                // Auto-start VPN when ad blocker is enabled (Brave-style)
                if (isChecked) {
                    // Enable VPN toggle and start VPN service
                    prefs.edit().putBoolean("vpn_enabled", true).apply()
                    view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.vpnToggle)?.isChecked = true
                    
                    // Request VPN permission and start service
                    val activity = requireActivity() as? com.security.guardian.ui.MainActivity
                    activity?.let { act ->
                        val vpnIntent = android.net.VpnService.prepare(context)
                        if (vpnIntent != null) {
                            // Request VPN permission
                            act.startActivityForResult(vpnIntent, 1001)
                        } else {
                            // VPN permission already granted, start service
                            val intent = Intent(context, VPNInterceptionService::class.java).apply {
                                action = VPNInterceptionService.ACTION_START
                            }
                            context.startForegroundService(intent)
                        }
                    }
                    
                    // Force start VPN immediately (CRITICAL for ad blocking)
                    val vpnIntent = android.net.VpnService.prepare(context)
                    if (vpnIntent == null) {
                        // VPN permission already granted, start immediately
                        val intent = Intent(context, VPNInterceptionService::class.java).apply {
                            action = VPNInterceptionService.ACTION_START
                        }
                        try {
                            context.startForegroundService(intent)
                            Toast.makeText(context, 
                                "✅ Ad Blocker enabled - VPN started! Ads will be blocked from YouTube and all apps.", 
                                Toast.LENGTH_LONG
                            ).show()
                        } catch (e: Exception) {
                            android.util.Log.e("ProtectionControls", "Error starting VPN", e)
                            Toast.makeText(context, 
                                "⚠️ Error starting VPN. Please restart the app and try again.", 
                                Toast.LENGTH_LONG
                            ).show()
                        }
                    } else {
                        // Request VPN permission
                        Toast.makeText(context, 
                            "🛡️ Ad Blocker enabled - Please grant VPN permission when prompted to block ads", 
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    
                    // Update ad block lists in background
                    viewLifecycleOwner.lifecycleScope.launch {
                        if (adBlocker.isUpdateNeeded()) {
                            Toast.makeText(context, "Updating ad block lists...", Toast.LENGTH_SHORT).show()
                            val success = adBlocker.updateAdBlockLists()
                            if (success) {
                                Toast.makeText(context, "✅ Ad block lists updated - Ready to block ads!", Toast.LENGTH_LONG).show()
                            } else {
                                Toast.makeText(context, "Using cached ad block lists", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                } else {
                    Toast.makeText(context, "Ad Blocker disabled", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
    
    private fun restartProtectionService(context: Context) {
        try {
            val intent = Intent(context, RansomwareProtectionService::class.java)
            context.stopService(intent)
            context.startForegroundService(intent)
        } catch (e: Exception) {
            android.util.Log.e("ProtectionControls", "Error restarting service", e)
        }
    }
}
