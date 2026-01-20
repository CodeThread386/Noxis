package com.security.guardian.ui.fragments

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.security.guardian.R
import com.security.guardian.services.RansomwareProtectionService

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
