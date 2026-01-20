package com.security.guardian.ui.fragments

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Switch
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.security.guardian.R

class SettingsFragment : Fragment() {
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_settings, container, false)
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        val prefs = requireContext().getSharedPreferences("ransomware_guard", Context.MODE_PRIVATE)
        
        // Setup switches
        view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.notificationsSwitch)?.apply {
            isChecked = prefs.getBoolean("notifications_enabled", true)
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean("notifications_enabled", isChecked).apply()
            }
        }
        
        view.findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.autoScanSwitch)?.apply {
            isChecked = prefs.getBoolean("auto_scan_enabled", true)
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean("auto_scan_enabled", isChecked).apply()
            }
        }
        
        // Setup permission buttons
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.vpnPermissionButton)?.setOnClickListener {
            val intent = Intent(android.provider.Settings.ACTION_VPN_SETTINGS)
            startActivity(intent)
        }
        
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.accessibilityPermissionButton)?.setOnClickListener {
            val intent = Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS)
            startActivity(intent)
        }
        
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.usageStatsPermissionButton)?.setOnClickListener {
            val intent = Intent(android.provider.Settings.ACTION_USAGE_ACCESS_SETTINGS)
            startActivity(intent)
        }
    }
}
