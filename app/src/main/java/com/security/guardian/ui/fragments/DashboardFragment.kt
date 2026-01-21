package com.security.guardian.ui.fragments

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.security.guardian.R
import com.security.guardian.viewmodel.RansomwareViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class DashboardFragment : Fragment() {
    
    private lateinit var viewModel: RansomwareViewModel
    private lateinit var threatsDetectedText: TextView
    private lateinit var appsMonitoredText: TextView
    private lateinit var trackersBlockedText: TextView
    private lateinit var permissionsBlockedText: TextView
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_dashboard, container, false)
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        viewModel = ViewModelProvider(requireActivity())[RansomwareViewModel::class.java]
        
        threatsDetectedText = view.findViewById(R.id.threatsDetectedText)
        appsMonitoredText = view.findViewById(R.id.appsMonitoredText)
        trackersBlockedText = view.findViewById(R.id.trackersBlockedText)
        permissionsBlockedText = view.findViewById(R.id.permissionsBlockedText)
        
        // Setup quick action buttons
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.scanNowButton)?.setOnClickListener {
            android.widget.Toast.makeText(requireContext(), "Starting system scan...", android.widget.Toast.LENGTH_SHORT).show()
        }
        
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.viewThreatsButton)?.setOnClickListener {
            // Switch to threats tab
            (requireActivity() as? com.security.guardian.ui.MainActivity)?.let { activity ->
                activity.findViewById<androidx.viewpager2.widget.ViewPager2>(R.id.viewPager)?.currentItem = 1
            }
        }
        
        // Observe threats
        viewModel.activeThreats.observe(viewLifecycleOwner) { threats ->
            threatsDetectedText.text = "${threats?.size ?: 0}"
            animateNumberChange(threatsDetectedText, threats?.size ?: 0)
        }
        
        // Load real statistics
        loadStatistics()
        
        // Refresh statistics every 3 seconds
        viewLifecycleOwner.lifecycleScope.launch {
            while (true) {
                kotlinx.coroutines.delay(3000)
                loadStatistics()
            }
        }
    }
    
    private fun loadStatistics() {
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val context = requireContext()
                
                // Apps monitored - count only user-installed apps (not system apps)
                val packageManager = context.packageManager
                val allPackages = packageManager.getInstalledPackages(0)
                val userAppsCount = allPackages.count { packageInfo ->
                    try {
                        val appInfo = packageManager.getApplicationInfo(packageInfo.packageName, 0)
                        // Only count user-installed apps (not system apps)
                        (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 ||
                        (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    } catch (e: Exception) {
                        false
                    }
                }
                appsMonitoredText.text = "$userAppsCount"
                
                // Trackers/Ads blocked - get from VPN service stats (includes ads)
                val vpnPrefs = context.getSharedPreferences("vpn_stats", Context.MODE_PRIVATE)
                val trackersBlocked = vpnPrefs.getInt("trackers_blocked", 0)
                val adsBlocked = vpnPrefs.getInt("ads_blocked_count", 0)
                val totalBlocked = trackersBlocked + adsBlocked
                trackersBlockedText.text = "$totalBlocked"
                
                // Permissions blocked - get from permission blocker stats
                val permPrefs = context.getSharedPreferences("permission_stats", Context.MODE_PRIVATE)
                val permissionsBlocked = permPrefs.getInt("permissions_blocked", 0)
                permissionsBlockedText.text = "$permissionsBlocked"
                
            } catch (e: Exception) {
                android.util.Log.e("DashboardFragment", "Error loading statistics", e)
                // Fallback to 0
                appsMonitoredText.text = "0"
                trackersBlockedText.text = "0"
                permissionsBlockedText.text = "0"
            }
        }
    }
    
    private fun animateNumberChange(textView: TextView, newValue: Int) {
        // Simple animation for number changes
        textView.animate()
            .scaleX(1.2f)
            .scaleY(1.2f)
            .setDuration(150)
            .withEndAction {
                textView.animate()
                    .scaleX(1f)
                    .scaleY(1f)
                    .setDuration(150)
                    .start()
            }
            .start()
    }
}
