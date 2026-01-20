package com.security.guardian.ui.fragments

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.security.guardian.R
import com.security.guardian.network.PIILeakTracker
import com.security.guardian.network.VPNInterceptionService
import com.security.guardian.quarantine.AppQuarantineManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Network Insights Fragment - Industry-grade network monitoring display
 * Shows blocked domains, top blocked domains, and PII leak detection
 */
class NetworkInsightsFragment : Fragment() {
    
    private lateinit var blockedDomainsCountText: TextView
    private lateinit var topBlockedDomainsText: TextView
    private lateinit var piiLeaksText: TextView
    
    private var piiLeakTracker: PIILeakTracker? = null
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_network, container, false)
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        blockedDomainsCountText = view.findViewById(R.id.blockedDomainsCountText)
        topBlockedDomainsText = view.findViewById(R.id.topBlockedDomainsText)
        piiLeaksText = view.findViewById(R.id.piiLeaksText)
        
        piiLeakTracker = PIILeakTracker(requireContext())
        
        // Load network insights
        loadNetworkInsights()
        
        // Refresh every 5 seconds
        viewLifecycleOwner.lifecycleScope.launch {
            while (true) {
                kotlinx.coroutines.delay(5000)
                loadNetworkInsights()
            }
        }
    }
    
    private fun loadNetworkInsights() {
        viewLifecycleOwner.lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    // Get blocked domains count from VPN service
                    val blockedCount = getBlockedDomainsCount()
                    val topDomains = getTopBlockedDomains(10)
                    val piiLeaks = piiLeakTracker?.getAllLeaks() ?: emptyList()
                    
                    withContext(Dispatchers.Main) {
                        updateUI(blockedCount, topDomains, piiLeaks)
                    }
                } catch (e: Exception) {
                    android.util.Log.e("NetworkInsights", "Error loading network insights", e)
                }
            }
        }
    }
    
    private fun updateUI(blockedCount: Int, topDomains: List<String>, piiLeaks: List<PIILeakTracker.PIILeak>) {
        // Update blocked domains count
        blockedDomainsCountText.text = "Blocked Domains: $blockedCount"
        
        // Update top blocked domains
        if (topDomains.isNotEmpty()) {
            val domainsText = topDomains.joinToString("\n") { "• $it" }
            topBlockedDomainsText.text = "Top Blocked Domains:\n$domainsText"
        } else {
            topBlockedDomainsText.text = "No domains blocked yet"
        }
        
        // Update PII leaks
        if (piiLeaks.isNotEmpty()) {
            val leaksByType = piiLeaks.groupBy { it.type }
            val leaksText = buildString {
                append("PII Leaks Detected: ${piiLeaks.size}\n\n")
                leaksByType.forEach { (type, leaks) ->
                    append("${type.name}: ${leaks.size}\n")
                    leaks.take(3).forEach { leak ->
                        append("  • ${leak.value} → ${leak.domain}\n")
                    }
                    if (leaks.size > 3) {
                        append("  ... and ${leaks.size - 3} more\n")
                    }
                }
            }
            piiLeaksText.text = leaksText
        } else {
            piiLeaksText.text = "No PII leaks detected"
        }
    }
    
    private fun getBlockedDomainsCount(): Int {
        return try {
            // Try to get from VPN service via SharedPreferences
            val prefs = requireContext().getSharedPreferences("vpn_stats", Context.MODE_PRIVATE)
            prefs.getInt("blocked_domains_count", 0)
        } catch (e: Exception) {
            0
        }
    }
    
    private fun getTopBlockedDomains(limit: Int): List<String> {
        return try {
            // Try to get from VPN service via SharedPreferences
            val prefs = requireContext().getSharedPreferences("vpn_stats", Context.MODE_PRIVATE)
            val domainsString = prefs.getString("top_blocked_domains", "")
            if (domainsString.isNullOrEmpty()) {
                emptyList()
            } else {
                domainsString.split(",").take(limit)
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
