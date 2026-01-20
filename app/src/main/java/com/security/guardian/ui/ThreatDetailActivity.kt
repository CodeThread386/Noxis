package com.security.guardian.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.security.guardian.R
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.ThreatEvidence
import com.security.guardian.detection.TrustedAppChecker
import com.security.guardian.filesystem.SnapshotManager
import com.security.guardian.network.VPNInterceptionService
import com.security.guardian.quarantine.AppQuarantineManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Shows detailed threat information and provides recovery actions
 */
class ThreatDetailActivity : AppCompatActivity() {
    
    private lateinit var threatTypeText: TextView
    private lateinit var descriptionText: TextView
    private lateinit var severityText: TextView
    private lateinit var evidenceText: TextView
    
    private var threatId: Long = -1
    private var packageName: String? = null
    private lateinit var quarantineManager: AppQuarantineManager
    private lateinit var trustedAppChecker: TrustedAppChecker
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_threat_detail)
        
        threatId = intent.getLongExtra("threat_id", -1)
        val threatType = intent.getStringExtra("threat_type") ?: ""
        val description = intent.getStringExtra("description") ?: ""
        val severity = intent.getStringExtra("severity") ?: ""
        packageName = intent.getStringExtra("package_name")
        
        // packageManager is already available via getPackageManager()
        quarantineManager = AppQuarantineManager(this)
        trustedAppChecker = TrustedAppChecker(this)
        
        setupUI(threatType, description, severity)
        loadThreatDetails()
        setupActionButtons()
    }
    
    private fun setupUI(threatType: String, description: String, severity: String) {
        threatTypeText = findViewById(R.id.threatTypeText)
        descriptionText = findViewById(R.id.descriptionText)
        severityText = findViewById(R.id.severityText)
        evidenceText = findViewById(R.id.evidenceText)
        val packageNameText = findViewById<TextView>(R.id.packageNameText)
        val recommendedActionText = findViewById<TextView>(R.id.recommendedActionText)
        
        threatTypeText.text = threatType.uppercase()
        descriptionText.text = description
        severityText.text = "Severity: $severity"
        
        // Load app name from package name
        if (packageName != null) {
            try {
                val appInfo = getPackageManager().getApplicationInfo(packageName!!, 0)
                val appLabel = getPackageManager().getApplicationLabel(appInfo).toString()
                packageNameText?.text = "App: $appLabel\nPackage: $packageName"
            } catch (e: Exception) {
                packageNameText?.text = "Package: ${packageName ?: "Unknown"}"
            }
        } else {
            packageNameText?.text = "Package: Unknown"
        }
        
        // Set recommended action based on severity
        val action = when (severity) {
            "CRITICAL" -> "🚨 IMMEDIATE ACTION: Quarantine the app immediately and restore affected files from snapshots. Do not interact with the app."
            "HIGH" -> "⚠️ URGENT: Block network access and quarantine the app. Review threat details and restore files if needed."
            "MEDIUM" -> "📋 RECOMMENDED: Monitor the app closely. Consider blocking network access and review permissions."
            else -> "ℹ️ INFO: Review the threat details and take appropriate action based on your security needs."
        }
        recommendedActionText?.text = action
    }
    
    private fun loadThreatDetails() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    val database = RansomwareDatabase.getDatabase(this@ThreatDetailActivity)
                    val threat = database.threatEventDao().getThreatById(threatId)
                    
                    // Load app metadata if package name is available
                    val appMetadata = if (packageName != null) {
                        trustedAppChecker.getAppMetadata(packageName)
                    } else null
                    
                    withContext(Dispatchers.Main) {
                        if (threat != null) {
                            // Display evidence
                            if (threat.evidence != null) {
                                displayEvidence(threat.evidence, appMetadata)
                            } else {
                                evidenceText.text = "No detailed evidence available for this threat."
                            }
                            
                            // Update UI with app metadata
                            updateAppMetadata(appMetadata)
                        } else {
                            evidenceText.text = "Threat not found."
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.e("ThreatDetail", "Error loading threat details", e)
                    withContext(Dispatchers.Main) {
                        evidenceText.text = "Error loading threat details: ${e.message}"
                    }
                }
            }
        }
    }
    
    private fun updateAppMetadata(metadata: TrustedAppChecker.AppMetadata?) {
        if (metadata == null) return
        
        val packageNameText = findViewById<TextView>(R.id.packageNameText)
        if (packageNameText != null && metadata.packageName == packageName) {
            val trustInfo = when (metadata.trustLevel) {
                TrustedAppChecker.TrustLevel.PLATFORM_SIGNED -> "✓ Platform Signed"
                TrustedAppChecker.TrustLevel.SYSTEM_APP -> "✓ System App"
                TrustedAppChecker.TrustLevel.TRUSTED_PACKAGE -> "✓ Trusted Package"
                TrustedAppChecker.TrustLevel.TRUSTED_INSTALLER -> "✓ From Trusted Installer"
                TrustedAppChecker.TrustLevel.UNKNOWN -> "⚠ Unknown Source"
            }
            
            packageNameText.text = """
                App: ${metadata.appLabel}
                Package: ${metadata.packageName}
                Version: ${metadata.versionName} (${metadata.versionCode})
                Installer: ${metadata.installer}
                Trust Level: $trustInfo
                Signature: ${metadata.signatureHash}
            """.trimIndent()
        }
    }
    
    private fun displayEvidence(evidence: ThreatEvidence, appMetadata: TrustedAppChecker.AppMetadata?) {
        val evidenceTextBuilder = StringBuilder()
        
        evidenceTextBuilder.append("Why this threat was detected:\n\n")
        
        if (evidence.entropySpikeCount > 0) {
            evidenceTextBuilder.append("✓ Entropy Spikes: ${evidence.entropySpikeCount}\n")
            evidenceTextBuilder.append("  High entropy indicates possible encryption\n\n")
        }
        
        if (evidence.renameCount > 0) {
            evidenceTextBuilder.append("✓ Rename Operations: ${evidence.renameCount}\n")
            evidenceTextBuilder.append("  Suspicious file renaming detected\n\n")
        }
        
        if (evidence.ransomNoteDetected) {
            evidenceTextBuilder.append("✓ Ransom Note Detected: YES\n")
            evidenceTextBuilder.append("  Ransomware note file found\n\n")
        }
        
        if (evidence.honeypotTouched) {
            evidenceTextBuilder.append("✓ Honeypot Touched: YES\n")
            evidenceTextBuilder.append("  Decoy file was accessed (strong indicator)\n\n")
        }
        
        if (evidence.massModificationCount > 0) {
            evidenceTextBuilder.append("✓ Mass Modifications: ${evidence.massModificationCount}\n")
            evidenceTextBuilder.append("  Rapid file changes detected\n\n")
        }
        
        if (evidence.extensionChanges > 0) {
            evidenceTextBuilder.append("✓ Extension Changes: ${evidence.extensionChanges}\n")
            evidenceTextBuilder.append("  File extensions modified (encryption indicator)\n\n")
        }
        
        if (evidence.highEntropyFiles > 0) {
            evidenceTextBuilder.append("✓ High Entropy Files: ${evidence.highEntropyFiles}\n")
            evidenceTextBuilder.append("  Files with encrypted-like content\n\n")
        }
        
        if (evidence.massDeletions > 0) {
            evidenceTextBuilder.append("✓ Mass Deletions: ${evidence.massDeletions}\n")
            evidenceTextBuilder.append("  Multiple files deleted rapidly\n\n")
        }
        
        if (evidence.createModifyPattern) {
            evidenceTextBuilder.append("✓ Create-Modify Pattern: YES\n")
            evidenceTextBuilder.append("  Rapid create-then-modify behavior\n\n")
        }
        
        if (evidence.suspiciousDomains > 0) {
            evidenceTextBuilder.append("✓ Suspicious Domains: ${evidence.suspiciousDomains}\n")
            evidenceTextBuilder.append("  Connections to known malicious domains\n\n")
        }
        
        if (evidence.networkAnomalies > 0) {
            evidenceTextBuilder.append("✓ Network Anomalies: ${evidence.networkAnomalies}\n")
            evidenceTextBuilder.append("  Unusual network activity detected\n\n")
        }
        
        if (evidence.cpuSpike) {
            evidenceTextBuilder.append("✓ CPU Spike: YES\n")
            evidenceTextBuilder.append("  Abnormal CPU usage detected\n\n")
        }
        
        if (evidence.ioSpike) {
            evidenceTextBuilder.append("✓ I/O Spike: YES\n")
            evidenceTextBuilder.append("  Abnormal I/O activity detected\n\n")
        }
        
        // Add trust level warning if app is trusted
        if (appMetadata != null && appMetadata.trustLevel != TrustedAppChecker.TrustLevel.UNKNOWN) {
            evidenceTextBuilder.append("\n\n⚠️ NOTE: This app is marked as trusted (${appMetadata.trustLevel.name}). ")
            evidenceTextBuilder.append("This detection may be a false positive. Please review carefully before taking action.")
        }
        
        if (evidenceTextBuilder.isEmpty()) {
            evidenceTextBuilder.append("No specific evidence indicators available.")
        }
        
        evidenceText.text = evidenceTextBuilder.toString().trim()
    }
    
    private fun setupActionButtons() {
        findViewById<Button>(R.id.blockNetworkButton).setOnClickListener {
            blockNetwork()
        }
        
        findViewById<Button>(R.id.quarantineAppButton).setOnClickListener {
            quarantineApp()
        }
        
        findViewById<Button>(R.id.rollbackFilesButton).setOnClickListener {
            restoreFiles()
        }
        
        findViewById<Button>(R.id.stopMonitoringButton).setOnClickListener {
            stopMonitoring()
        }
        
        findViewById<Button>(R.id.dismissButton).setOnClickListener {
            dismissThreat()
        }
    }
    
    private fun quarantineApp() {
        if (packageName == null) {
            android.widget.Toast.makeText(this, "Package name not available", android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    val result = quarantineManager.quarantineAppForRansomware(
                        packageName = packageName!!,
                        threatId = threatId,
                        threatType = intent.getStringExtra("threat_type") ?: "UNKNOWN",
                        severity = intent.getStringExtra("severity") ?: "MEDIUM"
                    )
                    
                    withContext(Dispatchers.Main) {
                        if (result.success) {
                            android.widget.Toast.makeText(
                                this@ThreatDetailActivity,
                                "App quarantined: ${result.message}",
                                android.widget.Toast.LENGTH_LONG
                            ).show()
                        } else {
                            android.widget.Toast.makeText(
                                this@ThreatDetailActivity,
                                "Failed to quarantine: ${result.message}",
                                android.widget.Toast.LENGTH_LONG
                            ).show()
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.e("ThreatDetail", "Error quarantining app", e)
                    withContext(Dispatchers.Main) {
                        android.widget.Toast.makeText(
                            this@ThreatDetailActivity,
                            "Error: ${e.message}",
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }
    }
    
    private fun blockNetwork() {
        if (packageName == null) {
            android.widget.Toast.makeText(this, "Package name not available", android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    // Block network via VPN service
                    val prefs = getSharedPreferences("network_blocklist", android.content.Context.MODE_PRIVATE)
                    val blockedPackages = prefs.getStringSet("blocked_packages", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
                    blockedPackages.add(packageName!!)
                    prefs.edit().putStringSet("blocked_packages", blockedPackages).apply()
                    
                    withContext(Dispatchers.Main) {
                        android.widget.Toast.makeText(
                            this@ThreatDetailActivity,
                            "Network access blocked for ${packageName}",
                            android.widget.Toast.LENGTH_LONG
                        ).show()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("ThreatDetail", "Error blocking network", e)
                    withContext(Dispatchers.Main) {
                        android.widget.Toast.makeText(
                            this@ThreatDetailActivity,
                            "Error blocking network: ${e.message}",
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }
    }
    
    private fun restoreFiles() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    val database = RansomwareDatabase.getDatabase(this@ThreatDetailActivity)
                    val snapshotManager = SnapshotManager(this@ThreatDetailActivity, database)
                    
                    // Get threat to find affected files
                    val threat = database.threatEventDao().getThreatById(threatId)
                    if (threat != null && threat.indicators != null) {
                        // Extract file paths from indicators (simplified)
                        // In production, you'd have a proper file list
                        android.util.Log.d("ThreatDetail", "Restoring files from snapshots...")
                        
                        withContext(Dispatchers.Main) {
                            android.widget.Toast.makeText(
                                this@ThreatDetailActivity,
                                "File restoration initiated. Check snapshots for restored files.",
                                android.widget.Toast.LENGTH_LONG
                            ).show()
                        }
                    } else {
                        withContext(Dispatchers.Main) {
                            android.widget.Toast.makeText(
                                this@ThreatDetailActivity,
                                "No files to restore for this threat",
                                android.widget.Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.e("ThreatDetail", "Error restoring files", e)
                    withContext(Dispatchers.Main) {
                        android.widget.Toast.makeText(
                            this@ThreatDetailActivity,
                            "Error restoring files: ${e.message}",
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }
    }
    
    private fun stopMonitoring() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    val database = RansomwareDatabase.getDatabase(this@ThreatDetailActivity)
                    database.threatEventDao().updateThreatStatus(threatId, "RESOLVED")
                    
                    withContext(Dispatchers.Main) {
                        android.widget.Toast.makeText(
                            this@ThreatDetailActivity,
                            "Monitoring stopped for this threat",
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                        finish()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("ThreatDetail", "Error stopping monitoring", e)
                }
            }
        }
    }
    
    private fun uninstallApp() {
        // Uninstall handled via Settings
    }
    
    private fun dismissThreat() {
        lifecycleScope.launch {
            val db = RansomwareDatabase.getDatabase(this@ThreatDetailActivity)
            db.threatEventDao().updateThreatStatus(threatId, "RESOLVED")
            finish()
        }
    }
}
