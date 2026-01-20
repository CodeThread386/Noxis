package com.security.guardian.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.security.guardian.R
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.filesystem.SnapshotManager
import kotlinx.coroutines.launch

/**
 * Shows detailed threat information and provides recovery actions
 */
class ThreatDetailActivity : AppCompatActivity() {
    
    private lateinit var threatTypeText: TextView
    private lateinit var descriptionText: TextView
    private lateinit var severityText: TextView
    
    private var threatId: Long = -1
    private var packageName: String? = null
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_threat_detail)
        
        threatId = intent.getLongExtra("threat_id", -1)
        val threatType = intent.getStringExtra("threat_type") ?: ""
        val description = intent.getStringExtra("description") ?: ""
        val severity = intent.getStringExtra("severity") ?: ""
        packageName = intent.getStringExtra("package_name")
        
        setupUI(threatType, description, severity)
        setupActionButtons()
    }
    
    private fun setupUI(threatType: String, description: String, severity: String) {
        threatTypeText = findViewById(R.id.threatTypeText)
        descriptionText = findViewById(R.id.descriptionText)
        severityText = findViewById(R.id.severityText)
        // indicatorsText removed - not in layout
        
        threatTypeText.text = "Threat Type: $threatType"
        descriptionText.text = description
        severityText.text = "Severity: $severity"
    }
    
    private fun setupActionButtons() {
        findViewById<Button>(R.id.blockNetworkButton).setOnClickListener {
            // Block network
        }
        
        findViewById<Button>(R.id.quarantineAppButton).setOnClickListener {
            quarantineApp()
        }
        
        findViewById<Button>(R.id.rollbackFilesButton).setOnClickListener {
            restoreFiles()
        }
        
        findViewById<Button>(R.id.stopMonitoringButton).setOnClickListener {
            // Stop monitoring
        }
        
        findViewById<Button>(R.id.dismissButton).setOnClickListener {
            dismissThreat()
        }
    }
    
    private fun quarantineApp() {
        // Quarantine app files
        lifecycleScope.launch {
            // Implementation: quarantine files
        }
    }
    
    private fun restoreFiles() {
        lifecycleScope.launch {
            val snapshotManager = SnapshotManager(this@ThreatDetailActivity)
            // Restore from snapshots
            // Implementation: restore files
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
