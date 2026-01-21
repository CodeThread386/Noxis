package com.security.guardian.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import com.security.guardian.R
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.ThreatEvent
import com.security.guardian.detection.BehaviorDetectionEngine
import com.security.guardian.download.DownloadMonitor
import com.security.guardian.filesystem.FileSystemMonitor
import com.security.guardian.filesystem.FileTracker
import com.security.guardian.ml.RansomwareClassifier
import com.security.guardian.monitoring.UsageStatsMonitor
import com.security.guardian.network.VPNInterceptionService
import com.security.guardian.notification.ThreatNotificationService
import com.security.guardian.packagemonitor.PackageMonitor
import com.security.guardian.ui.MainActivity
import kotlinx.coroutines.*

/**
 * Main coordinating service that starts all protection modules
 */
class RansomwareProtectionService : Service() {
    
    private val TAG = "RansomwareProtectionService"
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    private lateinit var detectionEngine: BehaviorDetectionEngine
    private lateinit var mlClassifier: RansomwareClassifier
    private lateinit var fileSystemMonitor: FileSystemMonitor
    private lateinit var downloadMonitor: DownloadMonitor
    private lateinit var packageMonitor: PackageMonitor
    private lateinit var usageStatsMonitor: UsageStatsMonitor
    private lateinit var notificationService: ThreatNotificationService
    private lateinit var database: RansomwareDatabase
    private lateinit var fileTracker: FileTracker
    
    override fun onCreate() {
        super.onCreate()
        
        try {
            detectionEngine = BehaviorDetectionEngine(this)
            database = RansomwareDatabase.getDatabase(this)
            notificationService = ThreatNotificationService(this)
            
            // Initialize ML classifier (may fail if model not available)
            try {
                mlClassifier = RansomwareClassifier(this)
            } catch (e: Exception) {
                Log.w(TAG, "ML Classifier not available, continuing without it", e)
                // Will use fallback heuristics
            }
            
            fileSystemMonitor = FileSystemMonitor(this, detectionEngine, database, notificationService)
            fileTracker = FileTracker(this, database, detectionEngine, notificationService)
            downloadMonitor = DownloadMonitor(this, database, notificationService)
            downloadMonitor.initialize(fileTracker)
            
            // Initialize package monitor (may fail on some devices)
            try {
                packageMonitor = PackageMonitor(this)
            } catch (e: Exception) {
                Log.w(TAG, "PackageMonitor initialization failed", e)
                // Will skip package monitoring
            }
            
            // Initialize usage stats monitor
            try {
                usageStatsMonitor = UsageStatsMonitor(this)
            } catch (e: Exception) {
                Log.w(TAG, "UsageStatsMonitor initialization failed", e)
                // Will skip usage stats monitoring
            }
            
            createNotificationChannel()
            Log.d(TAG, "Service initialized successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Critical error in service onCreate", e)
            // Don't crash - try to continue with minimal functionality
        }
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            startForeground(NOTIFICATION_ID, createNotification())
            
            serviceScope.launch {
                try {
                    startProtection()
                } catch (e: Exception) {
                    Log.e(TAG, "Error starting protection modules", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in onStartCommand", e)
            // Try to show notification anyway
            try {
                startForeground(NOTIFICATION_ID, createNotification())
            } catch (e2: Exception) {
                Log.e(TAG, "Failed to start foreground service", e2)
            }
        }
        
        return START_STICKY
    }
    
    private suspend fun startProtection() {
        try {
            // Start file system monitoring
            if (::fileSystemMonitor.isInitialized) {
                fileSystemMonitor.startMonitoring()
                Log.d(TAG, "File system monitoring started")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start file system monitoring", e)
        }
        
        try {
            // Start download monitoring
            if (::downloadMonitor.isInitialized) {
                downloadMonitor.startMonitoring()
                Log.d(TAG, "Download monitoring started")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start download monitoring", e)
        }
        
        try {
            // Start file tracking and periodic scanning
            if (::fileTracker.isInitialized) {
                // Start periodic scanning every hour
                fileTracker.startPeriodicScanning(intervalMinutes = 60)
                Log.d(TAG, "File tracking and periodic scanning started")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start file tracking", e)
        }
        
        try {
            // Start package monitoring
            if (::packageMonitor.isInitialized) {
                packageMonitor.startMonitoring()
                Log.d(TAG, "Package monitoring started")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start package monitoring", e)
        }
        
        try {
            // Start usage stats monitoring
            if (::usageStatsMonitor.isInitialized && hasUsageStatsPermission()) {
                usageStatsMonitor.startMonitoring()
                usageStatsMonitor.addAnomalyCallback { anomaly ->
                    serviceScope.launch {
                        try {
                            handleUsageAnomaly(anomaly)
                        } catch (e: Exception) {
                            Log.e(TAG, "Error handling usage anomaly", e)
                        }
                    }
                }
                Log.d(TAG, "Usage stats monitoring started")
            } else {
                Log.w(TAG, "UsageStats permission not granted or monitor not initialized")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start usage stats monitoring", e)
        }
        
        // Start VPN service (user must grant permission separately)
        // VPN is started from MainActivity after user approval
    }
    
    private suspend fun handleUsageAnomaly(anomaly: UsageStatsMonitor.AnomalyDetection) {
        // Create threat event
        val threat = ThreatEvent(
            type = "USAGE_ANOMALY",
            packageName = anomaly.packageName,
            description = "${anomaly.anomalyType}: ${anomaly.description}",
            severity = when (anomaly.severity) {
                UsageStatsMonitor.Severity.CRITICAL -> "CRITICAL"
                UsageStatsMonitor.Severity.HIGH -> "HIGH"
                UsageStatsMonitor.Severity.MEDIUM -> "MEDIUM"
                UsageStatsMonitor.Severity.LOW -> "LOW"
            },
            confidence = anomaly.metrics.anomalyScore,
            timestamp = System.currentTimeMillis(),
            status = "DETECTED",
            indicators = listOf(anomaly.description).toString()
        )
        
        database.threatEventDao().insertThreat(threat)
        notificationService.notifyThreat(threat)
    }
    
    private fun hasUsageStatsPermission(): Boolean {
        val appOps = getSystemService(APP_OPS_SERVICE) as android.app.AppOpsManager
        val mode = appOps.checkOpNoThrow(
            android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
            android.os.Process.myUid(),
            packageName
        )
        return mode == android.app.AppOpsManager.MODE_ALLOWED
    }
    
    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Ransomware Protection",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }
    
    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Ransomware Protection Active")
            .setContentText("Monitoring for threats")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onDestroy() {
        super.onDestroy()
        try {
            if (::fileSystemMonitor.isInitialized) {
                fileSystemMonitor.stopMonitoring()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping file system monitor", e)
        }
        
        try {
            if (::downloadMonitor.isInitialized) {
                downloadMonitor.stopMonitoring()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping download monitor", e)
        }
        
        try {
            if (::packageMonitor.isInitialized) {
                packageMonitor.stopMonitoring()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping package monitor", e)
        }
        
        try {
            if (::usageStatsMonitor.isInitialized) {
                usageStatsMonitor.stopMonitoring()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping usage stats monitor", e)
        }
        
        try {
            if (::mlClassifier.isInitialized) {
                mlClassifier.cleanup()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error cleaning up ML classifier", e)
        }
        
        serviceScope.cancel()
    }
    
    companion object {
        private const val CHANNEL_ID = "ransomware_protection"
        private const val NOTIFICATION_ID = 1
    }
}
