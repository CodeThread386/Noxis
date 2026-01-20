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
    
    override fun onCreate() {
        super.onCreate()
        
        detectionEngine = BehaviorDetectionEngine(this)
        mlClassifier = RansomwareClassifier(this)
        fileSystemMonitor = FileSystemMonitor(this, detectionEngine)
        downloadMonitor = DownloadMonitor(this)
        packageMonitor = PackageMonitor(this)
        usageStatsMonitor = UsageStatsMonitor(this)
        notificationService = ThreatNotificationService(this)
        database = RansomwareDatabase.getDatabase(this)
        
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, createNotification())
        
        serviceScope.launch {
            startProtection()
        }
        
        return START_STICKY
    }
    
    private suspend fun startProtection() {
        // Start file system monitoring
        fileSystemMonitor.startMonitoring()
        
        // Start download monitoring
        downloadMonitor.startMonitoring()
        
        // Start package monitoring
        packageMonitor.startMonitoring()
        
        // Start usage stats monitoring
        if (hasUsageStatsPermission()) {
            usageStatsMonitor.startMonitoring()
            usageStatsMonitor.addAnomalyCallback { anomaly ->
                serviceScope.launch {
                    handleUsageAnomaly(anomaly)
                }
            }
        } else {
            Log.w(TAG, "UsageStats permission not granted")
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
        fileSystemMonitor.stopMonitoring()
        downloadMonitor.stopMonitoring()
        packageMonitor.stopMonitoring()
        usageStatsMonitor.stopMonitoring()
        mlClassifier.cleanup()
        serviceScope.cancel()
    }
    
    companion object {
        private const val CHANNEL_ID = "ransomware_protection"
        private const val NOTIFICATION_ID = 1
    }
}
