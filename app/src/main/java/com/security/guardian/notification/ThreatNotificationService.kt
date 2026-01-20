package com.security.guardian.notification

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.security.guardian.R
import com.security.guardian.data.entities.ThreatEvent
import com.security.guardian.ui.ThreatDetailActivity

/**
 * Service for sending threat notifications with severity levels and action buttons
 */
class ThreatNotificationService(private val context: Context) {
    
    private val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    
    init {
        createNotificationChannels()
    }
    
    private fun createNotificationChannels() {
        val channels = listOf(
            NotificationChannel(
                CHANNEL_CRITICAL,
                "Critical Threats",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Critical ransomware threats requiring immediate action"
                enableVibration(true)
                enableLights(true)
            },
            NotificationChannel(
                CHANNEL_HIGH,
                "High Priority Threats",
                NotificationManager.IMPORTANCE_HIGH
            ),
            NotificationChannel(
                CHANNEL_MEDIUM,
                "Medium Priority Threats",
                NotificationManager.IMPORTANCE_DEFAULT
            ),
            NotificationChannel(
                CHANNEL_LOW,
                "Low Priority Alerts",
                NotificationManager.IMPORTANCE_LOW
            )
        )
        
        channels.forEach { notificationManager.createNotificationChannel(it) }
    }
    
    fun notifyThreat(threat: ThreatEvent) {
        val channel = when (threat.severity) {
            "CRITICAL" -> CHANNEL_CRITICAL
            "HIGH" -> CHANNEL_HIGH
            "MEDIUM" -> CHANNEL_MEDIUM
            else -> CHANNEL_LOW
        }
        
        val intent = Intent(context, ThreatDetailActivity::class.java).apply {
            putExtra("threat_id", threat.id)
            putExtra("threat_type", threat.type)
            putExtra("description", threat.description)
            putExtra("severity", threat.severity)
            putExtra("package_name", threat.packageName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent = PendingIntent.getActivity(
            context,
            threat.id.toInt(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val notification = NotificationCompat.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(getThreatTitle(threat))
            .setContentText(threat.description)
            .setStyle(NotificationCompat.BigTextStyle().bigText(threat.description))
            .setPriority(getNotificationPriority(threat.severity))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .addAction(
                R.drawable.ic_launcher_foreground,
                "View Details",
                pendingIntent
            )
            .build()
        
        notificationManager.notify(threat.id.toInt(), notification)
    }
    
    private fun getThreatTitle(threat: ThreatEvent): String {
        return when (threat.type) {
            "RANSOMWARE_OVERLAY" -> "🚨 Ransomware Overlay Detected!"
            "SUSPICIOUS_DOWNLOAD" -> "⚠️ Suspicious Download Blocked"
            "FILE_BEHAVIOR" -> "⚠️ Ransomware Behavior Detected"
            "RANSOM_NOTE" -> "🚨 Ransom Note Found!"
            else -> "Security Alert"
        }
    }
    
    private fun getNotificationPriority(severity: String): Int {
        return when (severity) {
            "CRITICAL" -> NotificationCompat.PRIORITY_MAX
            "HIGH" -> NotificationCompat.PRIORITY_HIGH
            "MEDIUM" -> NotificationCompat.PRIORITY_DEFAULT
            else -> NotificationCompat.PRIORITY_LOW
        }
    }
    
    companion object {
        private const val CHANNEL_CRITICAL = "threat_critical"
        private const val CHANNEL_HIGH = "threat_high"
        private const val CHANNEL_MEDIUM = "threat_medium"
        private const val CHANNEL_LOW = "threat_low"
    }
}
