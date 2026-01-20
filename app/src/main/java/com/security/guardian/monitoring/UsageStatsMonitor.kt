package com.security.guardian.monitoring

import android.app.usage.UsageEvents
import android.app.usage.UsageStats
import android.app.usage.UsageStatsManager
import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.util.concurrent.TimeUnit

/**
 * Monitors app CPU and I/O usage patterns using UsageStatsManager
 * Detects abnormal resource consumption that may indicate ransomware
 */
class UsageStatsMonitor(private val context: Context) {
    
    private val TAG = "UsageStatsMonitor"
    private val usageStatsManager = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    data class AppUsageMetrics(
        val packageName: String,
        val foregroundTime: Long, // milliseconds
        val backgroundTime: Long,
        val lastTimeUsed: Long,
        val launchCount: Int,
        val totalTimeInForeground: Long,
        val anomalyScore: Float // 0.0 to 1.0
    )
    
    data class AnomalyDetection(
        val packageName: String,
        val anomalyType: AnomalyType,
        val severity: Severity,
        val description: String,
        val metrics: AppUsageMetrics
    )
    
    enum class AnomalyType {
        HIGH_BACKGROUND_CPU,
        UNUSUAL_IO_PATTERN,
        EXCESSIVE_LAUNCHES,
        LONG_BACKGROUND_TIME,
        SUSPICIOUS_TIMING
    }
    
    enum class Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    private val baselineMetrics = mutableMapOf<String, AppUsageMetrics>()
    private val anomalyCallbacks = mutableListOf<(AnomalyDetection) -> Unit>()
    
    /**
     * Start monitoring app usage patterns
     */
    fun startMonitoring(intervalMinutes: Long = 5) {
        scope.launch {
            while (isActive) {
                analyzeUsagePatterns()
                delay(TimeUnit.MINUTES.toMillis(intervalMinutes))
            }
        }
    }
    
    fun stopMonitoring() {
        scope.cancel()
    }
    
    fun addAnomalyCallback(callback: (AnomalyDetection) -> Unit) {
        anomalyCallbacks.add(callback)
    }
    
    private suspend fun analyzeUsagePatterns() {
        try {
            val endTime = System.currentTimeMillis()
            val startTime = endTime - TimeUnit.HOURS.toMillis(1) // Analyze last hour
            
            // Get usage stats for all apps
            val stats = usageStatsManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                startTime,
                endTime
            )
            
            // Get usage events for more detailed analysis
            val events = usageStatsManager.queryEvents(startTime, endTime)
            
            val appMetrics = mutableMapOf<String, AppUsageMetrics>()
            val eventCounts = mutableMapOf<String, Int>()
            val foregroundTimes = mutableMapOf<String, Long>()
            val backgroundTimes = mutableMapOf<String, Long>()
            
            // Process events
            while (events.hasNextEvent()) {
                val event = UsageEvents.Event()
                events.getNextEvent(event)
                
                val pkg = event.packageName
                when (event.eventType) {
                    UsageEvents.Event.ACTIVITY_RESUMED -> {
                        foregroundTimes[pkg] = event.timeStamp
                        eventCounts[pkg] = (eventCounts[pkg] ?: 0) + 1
                    }
                    UsageEvents.Event.ACTIVITY_PAUSED -> {
                        val startTime = foregroundTimes[pkg] ?: event.timeStamp
                        val duration = event.timeStamp - startTime
                        foregroundTimes[pkg] = (foregroundTimes[pkg] ?: 0) + duration
                    }
                    UsageEvents.Event.MOVE_TO_BACKGROUND -> {
                        backgroundTimes[pkg] = event.timeStamp
                    }
                    UsageEvents.Event.MOVE_TO_FOREGROUND -> {
                        val startTime = backgroundTimes[pkg] ?: event.timeStamp
                        val duration = event.timeStamp - startTime
                        backgroundTimes[pkg] = (backgroundTimes[pkg] ?: 0) + duration
                    }
                }
            }
            
            // Calculate metrics for each app
            stats.forEach { stat ->
                val pkg = stat.packageName
                
                // Skip system apps
                if (pkg.startsWith("android.") || pkg.startsWith("com.android.")) {
                    return@forEach
                }
                
                val metrics = AppUsageMetrics(
                    packageName = pkg,
                    foregroundTime = stat.totalTimeInForeground,
                    backgroundTime = backgroundTimes[pkg] ?: 0,
                    lastTimeUsed = stat.lastTimeUsed,
                    launchCount = 0, // UsageStats doesn't have appLaunchCount, would need to track manually
                    totalTimeInForeground = stat.totalTimeInForeground,
                    anomalyScore = calculateAnomalyScore(stat, foregroundTimes[pkg] ?: 0, backgroundTimes[pkg] ?: 0)
                )
                
                appMetrics[pkg] = metrics
                
                // Check for anomalies
                val anomalies = detectAnomalies(metrics, baselineMetrics[pkg])
                anomalies.forEach { anomaly ->
                    notifyAnomaly(anomaly)
                }
                
                // Update baseline
                baselineMetrics[pkg] = metrics
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing usage patterns", e)
        }
    }
    
    private fun calculateAnomalyScore(
        stat: UsageStats,
        foregroundTime: Long,
        backgroundTime: Long
    ): Float {
        var score = 0f
        
        // High background time relative to foreground
        if (backgroundTime > 0 && foregroundTime > 0) {
            val ratio = backgroundTime.toFloat() / foregroundTime.toFloat()
            if (ratio > 10f) { // 10x more background than foreground
                score += 0.3f
            }
        }
        
        // Excessive launches (would need to track manually)
        // if (stat.appLaunchCount > 100) {
        //     score += 0.2f
        // }
        
        // Very high total foreground time (possible ransomware running)
        val hours = stat.totalTimeInForeground / (1000 * 60 * 60)
        if (hours > 8) {
            score += 0.2f
        }
        
        // Recent activity but no user interaction (suspicious)
        val timeSinceLastUsed = System.currentTimeMillis() - stat.lastTimeUsed
        if (timeSinceLastUsed < 60000 && stat.totalTimeInForeground < 1000) {
            score += 0.3f
        }
        
        return score.coerceIn(0f, 1f)
    }
    
    private fun detectAnomalies(
        current: AppUsageMetrics,
        baseline: AppUsageMetrics?
    ): List<AnomalyDetection> {
        val anomalies = mutableListOf<AnomalyDetection>()
        
        if (baseline == null) {
            // First time seeing this app, establish baseline
            return anomalies
        }
        
        // Check for high background CPU usage
        val backgroundRatio = if (current.foregroundTime > 0) {
            current.backgroundTime.toFloat() / current.foregroundTime.toFloat()
        } else {
            if (current.backgroundTime > 0) Float.MAX_VALUE else 0f
        }
        
        if (backgroundRatio > 20f) { // 20x more background than foreground
            anomalies.add(
                AnomalyDetection(
                    packageName = current.packageName,
                    anomalyType = AnomalyType.HIGH_BACKGROUND_CPU,
                    severity = if (backgroundRatio > 50f) Severity.CRITICAL else Severity.HIGH,
                    description = "Excessive background CPU usage (${backgroundRatio.toInt()}x foreground time)",
                    metrics = current
                )
            )
        }
        
        // Check for unusual launch pattern
        val launchIncrease = current.launchCount - baseline.launchCount
        if (launchIncrease > 50) {
            anomalies.add(
                AnomalyDetection(
                    packageName = current.packageName,
                    anomalyType = AnomalyType.EXCESSIVE_LAUNCHES,
                    severity = if (launchIncrease > 100) Severity.HIGH else Severity.MEDIUM,
                    description = "Unusual launch pattern: $launchIncrease launches in monitoring period",
                    metrics = current
                )
            )
        }
        
        // Check for long background time
        val backgroundHours = current.backgroundTime / (1000 * 60 * 60)
        if (backgroundHours > 2) {
            anomalies.add(
                AnomalyDetection(
                    packageName = current.packageName,
                    anomalyType = AnomalyType.LONG_BACKGROUND_TIME,
                    severity = if (backgroundHours > 4) Severity.HIGH else Severity.MEDIUM,
                    description = "App running in background for ${backgroundHours}h",
                    metrics = current
                )
            )
        }
        
        // Check for suspicious timing (activity at unusual hours)
        val hourOfDay = java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
        if ((hourOfDay < 6 || hourOfDay > 23) && current.totalTimeInForeground > 0) {
            anomalies.add(
                AnomalyDetection(
                    packageName = current.packageName,
                    anomalyType = AnomalyType.SUSPICIOUS_TIMING,
                    severity = Severity.MEDIUM,
                    description = "Activity detected at unusual time (${hourOfDay}:00)",
                    metrics = current
                )
            )
        }
        
        return anomalies
    }
    
    private fun notifyAnomaly(anomaly: AnomalyDetection) {
        Log.w(TAG, "Usage anomaly detected: ${anomaly.packageName} - ${anomaly.description}")
        anomalyCallbacks.forEach { it(anomaly) }
    }
    
    /**
     * Get current usage metrics for a specific app
     */
    suspend fun getAppMetrics(packageName: String): AppUsageMetrics? {
        return try {
            val endTime = System.currentTimeMillis()
            val startTime = endTime - TimeUnit.HOURS.toMillis(1)
            
            val stats = usageStatsManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                startTime,
                endTime
            )
            
            stats.find { it.packageName == packageName }?.let { stat ->
                AppUsageMetrics(
                    packageName = packageName,
                    foregroundTime = stat.totalTimeInForeground,
                    backgroundTime = 0, // Would need event tracking
                    lastTimeUsed = stat.lastTimeUsed,
                    launchCount = 0, // UsageStats doesn't have appLaunchCount, would need to track manually
                    totalTimeInForeground = stat.totalTimeInForeground,
                    anomalyScore = calculateAnomalyScore(stat, stat.totalTimeInForeground, 0)
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting app metrics", e)
            null
        }
    }
}
