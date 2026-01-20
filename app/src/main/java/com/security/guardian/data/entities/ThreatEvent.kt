package com.security.guardian.data.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "threat_events")
data class ThreatEvent(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val type: String, // RANSOMWARE_OVERLAY, SUSPICIOUS_DOWNLOAD, FILE_BEHAVIOR, etc.
    val packageName: String?,
    val description: String,
    val severity: String, // LOW, MEDIUM, HIGH, CRITICAL
    val confidence: Float, // 0.0 to 1.0
    val timestamp: Long,
    val status: String, // DETECTED, RESOLVED, QUARANTINED
    val indicators: String? // JSON array of indicators
)
