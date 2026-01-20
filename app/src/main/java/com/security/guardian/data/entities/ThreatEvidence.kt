package com.security.guardian.data.entities

import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Structured evidence data for ransomware threats
 * Embedded in ThreatEvent for detailed evidence tracking
 */
data class ThreatEvidence(
    val entropySpikeCount: Int = 0,
    val renameCount: Int = 0,
    val ransomNoteDetected: Boolean = false,
    val honeypotTouched: Boolean = false,
    val massModificationCount: Int = 0,
    val extensionChanges: Int = 0,
    val highEntropyFiles: Int = 0,
    val massDeletions: Int = 0,
    val createModifyPattern: Boolean = false,
    val suspiciousDomains: Int = 0,
    val networkAnomalies: Int = 0,
    val cpuSpike: Boolean = false,
    val ioSpike: Boolean = false
)
