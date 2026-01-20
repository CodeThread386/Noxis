package com.security.guardian.data.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "snapshot_metadata")
data class SnapshotMetadata(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val originalPath: String,
    val snapshotPath: String,
    val timestamp: Long,
    val fileSize: Long,
    val encrypted: Boolean = true
)
