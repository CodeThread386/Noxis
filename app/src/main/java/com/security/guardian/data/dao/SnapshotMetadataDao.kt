package com.security.guardian.data.dao

import androidx.room.*
import com.security.guardian.data.entities.SnapshotMetadata

@Dao
interface SnapshotMetadataDao {
    
    @Query("SELECT * FROM snapshot_metadata WHERE originalPath = :path ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLatestSnapshot(path: String): SnapshotMetadata?
    
    @Query("SELECT * FROM snapshot_metadata ORDER BY timestamp DESC")
    suspend fun getAllSnapshots(): List<SnapshotMetadata>
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSnapshot(metadata: SnapshotMetadata): Long
    
    @Delete
    suspend fun deleteSnapshot(metadata: SnapshotMetadata)
    
    @Query("DELETE FROM snapshot_metadata WHERE timestamp < :beforeTimestamp")
    suspend fun deleteOldSnapshots(beforeTimestamp: Long)
}
