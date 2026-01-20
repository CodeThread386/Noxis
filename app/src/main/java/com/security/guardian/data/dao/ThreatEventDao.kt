package com.security.guardian.data.dao

import androidx.lifecycle.LiveData
import androidx.room.*
import com.security.guardian.data.entities.ThreatEvent

@Dao
interface ThreatEventDao {
    
    @Query("SELECT * FROM threat_events ORDER BY timestamp DESC")
    fun getAllThreats(): LiveData<List<ThreatEvent>>
    
    @Query("SELECT * FROM threat_events WHERE status = 'DETECTED' ORDER BY timestamp DESC")
    fun getActiveThreats(): LiveData<List<ThreatEvent>>
    
    @Query("SELECT * FROM threat_events WHERE id = :id")
    suspend fun getThreatById(id: Long): ThreatEvent?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreat(event: ThreatEvent): Long
    
    @Update
    suspend fun updateThreat(event: ThreatEvent)
    
    @Query("UPDATE threat_events SET status = :status WHERE id = :id")
    suspend fun updateThreatStatus(id: Long, status: String)
    
    @Query("DELETE FROM threat_events WHERE timestamp < :beforeTimestamp")
    suspend fun deleteOldThreats(beforeTimestamp: Long)
}
