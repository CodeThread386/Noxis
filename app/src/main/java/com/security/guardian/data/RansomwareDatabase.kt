package com.security.guardian.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.security.guardian.data.dao.ThreatEventDao
import com.security.guardian.data.dao.SnapshotMetadataDao
import com.security.guardian.data.entities.ThreatEvent
import com.security.guardian.data.entities.SnapshotMetadata

@Database(
    entities = [ThreatEvent::class, SnapshotMetadata::class],
    version = 1,
    exportSchema = false
)
abstract class RansomwareDatabase : RoomDatabase() {
    
    abstract fun threatEventDao(): ThreatEventDao
    abstract fun snapshotMetadataDao(): SnapshotMetadataDao
    
    companion object {
        @Volatile
        private var INSTANCE: RansomwareDatabase? = null
        
        fun getDatabase(context: Context): RansomwareDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    RansomwareDatabase::class.java,
                    "ransomware_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
