package com.security.guardian.data.converters

import androidx.room.TypeConverter
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.security.guardian.data.entities.ThreatEvidence

/**
 * Room TypeConverter for ThreatEvidence
 */
class ThreatEvidenceConverter {
    
    private val gson = Gson()
    
    @TypeConverter
    fun fromThreatEvidence(evidence: ThreatEvidence?): String? {
        return if (evidence == null) null else gson.toJson(evidence)
    }
    
    @TypeConverter
    fun toThreatEvidence(evidenceString: String?): ThreatEvidence? {
        return if (evidenceString == null) {
            null
        } else {
            try {
                gson.fromJson(evidenceString, ThreatEvidence::class.java)
            } catch (e: Exception) {
                null
            }
        }
    }
}
