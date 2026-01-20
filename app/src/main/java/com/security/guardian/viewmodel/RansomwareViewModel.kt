package com.security.guardian.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.viewModelScope
import com.security.guardian.data.RansomwareDatabase
import com.security.guardian.data.entities.ThreatEvent
import kotlinx.coroutines.launch

class RansomwareViewModel(application: Application) : AndroidViewModel(application) {
    
    private val database = try {
        RansomwareDatabase.getDatabase(application)
    } catch (e: Exception) {
        android.util.Log.e("RansomwareViewModel", "Error getting database", e)
        null
    }
    
    private val threatDao = database?.threatEventDao()
    
    val allThreats: LiveData<List<ThreatEvent>> = threatDao?.getAllThreats() 
        ?: androidx.lifecycle.MutableLiveData<List<ThreatEvent>>().apply { value = emptyList() }
    val activeThreats: LiveData<List<ThreatEvent>> = threatDao?.getActiveThreats()
        ?: androidx.lifecycle.MutableLiveData<List<ThreatEvent>>().apply { value = emptyList() }
    
    fun insertThreat(threat: ThreatEvent) {
        viewModelScope.launch {
            try {
                threatDao?.insertThreat(threat)
            } catch (e: Exception) {
                android.util.Log.e("RansomwareViewModel", "Error inserting threat", e)
            }
        }
    }
    
    fun updateThreatStatus(id: Long, status: String) {
        viewModelScope.launch {
            try {
                threatDao?.updateThreatStatus(id, status)
            } catch (e: Exception) {
                android.util.Log.e("RansomwareViewModel", "Error updating threat status", e)
            }
        }
    }
}
