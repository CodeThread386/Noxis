package com.security.guardian

import android.app.Application
import android.util.Log

/**
 * Main Application class for Ransomware Early Warning System
 */
class RansomwareGuardApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        Log.d("RansomwareGuardApp", "Application started")
        
        // Initialize database
        try {
            com.security.guardian.data.RansomwareDatabase.getDatabase(this)
        } catch (e: Exception) {
            Log.e("RansomwareGuardApp", "Error initializing database", e)
        }
    }
}
