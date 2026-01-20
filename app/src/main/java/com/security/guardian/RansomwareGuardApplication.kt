package com.security.guardian

import android.app.Application
import android.content.Intent
import android.os.Build
import android.util.Log
import com.security.guardian.services.RansomwareProtectionService

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
            Log.d("RansomwareGuardApp", "Database initialized")
        } catch (e: Exception) {
            Log.e("RansomwareGuardApp", "Error initializing database", e)
            // Don't crash - database will be initialized when needed
        }
        
        // Start protection service after a delay to ensure app is fully initialized
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            startProtectionService()
        }, 1000) // 1 second delay
    }
    
    private fun startProtectionService() {
        try {
            val intent = Intent(this, RansomwareProtectionService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            Log.d("RansomwareGuardApp", "Protection service started")
        } catch (e: IllegalStateException) {
            // Service might already be running
            Log.w("RansomwareGuardApp", "Service already running or cannot start", e)
        } catch (e: Exception) {
            Log.e("RansomwareGuardApp", "Error starting protection service", e)
            // Don't crash - service can be started manually later
        }
    }
}
