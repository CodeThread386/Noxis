package com.security.guardian.accessibility

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.security.guardian.detection.BehaviorDetectionEngine

/**
 * AccessibilityService for detecting overlay and lock-screen ransom UIs
 * Also automates safe UI interactions (dismiss overlays, guide to uninstall)
 * 
 * IMPORTANT: Requires explicit user consent and clear explanation
 */
class OverlayDetectionService : AccessibilityService() {
    
    private val TAG = "OverlayDetectionService"
    private val detectionEngine = BehaviorDetectionEngine(this)
    
    // Ransomware UI indicators
    private val ransomKeywords = listOf(
        "your files have been encrypted",
        "pay bitcoin",
        "decrypt your files",
        "payment required",
        "your data is locked",
        "ransom",
        "bitcoin address"
    )
    
    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                checkForRansomwareOverlay(event)
            }
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                checkForRansomwareContent(event)
            }
            AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED -> {
                checkNotificationForRansomware(event)
            }
        }
    }
    
    override fun onInterrupt() {
        // Service interrupted
    }
    
    private fun checkForRansomwareOverlay(event: AccessibilityEvent) {
        val packageName = event.packageName?.toString() ?: return
        val className = event.className?.toString() ?: ""
        
        // Check for suspicious overlay windows
        if (isOverlayWindow(className)) {
            Log.w(TAG, "Suspicious overlay detected from: $packageName")
            
            // Get window content
            val rootNode = rootInActiveWindow
            if (rootNode != null) {
                val content = extractTextContent(rootNode)
                if (containsRansomwareKeywords(content)) {
                    handleRansomwareOverlay(packageName, rootNode)
                }
            }
        }
    }
    
    private fun checkForRansomwareContent(event: AccessibilityEvent) {
        val text = event.text?.joinToString(" ") ?: ""
        if (containsRansomwareKeywords(text)) {
            val packageName = event.packageName?.toString() ?: "unknown"
            Log.e(TAG, "Ransomware content detected in package: $packageName")
            handleRansomwareDetected(packageName, text)
        }
    }
    
    private fun checkNotificationForRansomware(event: AccessibilityEvent) {
        val text = event.text?.joinToString(" ") ?: ""
        if (containsRansomwareKeywords(text)) {
            val packageName = event.packageName?.toString() ?: "unknown"
            Log.w(TAG, "Ransomware notification detected from: $packageName")
        }
    }
    
    private fun isOverlayWindow(className: String): Boolean {
        // Check for common overlay window types
        val overlayIndicators = listOf(
            "Overlay",
            "Floating",
            "SystemAlertWindow",
            "TYPE_APPLICATION_OVERLAY"
        )
        return overlayIndicators.any { className.contains(it, ignoreCase = true) }
    }
    
    private fun containsRansomwareKeywords(text: String): Boolean {
        val lowerText = text.lowercase()
        return ransomKeywords.any { keyword ->
            lowerText.contains(keyword, ignoreCase = true)
        }
    }
    
    private fun extractTextContent(node: AccessibilityNodeInfo?): String {
        if (node == null) return ""
        
        val text = node.text?.toString() ?: ""
        val contentDescription = node.contentDescription?.toString() ?: ""
        
        val childrenText = (0 until node.childCount).joinToString(" ") { index ->
            extractTextContent(node.getChild(index))
        }
        
        return "$text $contentDescription $childrenText"
    }
    
    private fun handleRansomwareOverlay(packageName: String, rootNode: AccessibilityNodeInfo) {
        // Attempt to dismiss overlay
        dismissOverlay(rootNode)
        
        // Notify user
        notifyCriticalThreat(
            type = "RANSOMWARE_OVERLAY",
            packageName = packageName,
            description = "Ransomware overlay detected. Attempting to dismiss."
        )
        
        // Guide user to uninstall
        guideUserToUninstall(packageName)
    }
    
    private fun handleRansomwareDetected(packageName: String, content: String) {
        notifyCriticalThreat(
            type = "RANSOMWARE_UI",
            packageName = packageName,
            description = "Ransomware UI detected: ${content.take(100)}"
        )
    }
    
    private fun dismissOverlay(rootNode: AccessibilityNodeInfo) {
        // Try to find and click dismiss/close buttons
        val dismissButtons = findDismissButtons(rootNode)
        dismissButtons.forEach { button ->
            performClick(button)
        }
        
        // Try back gesture
        performGlobalAction(GLOBAL_ACTION_BACK)
    }
    
    private fun findDismissButtons(rootNode: AccessibilityNodeInfo): List<AccessibilityNodeInfo> {
        val buttons = mutableListOf<AccessibilityNodeInfo>()
        
        fun searchNode(node: AccessibilityNodeInfo?) {
            if (node == null) return
            
            val text = node.text?.toString()?.lowercase() ?: ""
            val contentDesc = node.contentDescription?.toString()?.lowercase() ?: ""
            
            if (node.isClickable && (
                text.contains("close") || text.contains("dismiss") || 
                text.contains("cancel") || contentDesc.contains("close") ||
                contentDesc.contains("dismiss")
            )) {
                buttons.add(AccessibilityNodeInfo.obtain(node))
            }
            
            for (i in 0 until node.childCount) {
                searchNode(node.getChild(i))
            }
        }
        
        searchNode(rootNode)
        return buttons
    }
    
    private fun performClick(node: AccessibilityNodeInfo) {
        val bounds = android.graphics.Rect()
        node.getBoundsInScreen(bounds)
        
        val path = Path().apply {
            moveTo(bounds.centerX().toFloat(), bounds.centerY().toFloat())
        }
        
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, 100))
            .build()
        
        dispatchGesture(gesture, object : GestureResultCallback() {
            override fun onCompleted(gestureDescription: GestureDescription?) {
                Log.d(TAG, "Click gesture completed")
            }
            
            override fun onCancelled(gestureDescription: GestureDescription?) {
                Log.d(TAG, "Click gesture cancelled")
            }
        }, null)
    }
    
    private fun guideUserToUninstall(packageName: String) {
        // Open app settings for uninstall
        val intent = android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = android.net.Uri.parse("package:$packageName")
            flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(intent)
        
        // Show notification with instructions
        showUninstallGuidance(packageName)
    }
    
    private fun showUninstallGuidance(packageName: String) {
        // Create notification with uninstall steps
        // Implementation in notification service
    }
    
    private fun notifyCriticalThreat(type: String, packageName: String, description: String) {
        // Send critical threat notification
        // Implementation in notification service
    }
}
