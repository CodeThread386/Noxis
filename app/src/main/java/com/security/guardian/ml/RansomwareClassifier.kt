package com.security.guardian.ml

import android.content.Context
import android.util.Log
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import kotlin.math.exp

/**
 * TensorFlow Lite-based ML classifier for ransomware behavior detection
 * Uses lightweight on-device model for real-time classification
 */
class RansomwareClassifier(private val context: Context) {
    
    private val TAG = "RansomwareClassifier"
    private var interpreter: Interpreter? = null
    private val modelFileName = "ransomware_model.tflite"
    
    // Feature vector size (must match model input)
    private val featureSize = 20
    
    data class ClassificationResult(
        val isRansomware: Boolean,
        val confidence: Float,
        val features: FloatArray
    )
    
    data class BehaviorFeatures(
        val fileModificationsPerMinute: Float,
        val extensionChanges: Float,
        val highEntropyFiles: Float,
        val massDeletions: Float,
        val createModifyPattern: Float, // 0.0 or 1.0
        val suspiciousPermissions: Float,
        val overlayDetected: Float, // 0.0 or 1.0
        val networkAnomaly: Float, // 0.0 or 1.0
        val cpuUsage: Float,
        val ioOperations: Float,
        val fileSizeChanges: Float,
        val renameOperations: Float,
        val encryptionIndicators: Float,
        val ransomNoteDetected: Float, // 0.0 or 1.0
        val suspiciousDomains: Float,
        val downloadAnomaly: Float, // 0.0 or 1.0
        val processAnomaly: Float, // 0.0 or 1.0
        val memoryAnomaly: Float, // 0.0 or 1.0
        val timeOfDay: Float, // Normalized 0-1
        val userInteraction: Float // 0 = no interaction, 1 = high interaction
    )
    
    init {
        loadModel()
    }
    
    private fun loadModel() {
        try {
            val modelFile = loadModelFile(context, modelFileName)
            if (modelFile != null) {
                val options = Interpreter.Options().apply {
                    setNumThreads(4)
                    setUseNNAPI(true) // Use Neural Networks API if available
                }
                interpreter = Interpreter(modelFile, options)
                Log.d(TAG, "TensorFlow Lite model loaded successfully")
            } else {
                Log.w(TAG, "Model file not found, using fallback heuristics")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error loading TensorFlow Lite model", e)
        }
    }
    
    /**
     * Classify behavior as ransomware or benign
     */
    fun classify(features: BehaviorFeatures): ClassificationResult {
        val featureVector = extractFeatureVector(features)
        
        return if (interpreter != null) {
            classifyWithML(featureVector)
        } else {
            // Fallback to rule-based classification
            classifyWithHeuristics(features)
        }
    }
    
    private fun extractFeatureVector(features: BehaviorFeatures): FloatArray {
        return floatArrayOf(
            normalize(features.fileModificationsPerMinute, 0f, 1000f),
            normalize(features.extensionChanges, 0f, 100f),
            normalize(features.highEntropyFiles, 0f, 100f),
            normalize(features.massDeletions, 0f, 100f),
            features.createModifyPattern, // Already 0f or 1f
            normalize(features.suspiciousPermissions, 0f, 10f),
            features.overlayDetected, // Already 0f or 1f
            features.networkAnomaly, // Already 0f or 1f
            normalize(features.cpuUsage, 0f, 100f),
            normalize(features.ioOperations, 0f, 10000f),
            normalize(features.fileSizeChanges, 0f, 1000000f),
            normalize(features.renameOperations, 0f, 100f),
            normalize(features.encryptionIndicators, 0f, 100f),
            features.ransomNoteDetected, // Already 0f or 1f
            normalize(features.suspiciousDomains, 0f, 10f),
            features.downloadAnomaly, // Already 0f or 1f
            features.processAnomaly, // Already 0f or 1f
            features.memoryAnomaly, // Already 0f or 1f
            features.timeOfDay,
            features.userInteraction
        )
    }
    
    private fun normalize(value: Float, min: Float, max: Float): Float {
        return ((value - min) / (max - min)).coerceIn(0f, 1f)
    }
    
    private fun classifyWithML(featureVector: FloatArray): ClassificationResult {
        return try {
            val inputBuffer = java.nio.ByteBuffer.allocateDirect(featureVector.size * 4)
            inputBuffer.order(java.nio.ByteOrder.nativeOrder())
            featureVector.forEach { inputBuffer.putFloat(it) }
            
            val outputBuffer = java.nio.ByteBuffer.allocateDirect(2 * 4) // 2 outputs: [benign, ransomware]
            outputBuffer.order(java.nio.ByteOrder.nativeOrder())
            
            interpreter?.run(inputBuffer, outputBuffer)
            
            outputBuffer.rewind()
            val benignProb = outputBuffer.float
            val ransomwareProb = outputBuffer.float
            
            val isRansomware = ransomwareProb > benignProb
            val confidence = if (isRansomware) ransomwareProb else benignProb
            
            ClassificationResult(
                isRansomware = isRansomware,
                confidence = confidence,
                features = featureVector
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error in ML classification", e)
            ClassificationResult(false, 0f, featureVector)
        }
    }
    
    private fun classifyWithHeuristics(features: BehaviorFeatures): ClassificationResult {
        var score = 0f
        
        // Weighted heuristic scoring
        if (features.fileModificationsPerMinute > 50) score += 0.2f
        if (features.extensionChanges > 10) score += 0.3f
        if (features.highEntropyFiles > 20) score += 0.3f
        if (features.massDeletions > 30) score += 0.2f
        if (features.createModifyPattern > 0.5f) score += 0.2f
        if (features.overlayDetected > 0.5f) score += 0.4f
        if (features.ransomNoteDetected > 0.5f) score += 0.5f
        if (features.encryptionIndicators > 50) score += 0.3f
        
        val isRansomware = score >= 0.5f
        val confidence = score.coerceIn(0f, 1f)
        
        return ClassificationResult(
            isRansomware = isRansomware,
            confidence = confidence,
            features = extractFeatureVector(features)
        )
    }
    
    private fun loadModelFile(context: Context, filename: String): MappedByteBuffer? {
        return try {
            val assetFileDescriptor = context.assets.openFd(filename)
            val fileInputStream = FileInputStream(assetFileDescriptor.fileDescriptor)
            val fileChannel = fileInputStream.channel
            val startOffset = assetFileDescriptor.startOffset
            val declaredLength = assetFileDescriptor.declaredLength
            fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
        } catch (e: Exception) {
            Log.e(TAG, "Error loading model file: $filename", e)
            null
        }
    }
    
    fun cleanup() {
        interpreter?.close()
        interpreter = null
    }
}
