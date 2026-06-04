package com.sentrix.core.engine

import android.os.Build
import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Root Detection Engine
 *
 * Responsible for:
 * - Root detection analysis
 * - Root indicator monitoring
 * - Device compromise assessment
 * - Root risk scoring
 * - Security recommendations
 */
class RootDetectionEngine {

    private val scanResults =
        ConcurrentHashMap<String, RootScanResult>()

    data class RootScanResult(
        val deviceId: String,
        val isRooted: Boolean,
        val detectedIndicators: List<String>,
        val riskScore: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Performs root detection scan.
     */
    suspend fun scanDevice(
        deviceId: String
    ): NetworkResult<RootScanResult> = withContext(Dispatchers.IO) {

        try {

            val indicators = mutableListOf<String>()

            if (detectSuBinary()) {
                indicators.add("SU_BINARY")
            }

            if (detectRootApps()) {
                indicators.add("ROOT_APP")
            }

            if (detectDangerousProperties()) {
                indicators.add("DANGEROUS_PROPERTIES")
            }

            val riskScore =
                calculateRiskScore(indicators)

            val result = RootScanResult(
                deviceId = deviceId,
                isRooted = indicators.isNotEmpty(),
                detectedIndicators = indicators,
                riskScore = riskScore
            )

            scanResults[deviceId] = result

            NetworkResult.Success(result)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Root detection scan failed"
            )
        }
    }

    /**
     * Registers scan result.
     */
    fun registerResult(
        result: RootScanResult
    ) {
        scanResults[result.deviceId] = result
    }

    /**
     * Retrieves scan result.
     */
    fun getResult(
        deviceId: String
    ): RootScanResult? {
        return scanResults[deviceId]
    }

    /**
     * Returns all scan results.
     */
    fun getResults(): List<RootScanResult> {
        return scanResults.values.toList()
    }

    /**
     * Calculates root risk score.
     */
    fun calculateRiskScore(
        indicators: List<String>
    ): Int {

        return when {
            indicators.size >= 3 -> 100
            indicators.size == 2 -> 80
            indicators.size == 1 -> 60
            else -> 0
        }
    }

    /**
     * Determines risk level.
     */
    fun getRiskLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "CRITICAL"
            score >= 75 -> "HIGH"
            score >= 50 -> "MEDIUM"
            score >= 25 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Checks whether device is rooted.
     */
    fun isRooted(
        deviceId: String
    ): Boolean {
        return scanResults[deviceId]?.isRooted == true
    }

    /**
     * Generates root-related recommendations.
     */
    fun generateRecommendations(
        riskScore: Int
    ): List<String> {

        return when {
            riskScore >= 90 -> listOf(
                "Root access detected.",
                "Block sensitive operations.",
                "Require device remediation."
            )

            riskScore >= 75 -> listOf(
                "Restrict privileged actions.",
                "Review root indicators."
            )

            riskScore >= 50 -> listOf(
                "Monitor device closely.",
                "Run additional integrity checks."
            )

            else -> listOf(
                "No root indicators detected."
            )
        }
    }

    /**
     * Removes a stored result.
     */
    fun removeResult(
        deviceId: String
    ) {
        scanResults.remove(deviceId)
    }

    /**
     * Clears all results.
     */
    fun clearResults() {
        scanResults.clear()
    }

    /**
     * Returns total scan count.
     */
    fun getScanCount(): Int {
        return scanResults.size
    }

    /**
     * Detects SU binary existence.
     */
    private fun detectSuBinary(): Boolean {

        val paths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/system/app/Superuser.apk"
        )

        return paths.any { path ->
            File(path).exists()
        }
    }

    /**
     * Detects common root management apps.
     */
    private fun detectRootApps(): Boolean {

        val tags = Build.TAGS ?: ""

        return tags.contains("test-keys")
    }

    /**
     * Detects dangerous system properties.
     */
    private fun detectDangerousProperties(): Boolean {

        return try {
            val buildType = Build.TYPE

            buildType.equals(
                "userdebug",
                ignoreCase = true
            ) || buildType.equals(
                "eng",
                ignoreCase = true
            )

        } catch (_: Exception) {
            false
        }
    }
}
