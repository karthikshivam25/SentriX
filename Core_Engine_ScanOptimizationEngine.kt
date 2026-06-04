package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Scan Optimization Engine
 *
 * Responsible for:
 * - Scan performance optimization
 * - Resource utilization analysis
 * - Scan prioritization
 * - Scan strategy selection
 * - Performance recommendations
 */
class ScanOptimizationEngine {

    private val scanProfiles =
        ConcurrentHashMap<String, ScanProfile>()

    data class ScanProfile(
        val profileId: String,
        val scanDurationMs: Long,
        val cpuUsagePercent: Double,
        val memoryUsageMb: Double,
        val filesScanned: Int,
        val optimizationScore: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    enum class ScanStrategy {
        QUICK,
        BALANCED,
        DEEP,
        CUSTOM
    }

    /**
     * Analyzes scan performance and creates a profile.
     */
    suspend fun analyzeScan(
        profileId: String,
        scanDurationMs: Long,
        cpuUsagePercent: Double,
        memoryUsageMb: Double,
        filesScanned: Int
    ): NetworkResult<ScanProfile> = withContext(Dispatchers.Default) {

        try {

            val score = calculateOptimizationScore(
                scanDurationMs = scanDurationMs,
                cpuUsagePercent = cpuUsagePercent,
                memoryUsageMb = memoryUsageMb,
                filesScanned = filesScanned
            )

            val profile = ScanProfile(
                profileId = profileId,
                scanDurationMs = scanDurationMs,
                cpuUsagePercent = cpuUsagePercent,
                memoryUsageMb = memoryUsageMb,
                filesScanned = filesScanned,
                optimizationScore = score
            )

            scanProfiles[profileId] = profile

            NetworkResult.Success(profile)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Scan optimization analysis failed"
            )
        }
    }

    /**
     * Registers a scan profile.
     */
    fun registerProfile(
        profile: ScanProfile
    ) {
        scanProfiles[profile.profileId] = profile
    }

    /**
     * Retrieves a scan profile.
     */
    fun getProfile(
        profileId: String
    ): ScanProfile? {
        return scanProfiles[profileId]
    }

    /**
     * Returns all scan profiles.
     */
    fun getProfiles(): List<ScanProfile> {
        return scanProfiles.values.toList()
    }

    /**
     * Calculates optimization score.
     */
    fun calculateOptimizationScore(
        scanDurationMs: Long,
        cpuUsagePercent: Double,
        memoryUsageMb: Double,
        filesScanned: Int
    ): Int {

        var score = 100

        if (scanDurationMs > 300_000L) score -= 30
        else if (scanDurationMs > 120_000L) score -= 15

        if (cpuUsagePercent > 80) score -= 25
        else if (cpuUsagePercent > 60) score -= 10

        if (memoryUsageMb > 1024) score -= 20
        else if (memoryUsageMb > 512) score -= 10

        if (filesScanned < 100) score -= 10

        return score.coerceIn(0, 100)
    }

    /**
     * Selects the most suitable scan strategy.
     */
    fun determineScanStrategy(
        batteryLevel: Int,
        isCharging: Boolean,
        availableMemoryMb: Double
    ): ScanStrategy {

        return when {
            isCharging &&
                batteryLevel > 50 &&
                availableMemoryMb > 2048 ->
                ScanStrategy.DEEP

            batteryLevel < 20 ->
                ScanStrategy.QUICK

            availableMemoryMb < 512 ->
                ScanStrategy.QUICK

            else ->
                ScanStrategy.BALANCED
        }
    }

    /**
     * Calculates average optimization score.
     */
    fun calculateAverageScore(): Int {

        if (scanProfiles.isEmpty()) {
            return 0
        }

        return scanProfiles.values
            .map { it.optimizationScore }
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Returns optimization level.
     */
    fun getOptimizationLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "EXCELLENT"
            score >= 75 -> "GOOD"
            score >= 50 -> "FAIR"
            score >= 25 -> "POOR"
            else -> "CRITICAL"
        }
    }

    /**
     * Generates optimization recommendations.
     */
    fun generateRecommendations(
        score: Int
    ): List<String> {

        return when {
            score >= 90 -> listOf(
                "Scan performance is highly optimized."
            )

            score >= 75 -> listOf(
                "Performance is good.",
                "Continue current scan configuration."
            )

            score >= 50 -> listOf(
                "Reduce scan scope where possible.",
                "Monitor resource consumption."
            )

            score >= 25 -> listOf(
                "Optimize memory usage.",
                "Adjust scan scheduling."
            )

            else -> listOf(
                "Scan performance is degraded.",
                "Use quick scan mode.",
                "Review optimization settings."
            )
        }
    }

    /**
     * Removes a scan profile.
     */
    fun removeProfile(
        profileId: String
    ) {
        scanProfiles.remove(profileId)
    }

    /**
     * Clears all scan profiles.
     */
    fun clearProfiles() {
        scanProfiles.clear()
    }

    /**
     * Returns total profile count.
     */
    fun getProfileCount(): Int {
        return scanProfiles.size
    }

    /**
     * Returns highly optimized profiles.
     */
    fun getOptimizedProfiles(
        minimumScore: Int = 90
    ): List<ScanProfile> {
        return scanProfiles.values.filter {
            it.optimizationScore >= minimumScore
        }
    }
}
