package com.sentrix.domain.usecases

import com.sentrix.domain.models.ScanConfiguration
import com.sentrix.domain.models.ScanStatistics
import com.sentrix.domain.repositories.ScanOptimizationRepository

/**
 * OptimizeScanUseCase
 *
 * Responsible for optimizing scan execution
 * strategies within the SentriX cybersecurity
 * platform.
 *
 * This use case analyzes historical scan data,
 * system resources, device health, threat trends,
 * and scan performance metrics to determine the
 * most efficient scan configuration.
 *
 * The objective is to maximize threat detection
 * effectiveness while minimizing CPU usage,
 * memory consumption, battery drain, and scan
 * duration.
 *
 * Used by:
 * - ScanManager
 * - SmartScanEngine
 * - SecurityAnalyticsEngine
 * - RealtimeProtectionEngine
 * - ResourceOptimizationManager
 * - CyberDefenseManager
 * - DeviceProtectionService
 * - ScanScheduler
 *
 * Responsibilities:
 * - Optimize scan performance
 * - Reduce resource consumption
 * - Improve detection efficiency
 * - Select optimal scan strategies
 * - Generate scan recommendations
 * - Support adaptive scanning
 */
class OptimizeScanUseCase(
    private val repository: ScanOptimizationRepository
) {

    /**
     * Optimizes scan configuration
     * based on available telemetry.
     *
     * @return ScanOptimizationResult
     */
    suspend operator fun invoke():
        ScanOptimizationResult {

        val statistics =
            repository.getScanStatistics()

        val systemResources =
            repository.getSystemResources()

        val recommendedConfiguration =
            generateOptimalConfiguration(
                statistics,
                systemResources
            )

        val optimizationScore =
            calculateOptimizationScore(
                statistics
            )

        return ScanOptimizationResult(
            optimizedAt =
                System.currentTimeMillis(),
            optimizationScore =
                optimizationScore,
            recommendedConfiguration =
                recommendedConfiguration,
            expectedPerformanceGain =
                estimatePerformanceGain(
                    optimizationScore
                ),
            recommendations =
                generateRecommendations(
                    optimizationScore
                )
        )
    }

    /**
     * Generates an optimized
     * scan configuration.
     */
    private fun generateOptimalConfiguration(
        statistics: ScanStatistics,
        resources: SystemResourceSnapshot
    ): ScanConfiguration {

        return ScanConfiguration(
            scanName = "Optimized Scan",
            enableHeuristicAnalysis = true,
            enableBehaviorAnalysis = true,
            enableCloudIntelligence =
                resources.networkAvailable,
            enableMemoryScan =
                resources.availableMemoryMb > 1024,
            enableDeepInspection =
                resources.cpuUsagePercent < 70,
            maximumScanThreads =
                if (resources.cpuCores >= 8) 8 else 4
        )
    }

    /**
     * Calculates optimization score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateOptimizationScore(
        statistics: ScanStatistics
    ): Int {

        val detectionRate =
            statistics.detectionRate

        val blockingRate =
            statistics.threatBlockingRate

        return (
            (detectionRate + blockingRate) / 2
        ).toInt().coerceIn(0, 100)
    }

    /**
     * Estimates performance improvement.
     */
    private fun estimatePerformanceGain(
        optimizationScore: Int
    ): Int {

        return (optimizationScore * 0.2)
            .toInt()
            .coerceIn(0, 20)
    }

    /**
     * Generates optimization guidance.
     */
    private fun generateRecommendations(
        optimizationScore: Int
    ): List<String> {

        return when {

            optimizationScore >= 90 ->
                listOf(
                    "Current scan configuration is highly optimized",
                    "Continue adaptive scanning"
                )

            optimizationScore >= 70 ->
                listOf(
                    "Minor optimization opportunities detected",
                    "Enable advanced scan features"
                )

            optimizationScore >= 50 ->
                listOf(
                    "Review scan performance settings",
                    "Adjust scan scheduling"
                )

            else ->
                listOf(
                    "Significant optimization required",
                    "Review scan strategy",
                    "Enable intelligent scanning"
                )
        }
    }
}

/**
 * ScanOptimizationResult
 *
 * Represents the outcome of
 * scan optimization analysis.
 */
data class ScanOptimizationResult(

    /**
     * Optimization timestamp.
     */
    val optimizedAt: Long,

    /**
     * Overall optimization score.
     *
     * Range:
     * 0 - 100
     */
    val optimizationScore: Int,

    /**
     * Recommended scan configuration.
     */
    val recommendedConfiguration:
        ScanConfiguration,

    /**
     * Estimated performance gain.
     *
     * Percentage improvement.
     */
    val expectedPerformanceGain: Int,

    /**
     * Optimization recommendations.
     */
    val recommendations:
        List<String>
)

/**
 * SystemResourceSnapshot
 *
 * Represents current device
 * resource availability.
 */
data class SystemResourceSnapshot(

    /**
     * Available memory in MB.
     */
    val availableMemoryMb: Long,

    /**
     * CPU usage percentage.
     */
    val cpuUsagePercent: Double,

    /**
     * Number of CPU cores.
     */
    val cpuCores: Int,

    /**
     * Available storage in MB.
     */
    val availableStorageMb: Long,

    /**
     * Battery level percentage.
     */
    val batteryLevel: Int,

    /**
     * Indicates network availability.
     */
    val networkAvailable: Boolean
)
