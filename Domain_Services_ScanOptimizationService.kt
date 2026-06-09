package com.sentrix.domain.services

import com.sentrix.domain.models.ScanConfiguration
import com.sentrix.domain.models.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for scan optimization.
 *
 * This service analyzes scan performance,
 * recommends optimal scan settings,
 * and improves scanning efficiency.
 */
class ScanOptimizationService {

    /**
     * Optimizes scan configuration based on
     * previous scan results.
     */
    suspend fun optimizeScanConfiguration(
        scanResults: List<ScanResult>
    ): ScanConfiguration = withContext(Dispatchers.Default) {

        val averageThreats = if (scanResults.isNotEmpty()) {
            scanResults.sumOf { it.threatsDetected } / scanResults.size
        } else {
            0
        }

        ScanConfiguration(
            scanType = when {
                averageThreats >= 20 -> "DEEP"
                averageThreats >= 5 -> "SMART"
                else -> "QUICK"
            },
            enableRealtimeMonitoring = averageThreats > 0,
            scanSystemApps = averageThreats >= 5,
            scanExternalStorage = averageThreats >= 10
        )
    }

    /**
     * Calculates average scan duration.
     */
    suspend fun calculateAverageScanDuration(
        scanResults: List<ScanResult>
    ): Long = withContext(Dispatchers.Default) {

        if (scanResults.isEmpty()) {
            return@withContext 0L
        }

        scanResults.sumOf {
            it.scanDuration
        } / scanResults.size
    }

    /**
     * Calculates scan success rate.
     *
     * Formula:
     * Successful Scans / Total Scans * 100
     */
    suspend fun calculateScanSuccessRate(
        scanResults: List<ScanResult>
    ): Double = withContext(Dispatchers.Default) {

        if (scanResults.isEmpty()) {
            return@withContext 0.0
        }

        val successfulScans = scanResults.count {
            it.scanCompleted
        }

        (successfulScans.toDouble() / scanResults.size) * 100
    }

    /**
     * Returns scans that detected threats.
     */
    suspend fun getThreatDetectedScans(
        scanResults: List<ScanResult>
    ): List<ScanResult> = withContext(Dispatchers.Default) {

        scanResults.filter {
            it.threatsDetected > 0
        }
    }

    /**
     * Returns failed scans.
     */
    suspend fun getFailedScans(
        scanResults: List<ScanResult>
    ): List<ScanResult> = withContext(Dispatchers.Default) {

        scanResults.filter {
            !it.scanCompleted
        }
    }

    /**
     * Determines the recommended scan type.
     */
    suspend fun recommendScanType(
        scanResults: List<ScanResult>
    ): String = withContext(Dispatchers.Default) {

        val threats = scanResults.sumOf {
            it.threatsDetected
        }

        when {
            threats >= 50 -> "DEEP"
            threats >= 10 -> "SMART"
            else -> "QUICK"
        }
    }

    /**
     * Calculates scan efficiency score.
     *
     * Score is based on:
     * - Successful completion rate
     * - Threat detection capability
     */
    suspend fun calculateScanEfficiencyScore(
        scanResults: List<ScanResult>
    ): Int = withContext(Dispatchers.Default) {

        if (scanResults.isEmpty()) {
            return@withContext 0
        }

        val successRate = calculateScanSuccessRate(scanResults)

        successRate.toInt().coerceIn(0, 100)
    }

    /**
     * Generates optimization recommendations.
     */
    suspend fun generateOptimizationRecommendations(
        scanResults: List<ScanResult>
    ): List<String> = withContext(Dispatchers.Default) {

        val recommendations = mutableListOf<String>()

        if (scanResults.any { !it.scanCompleted }) {
            recommendations.add(
                "Investigate failed scans and improve scan stability."
            )
        }

        if (scanResults.sumOf { it.threatsDetected } > 20) {
            recommendations.add(
                "Enable deep scans for enhanced threat detection."
            )
        }

        if (scanResults.size > 10) {
            recommendations.add(
                "Schedule scans during low system activity periods."
            )
        }

        if (recommendations.isEmpty()) {
            recommendations.add(
                "Current scan configuration appears optimized."
            )
        }

        recommendations
    }

    /**
     * Generates scan optimization summary.
     */
    suspend fun generateOptimizationSummary(
        scanResults: List<ScanResult>
    ): String = withContext(Dispatchers.Default) {

        val totalScans = scanResults.size

        val successfulScans = scanResults.count {
            it.scanCompleted
        }

        val detectedThreats = scanResults.sumOf {
            it.threatsDetected
        }

        val averageDuration =
            calculateAverageScanDuration(scanResults)

        buildString {
            appendLine("SentriX Scan Optimization Summary")
            appendLine("---------------------------------")
            appendLine("Total Scans: $totalScans")
            appendLine("Successful Scans: $successfulScans")
            appendLine("Detected Threats: $detectedThreats")
            appendLine("Average Duration: ${averageDuration}ms")
            appendLine(
                "Recommended Scan Type: ${
                    recommendScanType(scanResults)
                }"
            )
        }
    }

    /**
     * Determines whether scan performance
     * is considered healthy.
     */
    suspend fun isScanPerformanceHealthy(
        scanResults: List<ScanResult>
    ): Boolean = withContext(Dispatchers.Default) {

        calculateScanSuccessRate(scanResults) >= 90.0
    }
}
