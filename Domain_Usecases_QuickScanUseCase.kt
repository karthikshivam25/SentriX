package com.sentrix.domain.usecases

import com.sentrix.domain.models.ScanResult
import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.repositories.ScanRepository

/**
 * QuickScanUseCase
 *
 * Responsible for performing a rapid security
 * assessment of the device, applications,
 * processes, and critical system areas within
 * the SentriX cybersecurity platform.
 *
 * Unlike a full system scan, a quick scan
 * focuses on high-risk locations, active
 * processes, installed applications, startup
 * components, temporary files, and recently
 * modified resources.
 *
 * This use case enables fast threat detection
 * while minimizing performance impact.
 *
 * Used by:
 * - SecurityDashboard
 * - RealtimeProtectionEngine
 * - ThreatAnalysisManager
 * - SecurityManager
 * - DeviceProtectionService
 * - ScanScheduler
 * - CyberDefenseManager
 * - AIThreatDetectionEngine
 *
 * Responsibilities:
 * - Perform quick security scans
 * - Analyze critical system areas
 * - Detect active threats
 * - Evaluate scan findings
 * - Calculate risk scores
 * - Generate remediation guidance
 */
class QuickScanUseCase(
    private val repository: ScanRepository
) {

    /**
     * Executes a quick security scan.
     *
     * @return QuickScanResult
     */
    suspend operator fun invoke():
        QuickScanResult {

        val scanStartedAt =
            System.currentTimeMillis()

        val scanTargets =
            repository.getQuickScanTargets()

        val scanFindings =
            repository.scanTargets(
                scanTargets
            )

        val detectedThreats =
            scanFindings.filter {
                it.isThreatDetected
            }

        val threatLevel =
            determineThreatLevel(
                detectedThreats.size
            )

        val riskScore =
            calculateRiskScore(
                detectedThreats.size
            )

        return QuickScanResult(
            scanId =
                generateScanId(),
            startedAt =
                scanStartedAt,
            completedAt =
                System.currentTimeMillis(),
            scannedTargets =
                scanTargets.size,
            detectedThreats =
                detectedThreats.size,
            threatLevel =
                threatLevel,
            riskScore =
                riskScore,
            findings =
                scanFindings,
            recommendations =
                generateRecommendations(
                    threatLevel
                )
        )
    }

    /**
     * Determines overall threat level.
     */
    private fun determineThreatLevel(
        threatCount: Int
    ): ThreatLevel {

        return when {

            threatCount >= 10 ->
                ThreatLevel.CRITICAL

            threatCount >= 5 ->
                ThreatLevel.HIGH

            threatCount >= 2 ->
                ThreatLevel.MEDIUM

            else ->
                ThreatLevel.LOW
        }
    }

    /**
     * Calculates scan risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        threatCount: Int
    ): Int {

        return (threatCount * 10)
            .coerceIn(0, 100)
    }

    /**
     * Generates scan recommendations.
     */
    private fun generateRecommendations(
        threatLevel: ThreatLevel
    ): List<String> {

        return when (threatLevel) {

            ThreatLevel.CRITICAL -> listOf(
                "Run a full system scan immediately",
                "Quarantine detected threats",
                "Enable maximum protection mode",
                "Review security alerts"
            )

            ThreatLevel.HIGH -> listOf(
                "Investigate detected threats",
                "Perform deep malware analysis",
                "Review affected applications"
            )

            ThreatLevel.MEDIUM -> listOf(
                "Monitor suspicious activity",
                "Review scan findings"
            )

            ThreatLevel.LOW -> listOf(
                "No significant threats detected",
                "Continue routine monitoring"
            )
        }
    }

    /**
     * Generates a unique scan identifier.
     */
    private fun generateScanId(): String {
        return "QUICK-${System.currentTimeMillis()}"
    }
}

/**
 * QuickScanResult
 *
 * Represents the outcome of a
 * quick security scan.
 */
data class QuickScanResult(

    /**
     * Unique scan identifier.
     */
    val scanId: String,

    /**
     * Scan start timestamp.
     */
    val startedAt: Long,

    /**
     * Scan completion timestamp.
     */
    val completedAt: Long,

    /**
     * Number of targets scanned.
     */
    val scannedTargets: Int,

    /**
     * Number of threats detected.
     */
    val detectedThreats: Int,

    /**
     * Calculated threat level.
     */
    val threatLevel: ThreatLevel,

    /**
     * Calculated risk score.
     */
    val riskScore: Int,

    /**
     * Detailed scan findings.
     */
    val findings:
        List<QuickScanFinding>,

    /**
     * Recommended actions.
     */
    val recommendations:
        List<String>
)

/**
 * QuickScanFinding
 *
 * Represents an individual
 * quick scan finding.
 */
data class QuickScanFinding(

    /**
     * Finding identifier.
     */
    val findingId: String,

    /**
     * Target scanned.
     */
    val targetName: String,

    /**
     * Target category.
     */
    val category:
        QuickScanTargetType,

    /**
     * Indicates whether a threat
     * was detected.
     */
    val isThreatDetected: Boolean,

    /**
     * Threat description.
     */
    val description: String,

    /**
     * Threat severity level.
     */
    val severity:
        ThreatLevel
)

/**
 * Quick scan target types.
 */
enum class QuickScanTargetType {

    /**
     * Running application.
     */
    APPLICATION,

    /**
     * Active process.
     */
    PROCESS,

    /**
     * Startup component.
     */
    STARTUP_ITEM,

    /**
     * Temporary file.
     */
    TEMPORARY_FILE,

    /**
     * Downloaded file.
     */
    DOWNLOAD,

    /**
     * System configuration.
     */
    SYSTEM_CONFIGURATION,

    /**
     * Browser data.
     */
    BROWSER_DATA,

    /**
     * Network activity.
     */
    NETWORK_ACTIVITY
}
