package com.sentrix.domain.usecases

import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.repositories.ScanRepository

/**
 * SmartScanUseCase
 *
 * Responsible for performing an intelligent,
 * adaptive security scan using risk-based
 * analysis and AI-driven prioritization
 * within the SentriX cybersecurity platform.
 *
 * Unlike Quick Scan and Deep Scan, Smart Scan
 * dynamically selects scan targets based on
 * threat intelligence, user behavior,
 * application risk, device integrity,
 * historical incidents, and security posture.
 *
 * This approach provides optimal threat
 * detection while minimizing scan duration
 * and resource consumption.
 *
 * Used by:
 * - SmartScanEngine
 * - SecurityDashboard
 * - AIThreatDetectionEngine
 * - CyberDefenseManager
 * - SecurityAnalyticsPlatform
 * - ThreatAnalysisEngine
 * - DeviceProtectionService
 * - RealtimeProtectionEngine
 *
 * Responsibilities:
 * - Perform intelligent scanning
 * - Prioritize high-risk assets
 * - Detect active threats
 * - Analyze attack indicators
 * - Calculate adaptive risk scores
 * - Generate remediation recommendations
 */
class SmartScanUseCase(
    private val repository: ScanRepository
) {

    /**
     * Executes an intelligent security scan.
     *
     * @return SmartScanResult
     */
    suspend operator fun invoke():
        SmartScanResult {

        val scanStartedAt =
            System.currentTimeMillis()

        val prioritizedTargets =
            repository.getSmartScanTargets()

        val findings =
            repository.performSmartScan(
                prioritizedTargets
            )

        val threatFindings =
            findings.filter {
                it.isThreatDetected
            }

        val criticalFindings =
            findings.filter {
                it.severity ==
                    ThreatLevel.CRITICAL
            }

        val threatLevel =
            determineThreatLevel(
                threatFindings.size,
                criticalFindings.size
            )

        val riskScore =
            calculateRiskScore(
                threatFindings.size,
                criticalFindings.size
            )

        return SmartScanResult(
            scanId =
                generateScanId(),
            startedAt =
                scanStartedAt,
            completedAt =
                System.currentTimeMillis(),
            scannedTargets =
                prioritizedTargets.size,
            detectedThreats =
                threatFindings.size,
            criticalThreats =
                criticalFindings.size,
            threatLevel =
                threatLevel,
            riskScore =
                riskScore,
            findings =
                findings,
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
        threatCount: Int,
        criticalCount: Int
    ): ThreatLevel {

        return when {

            criticalCount >= 3 ->
                ThreatLevel.CRITICAL

            threatCount >= 8 ->
                ThreatLevel.HIGH

            threatCount >= 3 ->
                ThreatLevel.MEDIUM

            else ->
                ThreatLevel.LOW
        }
    }

    /**
     * Calculates adaptive risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        threatCount: Int,
        criticalCount: Int
    ): Int {

        val score =
            (threatCount * 8) +
            (criticalCount * 20)

        return score.coerceIn(0, 100)
    }

    /**
     * Generates security recommendations.
     */
    private fun generateRecommendations(
        threatLevel: ThreatLevel
    ): List<String> {

        return when (threatLevel) {

            ThreatLevel.CRITICAL -> listOf(
                "Initiate immediate containment",
                "Run Deep Scan immediately",
                "Review critical threats",
                "Notify security administrators"
            )

            ThreatLevel.HIGH -> listOf(
                "Investigate detected threats",
                "Review high-risk applications",
                "Increase monitoring sensitivity"
            )

            ThreatLevel.MEDIUM -> listOf(
                "Review suspicious findings",
                "Monitor system activity"
            )

            ThreatLevel.LOW -> listOf(
                "No significant threats detected",
                "Maintain current protection posture"
            )
        }
    }

    /**
     * Generates a unique scan identifier.
     */
    private fun generateScanId(): String {
        return "SMART-${System.currentTimeMillis()}"
    }
}

/**
 * SmartScanResult
 *
 * Represents the outcome of
 * an intelligent adaptive scan.
 */
data class SmartScanResult(

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
     * Total threats detected.
     */
    val detectedThreats: Int,

    /**
     * Critical threats detected.
     */
    val criticalThreats: Int,

    /**
     * Overall threat level.
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
        List<SmartScanFinding>,

    /**
     * Recommended actions.
     */
    val recommendations:
        List<String>
)

/**
 * SmartScanFinding
 *
 * Represents an intelligent
 * scan finding generated by
 * the Smart Scan engine.
 */
data class SmartScanFinding(

    /**
     * Finding identifier.
     */
    val findingId: String,

    /**
     * Target name.
     */
    val targetName: String,

    /**
     * Risk category.
     */
    val category:
        SmartScanCategory,

    /**
     * Threat severity.
     */
    val severity:
        ThreatLevel,

    /**
     * Indicates whether a
     * threat was detected.
     */
    val isThreatDetected: Boolean,

    /**
     * AI-generated confidence score.
     *
     * Range:
     * 0.0 - 1.0
     */
    val confidence: Double,

    /**
     * Finding description.
     */
    val description: String,

    /**
     * Suggested remediation.
     */
    val remediation: String
)

/**
 * Smart scan target categories.
 */
enum class SmartScanCategory {

    /**
     * High-risk applications.
     */
    APPLICATION,

    /**
     * User behavioral analysis.
     */
    USER_BEHAVIOR,

    /**
     * Device integrity analysis.
     */
    DEVICE_INTEGRITY,

    /**
     * Network activity analysis.
     */
    NETWORK_ACTIVITY,

    /**
     * Security configuration review.
     */
    SECURITY_CONFIGURATION,

    /**
     * Malware intelligence.
     */
    MALWARE_ANALYSIS,

    /**
     * Threat intelligence correlation.
     */
    THREAT_INTELLIGENCE,

    /**
     * Privilege and permission review.
     */
    ACCESS_CONTROL,

    /**
     * Cloud security evaluation.
     */
    CLOUD_SECURITY
}
