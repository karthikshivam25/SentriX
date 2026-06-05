package com.sentrix.domain.usecases

import com.sentrix.domain.repositories.RootDetectionRepository

/**
 * DetectRootUseCase
 *
 * Responsible for detecting whether an Android
 * device has been rooted or compromised through
 * privilege escalation techniques.
 *
 * Root detection is a critical security control
 * used by SentriX to evaluate device trust,
 * enforce Zero Trust policies, protect sensitive
 * information, and prevent unauthorized access
 * to protected resources.
 *
 * This use case aggregates multiple root
 * detection techniques to improve detection
 * accuracy and reduce false positives.
 *
 * Used by:
 * - DeviceIntegrityManager
 * - SecurityManager
 * - AuthenticationManager
 * - ZeroTrustManager
 * - DeviceComplianceEngine
 * - RealtimeProtectionEngine
 * - ThreatAnalysisEngine
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Detect rooted devices
 * - Verify device trustworthiness
 * - Identify root indicators
 * - Calculate root risk scores
 * - Support access control decisions
 * - Generate remediation recommendations
 */
class DetectRootUseCase(
    private val repository: RootDetectionRepository
) {

    /**
     * Executes root detection analysis.
     *
     * @return RootDetectionResult
     */
    suspend operator fun invoke():
        RootDetectionResult {

        val indicators =
            repository.getRootIndicators()

        val detectedIndicators =
            indicators.filter {
                it.isDetected
            }

        val rootStatus =
            determineRootStatus(
                detectedIndicators.size
            )

        val riskScore =
            calculateRiskScore(
                detectedIndicators.size
            )

        return RootDetectionResult(
            analyzedAt = System.currentTimeMillis(),
            isRooted =
                rootStatus != RootStatus.CLEAN,
            rootStatus = rootStatus,
            riskScore = riskScore,
            detectedIndicators =
                detectedIndicators,
            recommendations =
                generateRecommendations(
                    rootStatus
                )
        )
    }

    /**
     * Determines device root status.
     */
    private fun determineRootStatus(
        indicatorCount: Int
    ): RootStatus {

        return when {

            indicatorCount >= 5 ->
                RootStatus.CONFIRMED_ROOTED

            indicatorCount >= 3 ->
                RootStatus.LIKELY_ROOTED

            indicatorCount >= 1 ->
                RootStatus.SUSPICIOUS

            else ->
                RootStatus.CLEAN
        }
    }

    /**
     * Calculates root risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        indicatorCount: Int
    ): Int {

        return (indicatorCount * 20)
            .coerceIn(0, 100)
    }

    /**
     * Generates security recommendations
     * based on root detection results.
     */
    private fun generateRecommendations(
        status: RootStatus
    ): List<String> {

        return when (status) {

            RootStatus.CONFIRMED_ROOTED -> listOf(
                "Block access to sensitive resources",
                "Disable high-risk functionality",
                "Restore device to secure state",
                "Reinstall official firmware"
            )

            RootStatus.LIKELY_ROOTED -> listOf(
                "Perform advanced integrity checks",
                "Restrict privileged operations",
                "Review device security posture"
            )

            RootStatus.SUSPICIOUS -> listOf(
                "Monitor device continuously",
                "Perform additional verification"
            )

            RootStatus.CLEAN -> listOf(
                "No root indicators detected",
                "Continue routine monitoring"
            )
        }
    }
}

/**
 * RootDetectionResult
 *
 * Represents the outcome of
 * root detection analysis.
 */
data class RootDetectionResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Indicates whether the
     * device appears rooted.
     */
    val isRooted: Boolean,

    /**
     * Determined root status.
     */
    val rootStatus: RootStatus,

    /**
     * Calculated risk score.
     */
    val riskScore: Int,

    /**
     * Detected root indicators.
     */
    val detectedIndicators:
        List<RootIndicator>,

    /**
     * Recommended actions.
     */
    val recommendations: List<String>
)

/**
 * RootIndicator
 *
 * Represents a root detection
 * indicator discovered during
 * device inspection.
 */
data class RootIndicator(

    /**
     * Indicator identifier.
     */
    val indicatorId: String,

    /**
     * Indicator name.
     */
    val name: String,

    /**
     * Detailed description.
     */
    val description: String,

    /**
     * Indicator category.
     */
    val category:
        RootIndicatorCategory,

    /**
     * Indicates whether the
     * indicator was detected.
     */
    val isDetected: Boolean
)

/**
 * Root detection categories.
 */
enum class RootIndicatorCategory {

    /**
     * Root binary detection.
     */
    ROOT_BINARY,

    /**
     * Superuser application detection.
     */
    SUPERUSER_APP,

    /**
     * Magisk detection.
     */
    MAGISK,

    /**
     * BusyBox detection.
     */
    BUSYBOX,

    /**
     * Dangerous system property.
     */
    SYSTEM_PROPERTY,

    /**
     * Writable system partition.
     */
    SYSTEM_PARTITION,

    /**
     * SELinux configuration issue.
     */
    SELINUX,

    /**
     * Runtime root evidence.
     */
    RUNTIME_EVIDENCE
}

/**
 * Root status indicators.
 */
enum class RootStatus {

    /**
     * Device appears clean.
     */
    CLEAN,

    /**
     * Suspicious indicators found.
     */
    SUSPICIOUS,

    /**
     * Device is likely rooted.
     */
    LIKELY_ROOTED,

    /**
     * Device is confirmed rooted.
     */
    CONFIRMED_ROOTED
}
