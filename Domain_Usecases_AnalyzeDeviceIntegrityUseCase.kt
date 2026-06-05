package com.sentrix.domain.usecases

import com.sentrix.domain.models.DeviceInfo
import com.sentrix.domain.repositories.DeviceIntegrityRepository

/**
 * AnalyzeDeviceIntegrityUseCase
 *
 * Responsible for evaluating device integrity
 * and trustworthiness within the SentriX platform.
 *
 * This use case performs integrity verification
 * by analyzing device security posture, root or
 * jailbreak status, bootloader state, system
 * modifications, security patches, and other
 * indicators that may compromise device security.
 *
 * Used by:
 * - DeviceIntegrityManager
 * - RealtimeProtectionEngine
 * - SecurityDashboard
 * - AuthenticationManager
 * - ZeroTrustManager
 * - EndpointProtectionService
 * - ThreatAnalysisEngine
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Verify device integrity
 * - Detect root or jailbreak status
 * - Detect system tampering
 * - Assess device trust level
 * - Calculate integrity scores
 * - Generate remediation recommendations
 */
class AnalyzeDeviceIntegrityUseCase(
    private val repository: DeviceIntegrityRepository
) {

    /**
     * Executes device integrity analysis.
     *
     * @param deviceInfo Device to analyze
     *
     * @return DeviceIntegrityAnalysisResult
     */
    suspend operator fun invoke(
        deviceInfo: DeviceInfo
    ): DeviceIntegrityAnalysisResult {

        val integrityChecks =
            repository.getIntegrityChecks()

        val failedChecks =
            integrityChecks.filter { check ->
                !check.isPassed
            }

        val trustLevel =
            determineTrustLevel(
                failedChecks.size
            )

        val integrityScore =
            calculateIntegrityScore(
                integrityChecks.size,
                failedChecks.size
            )

        return DeviceIntegrityAnalysisResult(
            analyzedAt = System.currentTimeMillis(),
            deviceId = deviceInfo.deviceId,
            deviceName = deviceInfo.deviceName,
            integrityScore = integrityScore,
            trustLevel = trustLevel,
            totalChecks = integrityChecks.size,
            passedChecks =
                integrityChecks.size -
                    failedChecks.size,
            failedChecks = failedChecks,
            recommendations =
                generateRecommendations(
                    trustLevel
                )
        )
    }

    /**
     * Determines device trust level.
     */
    private fun determineTrustLevel(
        failedChecks: Int
    ): DeviceTrustLevel {

        return when {

            failedChecks >= 5 ->
                DeviceTrustLevel.UNTRUSTED

            failedChecks >= 3 ->
                DeviceTrustLevel.HIGH_RISK

            failedChecks >= 1 ->
                DeviceTrustLevel.MODERATE_RISK

            else ->
                DeviceTrustLevel.TRUSTED
        }
    }

    /**
     * Calculates integrity score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateIntegrityScore(
        totalChecks: Int,
        failedChecks: Int
    ): Int {

        if (totalChecks == 0) return 0

        return (
            ((totalChecks - failedChecks)
                .toDouble() / totalChecks) * 100
            ).toInt()
    }

    /**
     * Generates integrity-related
     * security recommendations.
     */
    private fun generateRecommendations(
        trustLevel: DeviceTrustLevel
    ): List<String> {

        return when (trustLevel) {

            DeviceTrustLevel.UNTRUSTED -> listOf(
                "Block access to sensitive resources",
                "Perform complete security review",
                "Restore device integrity",
                "Reinstall trusted system software"
            )

            DeviceTrustLevel.HIGH_RISK -> listOf(
                "Review failed integrity checks",
                "Update device security patches",
                "Run advanced security scan"
            )

            DeviceTrustLevel.MODERATE_RISK -> listOf(
                "Investigate integrity anomalies",
                "Monitor device continuously"
            )

            DeviceTrustLevel.TRUSTED -> listOf(
                "Device integrity verified",
                "Continue routine monitoring"
            )
        }
    }
}

/**
 * DeviceIntegrityAnalysisResult
 *
 * Represents the outcome of
 * device integrity analysis.
 */
data class DeviceIntegrityAnalysisResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Device identifier.
     */
    val deviceId: String,

    /**
     * Device name.
     */
    val deviceName: String,

    /**
     * Calculated integrity score.
     */
    val integrityScore: Int,

    /**
     * Device trust level.
     */
    val trustLevel: DeviceTrustLevel,

    /**
     * Total integrity checks performed.
     */
    val totalChecks: Int,

    /**
     * Number of passed checks.
     */
    val passedChecks: Int,

    /**
     * Failed integrity checks.
     */
    val failedChecks:
        List<DeviceIntegrityCheck>,

    /**
     * Security recommendations.
     */
    val recommendations: List<String>
)

/**
 * DeviceIntegrityCheck
 *
 * Represents a single integrity
 * verification result.
 */
data class DeviceIntegrityCheck(

    /**
     * Check identifier.
     */
    val checkId: String,

    /**
     * Check name.
     */
    val checkName: String,

    /**
     * Check category.
     */
    val category: IntegrityCheckCategory,

    /**
     * Indicates whether the
     * check passed successfully.
     */
    val isPassed: Boolean,

    /**
     * Result description.
     */
    val description: String,

    /**
     * Check timestamp.
     */
    val checkedAt: Long
)

/**
 * Integrity verification categories.
 */
enum class IntegrityCheckCategory {

    /**
     * Root detection verification.
     */
    ROOT_DETECTION,

    /**
     * Jailbreak detection verification.
     */
    JAILBREAK_DETECTION,

    /**
     * Bootloader verification.
     */
    BOOTLOADER_SECURITY,

    /**
     * System file integrity.
     */
    SYSTEM_INTEGRITY,

    /**
     * Security patch verification.
     */
    SECURITY_PATCH,

    /**
     * Certificate validation.
     */
    CERTIFICATE_VALIDATION,

    /**
     * Application integrity.
     */
    APPLICATION_INTEGRITY,

    /**
     * Runtime protection verification.
     */
    RUNTIME_PROTECTION
}

/**
 * Device trust indicators.
 */
enum class DeviceTrustLevel {

    /**
     * Device is fully trusted.
     */
    TRUSTED,

    /**
     * Minor risks detected.
     */
    MODERATE_RISK,

    /**
     * Significant risks detected.
     */
    HIGH_RISK,

    /**
     * Device cannot be trusted.
     */
    UNTRUSTED
}
