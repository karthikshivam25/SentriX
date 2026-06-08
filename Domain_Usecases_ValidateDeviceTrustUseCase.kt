package com.sentrix.domain.usecases

/**
 * ValidateDeviceTrustUseCase
 *
 * Responsible for validating
 * device trust status within
 * the SentriX cybersecurity
 * platform.
 *
 * Device trust validation helps:
 * - Detect compromised devices
 * - Verify device integrity
 * - Assess security posture
 * - Prevent unauthorized access
 * - Strengthen cyber defense
 *
 * Used by:
 * - DeviceIntegrityManager
 * - SecurityDashboard
 * - CyberDefenseManager
 * - TrustEvaluationEngine
 *
 * Responsibilities:
 * - Validate device trust
 * - Check security controls
 * - Evaluate device integrity
 * - Generate trust score
 * - Determine trust level
 */
class ValidateDeviceTrustUseCase {

    /**
     * Validates device trust.
     */
    operator fun invoke(
        rootDetected: Boolean,
        developerModeEnabled: Boolean,
        firewallEnabled: Boolean,
        realTimeProtectionEnabled: Boolean,
        activeThreats: Int
    ): DeviceTrustResult {

        var trustScore = 100

        if (rootDetected) {
            trustScore -= 40
        }

        if (developerModeEnabled) {
            trustScore -= 15
        }

        if (!firewallEnabled) {
            trustScore -= 15
        }

        if (!realTimeProtectionEnabled) {
            trustScore -= 20
        }

        trustScore -= activeThreats * 5

        if (trustScore < 0) {
            trustScore = 0
        }

        return DeviceTrustResult(
            validatedAt =
                System.currentTimeMillis(),

            trustScore =
                trustScore,

            trustLevel =
                determineTrustLevel(
                    trustScore
                ),

            rootDetected =
                rootDetected,

            developerModeEnabled =
                developerModeEnabled,

            firewallEnabled =
                firewallEnabled,

            realTimeProtectionEnabled =
                realTimeProtectionEnabled,

            activeThreats =
                activeThreats,

            trusted =
                trustScore >= 70
        )
    }

    /**
     * Determines trust level.
     */
    private fun determineTrustLevel(
        trustScore: Int
    ): DeviceTrustLevel {

        return when {

            trustScore >= 90 ->
                DeviceTrustLevel.TRUSTED

            trustScore >= 70 ->
                DeviceTrustLevel.SECURE

            trustScore >= 50 ->
                DeviceTrustLevel.MODERATE

            trustScore >= 25 ->
                DeviceTrustLevel.UNTRUSTED

            else ->
                DeviceTrustLevel.COMPROMISED
        }
    }
}

/**
 * DeviceTrustResult
 *
 * Represents device trust
 * validation results.
 */
data class DeviceTrustResult(

    /**
     * Validation timestamp.
     */
    val validatedAt: Long,

    /**
     * Device trust score.
     */
    val trustScore: Int,

    /**
     * Trust level.
     */
    val trustLevel:
        DeviceTrustLevel,

    /**
     * Root status.
     */
    val rootDetected: Boolean,

    /**
     * Developer mode status.
     */
    val developerModeEnabled: Boolean,

    /**
     * Firewall status.
     */
    val firewallEnabled: Boolean,

    /**
     * Real-time protection status.
     */
    val realTimeProtectionEnabled: Boolean,

    /**
     * Active threats.
     */
    val activeThreats: Int,

    /**
     * Overall trust status.
     */
    val trusted: Boolean
)

/**
 * Device trust levels.
 */
enum class DeviceTrustLevel {

    /**
     * Fully trusted device.
     */
    TRUSTED,

    /**
     * Secure device.
     */
    SECURE,

    /**
     * Moderate trust level.
     */
    MODERATE,

    /**
     * Untrusted device.
     */
    UNTRUSTED,

    /**
     * Device compromised.
     */
    COMPROMISED
}
