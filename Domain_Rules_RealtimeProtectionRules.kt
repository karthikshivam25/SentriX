package com.sentrix.domain.rules

/**
 * SentriX Realtime Protection Rules
 *
 * Centralized rules for deciding realtime protection actions,
 * threat interception, automatic blocking, quarantine handling,
 * and protection state management.
 */
object RealtimeProtectionRules {

    enum class ProtectionStatus {
        ENABLED,
        DISABLED,
        DEGRADED,
        EMERGENCY_MODE
    }

    enum class ProtectionAction {
        ALLOW,
        MONITOR,
        WARN,
        BLOCK,
        QUARANTINE
    }

    /**
     * Determine protection action from threat score.
     */
    fun determineAction(
        threatScore: Int,
        confidenceScore: Double
    ): ProtectionAction {

        return when {
            threatScore >= 90 && confidenceScore >= 0.8 ->
                ProtectionAction.QUARANTINE

            threatScore >= 75 ->
                ProtectionAction.BLOCK

            threatScore >= 50 ->
                ProtectionAction.WARN

            threatScore >= 25 ->
                ProtectionAction.MONITOR

            else ->
                ProtectionAction.ALLOW
        }
    }

    /**
     * Calculate realtime protection score.
     */
    fun calculateProtectionScore(
        activeThreats: Int,
        blockedThreats: Int,
        quarantinedThreats: Int,
        failedProtectionEvents: Int
    ): Int {

        var score = 100

        score += blockedThreats
        score += quarantinedThreats * 2

        score -= activeThreats * 5
        score -= failedProtectionEvents * 10

        return score.coerceIn(0, 100)
    }

    /**
     * Determine protection status.
     */
    fun determineStatus(
        protectionScore: Int
    ): ProtectionStatus {

        return when {
            protectionScore >= 85 ->
                ProtectionStatus.ENABLED

            protectionScore >= 60 ->
                ProtectionStatus.DEGRADED

            protectionScore >= 30 ->
                ProtectionStatus.DISABLED

            else ->
                ProtectionStatus.EMERGENCY_MODE
        }
    }

    /**
     * Check whether automatic blocking is allowed.
     */
    fun shouldAutoBlock(
        threatScore: Int
    ): Boolean {
        return threatScore >= 75
    }

    /**
     * Check whether quarantine is required.
     */
    fun shouldQuarantine(
        threatScore: Int,
        confidenceScore: Double
    ): Boolean {

        return threatScore >= 90 &&
                confidenceScore >= 0.8
    }

    /**
     * Check whether user notification is required.
     */
    fun shouldNotifyUser(
        action: ProtectionAction
    ): Boolean {

        return action == ProtectionAction.WARN ||
                action == ProtectionAction.BLOCK ||
                action == ProtectionAction.QUARANTINE
    }

    /**
     * Check whether emergency protection should be enabled.
     */
    fun shouldEnableEmergencyMode(
        activeCriticalThreats: Int
    ): Boolean {
        return activeCriticalThreats >= 3
    }

    /**
     * Determine whether a process should be terminated.
     */
    fun shouldTerminateProcess(
        threatScore: Int
    ): Boolean {
        return threatScore >= 85
    }

    /**
     * Determine whether a network connection should be blocked.
     */
    fun shouldBlockConnection(
        threatScore: Int
    ): Boolean {
        return threatScore >= 70
    }

    /**
     * Calculate protection confidence.
     */
    fun calculateProtectionConfidence(
        successfulDetections: Int,
        totalDetections: Int
    ): Double {

        if (totalDetections <= 0) {
            return 0.0
        }

        return successfulDetections.toDouble() /
                totalDetections.toDouble()
    }

    /**
     * Generate protection summary.
     */
    fun getProtectionSummary(
        status: ProtectionStatus
    ): String {

        return when (status) {

            ProtectionStatus.ENABLED ->
                "Realtime protection is fully operational."

            ProtectionStatus.DEGRADED ->
                "Realtime protection is operational with reduced effectiveness."

            ProtectionStatus.DISABLED ->
                "Realtime protection is disabled."

            ProtectionStatus.EMERGENCY_MODE ->
                "Emergency protection mode activated."
        }
    }

    /**
     * Recommended action for current protection state.
     */
    fun getRecommendedAction(
        status: ProtectionStatus
    ): String {

        return when (status) {

            ProtectionStatus.ENABLED ->
                "No action required."

            ProtectionStatus.DEGRADED ->
                "Review protection modules and threat logs."

            ProtectionStatus.DISABLED ->
                "Enable realtime protection immediately."

            ProtectionStatus.EMERGENCY_MODE ->
                "Activate maximum security controls and investigate threats."
        }
    }

    /**
     * Determine whether a security alert should be generated.
     */
    fun requiresSecurityAlert(
        status: ProtectionStatus
    ): Boolean {

        return status == ProtectionStatus.DEGRADED ||
                status == ProtectionStatus.DISABLED ||
                status == ProtectionStatus.EMERGENCY_MODE
    }
}
