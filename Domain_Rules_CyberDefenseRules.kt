package com.sentrix.domain.rules

/**
 * SentriX Cyber Defense Rules
 *
 * Master security orchestration rules responsible for
 * evaluating overall cyber defense posture, activating
 * defense mechanisms, coordinating responses, and
 * determining defense readiness levels.
 */
object CyberDefenseRules {

    enum class DefenseLevel {
        NORMAL,
        ELEVATED,
        HIGH_ALERT,
        CRITICAL
    }

    enum class DefenseAction {
        MONITOR,
        HARDEN_SECURITY,
        RESTRICT_OPERATIONS,
        EMERGENCY_RESPONSE
    }

    /**
     * Calculate overall cyber defense score.
     */
    fun calculateDefenseScore(
        riskScore: Int,
        protectionScore: Int,
        deviceTrustScore: Int,
        networkTrustScore: Int,
        activeThreats: Int
    ): Int {

        val score =
            (100 - riskScore) * 0.35 +
            protectionScore * 0.25 +
            deviceTrustScore * 0.20 +
            networkTrustScore * 0.20 -
            (activeThreats * 2)

        return score.toInt()
            .coerceIn(0, 100)
    }

    /**
     * Determine current defense level.
     */
    fun determineDefenseLevel(
        defenseScore: Int
    ): DefenseLevel {

        return when {
            defenseScore >= 85 ->
                DefenseLevel.NORMAL

            defenseScore >= 65 ->
                DefenseLevel.ELEVATED

            defenseScore >= 40 ->
                DefenseLevel.HIGH_ALERT

            else ->
                DefenseLevel.CRITICAL
        }
    }

    /**
     * Determine recommended defense action.
     */
    fun determineDefenseAction(
        defenseLevel: DefenseLevel
    ): DefenseAction {

        return when (defenseLevel) {

            DefenseLevel.NORMAL ->
                DefenseAction.MONITOR

            DefenseLevel.ELEVATED ->
                DefenseAction.HARDEN_SECURITY

            DefenseLevel.HIGH_ALERT ->
                DefenseAction.RESTRICT_OPERATIONS

            DefenseLevel.CRITICAL ->
                DefenseAction.EMERGENCY_RESPONSE
        }
    }

    /**
     * Determine whether emergency mode should be enabled.
     */
    fun shouldEnableEmergencyMode(
        activeThreats: Int,
        riskScore: Int
    ): Boolean {

        return activeThreats >= 5 ||
                riskScore >= 90
    }

    /**
     * Determine whether sensitive operations should be restricted.
     */
    fun shouldRestrictSensitiveOperations(
        defenseLevel: DefenseLevel
    ): Boolean {

        return defenseLevel == DefenseLevel.HIGH_ALERT ||
                defenseLevel == DefenseLevel.CRITICAL
    }

    /**
     * Determine whether advanced protection should be activated.
     */
    fun shouldActivateAdvancedProtection(
        defenseLevel: DefenseLevel
    ): Boolean {

        return defenseLevel == DefenseLevel.ELEVATED ||
                defenseLevel == DefenseLevel.HIGH_ALERT ||
                defenseLevel == DefenseLevel.CRITICAL
    }

    /**
     * Determine whether realtime protection is mandatory.
     */
    fun requiresRealtimeProtection(
        riskScore: Int
    ): Boolean {
        return riskScore >= 40
    }

    /**
     * Determine whether deep scan is required.
     */
    fun requiresDeepScan(
        activeThreats: Int,
        malwareDetected: Boolean,
        riskScore: Int
    ): Boolean {

        return malwareDetected ||
                activeThreats > 0 ||
                riskScore >= 70
    }

    /**
     * Calculate defense readiness percentage.
     */
    fun calculateReadinessPercentage(
        defenseScore: Int
    ): Double {
        return defenseScore.toDouble()
    }

    /**
     * Calculate resilience score.
     */
    fun calculateResilienceScore(
        protectionScore: Int,
        deviceTrustScore: Int,
        networkTrustScore: Int
    ): Int {

        return (
            protectionScore * 0.40 +
            deviceTrustScore * 0.30 +
            networkTrustScore * 0.30
        ).toInt().coerceIn(0, 100)
    }

    /**
     * Determine whether incident response should start.
     */
    fun requiresIncidentResponse(
        defenseLevel: DefenseLevel
    ): Boolean {

        return defenseLevel == DefenseLevel.CRITICAL
    }

    /**
     * Generate cyber defense summary.
     */
    fun getDefenseSummary(
        defenseLevel: DefenseLevel
    ): String {

        return when (defenseLevel) {

            DefenseLevel.NORMAL ->
                "Cyber defense posture is healthy."

            DefenseLevel.ELEVATED ->
                "Elevated security posture detected."

            DefenseLevel.HIGH_ALERT ->
                "High alert status active. Increased threat exposure detected."

            DefenseLevel.CRITICAL ->
                "Critical cyber defense condition detected."
        }
    }

    /**
     * Generate recommended action message.
     */
    fun getRecommendedAction(
        defenseLevel: DefenseLevel
    ): String {

        return when (defenseLevel) {

            DefenseLevel.NORMAL ->
                "Continue normal monitoring."

            DefenseLevel.ELEVATED ->
                "Strengthen security controls and increase monitoring."

            DefenseLevel.HIGH_ALERT ->
                "Restrict sensitive operations and perform comprehensive analysis."

            DefenseLevel.CRITICAL ->
                "Activate emergency response procedures immediately."
        }
    }

    /**
     * Determine whether a security alert should be generated.
     */
    fun requiresSecurityAlert(
        defenseLevel: DefenseLevel
    ): Boolean {

        return defenseLevel == DefenseLevel.HIGH_ALERT ||
                defenseLevel == DefenseLevel.CRITICAL
    }
}
