package com.sentrix.domain.rules

/**
 * SentriX Risk Scoring Rules
 *
 * Centralized risk calculation engine used across
 * threat analysis, device trust evaluation,
 * network security assessment, and realtime protection.
 */
object RiskScoringRules {

    enum class RiskLevel {
        MINIMAL,
        LOW,
        MODERATE,
        HIGH,
        CRITICAL
    }

    /**
     * Calculate overall security risk score.
     */
    fun calculateOverallRiskScore(
        threatScore: Int,
        deviceRiskScore: Int,
        networkRiskScore: Int,
        behaviorRiskScore: Int,
        malwareRiskScore: Int
    ): Int {

        val weightedScore =
            (threatScore * 0.30) +
            (deviceRiskScore * 0.20) +
            (networkRiskScore * 0.15) +
            (behaviorRiskScore * 0.20) +
            (malwareRiskScore * 0.15)

        return weightedScore.toInt()
            .coerceIn(0, 100)
    }

    /**
     * Calculate application risk score.
     */
    fun calculateApplicationRiskScore(
        permissionRiskScore: Int,
        behaviorRiskScore: Int,
        malwareRiskScore: Int
    ): Int {

        return (
            permissionRiskScore * 0.35 +
            behaviorRiskScore * 0.35 +
            malwareRiskScore * 0.30
        ).toInt().coerceIn(0, 100)
    }

    /**
     * Calculate device risk score.
     */
    fun calculateDeviceRiskScore(
        integrityScore: Int,
        rootRiskScore: Int,
        threatCount: Int
    ): Int {

        val score =
            ((100 - integrityScore) * 0.50) +
            (rootRiskScore * 0.40) +
            (threatCount * 2)

        return score.toInt().coerceIn(0, 100)
    }

    /**
     * Calculate network risk score.
     */
    fun calculateNetworkRiskScore(
        firewallThreatScore: Int,
        intrusionRiskScore: Int,
        vpnRiskScore: Int
    ): Int {

        return (
            firewallThreatScore * 0.35 +
            intrusionRiskScore * 0.45 +
            vpnRiskScore * 0.20
        ).toInt().coerceIn(0, 100)
    }

    /**
     * Determine risk level.
     */
    fun determineRiskLevel(
        riskScore: Int
    ): RiskLevel {

        return when {
            riskScore >= 85 -> RiskLevel.CRITICAL
            riskScore >= 65 -> RiskLevel.HIGH
            riskScore >= 40 -> RiskLevel.MODERATE
            riskScore >= 15 -> RiskLevel.LOW
            else -> RiskLevel.MINIMAL
        }
    }

    /**
     * Calculate trust score from risk score.
     */
    fun calculateTrustScore(
        riskScore: Int
    ): Int {
        return (100 - riskScore)
            .coerceIn(0, 100)
    }

    /**
     * Check whether risk is acceptable.
     */
    fun isAcceptableRisk(
        riskLevel: RiskLevel
    ): Boolean {

        return riskLevel == RiskLevel.MINIMAL ||
                riskLevel == RiskLevel.LOW
    }

    /**
     * Determine whether security intervention
     * is required.
     */
    fun requiresIntervention(
        riskLevel: RiskLevel
    ): Boolean {

        return riskLevel == RiskLevel.HIGH ||
                riskLevel == RiskLevel.CRITICAL
    }

    /**
     * Determine whether emergency response
     * should be triggered.
     */
    fun requiresEmergencyResponse(
        riskLevel: RiskLevel
    ): Boolean {
        return riskLevel == RiskLevel.CRITICAL
    }

    /**
     * Calculate confidence-adjusted risk score.
     */
    fun calculateConfidenceAdjustedRisk(
        riskScore: Int,
        confidenceScore: Double
    ): Int {

        return (riskScore * confidenceScore)
            .toInt()
            .coerceIn(0, 100)
    }

    /**
     * Generate risk summary.
     */
    fun getRiskSummary(
        riskLevel: RiskLevel
    ): String {

        return when (riskLevel) {

            RiskLevel.MINIMAL ->
                "Minimal security risk detected."

            RiskLevel.LOW ->
                "Low security risk detected."

            RiskLevel.MODERATE ->
                "Moderate security risk detected."

            RiskLevel.HIGH ->
                "High security risk detected."

            RiskLevel.CRITICAL ->
                "Critical security risk detected."
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        riskLevel: RiskLevel
    ): String {

        return when (riskLevel) {

            RiskLevel.MINIMAL ->
                "No action required."

            RiskLevel.LOW ->
                "Continue monitoring."

            RiskLevel.MODERATE ->
                "Review security posture and monitor closely."

            RiskLevel.HIGH ->
                "Investigate threats and apply mitigation measures."

            RiskLevel.CRITICAL ->
                "Initiate immediate incident response procedures."
        }
    }

    /**
     * Determine whether security alert
     * should be generated.
     */
    fun requiresSecurityAlert(
        riskLevel: RiskLevel
    ): Boolean {

        return riskLevel == RiskLevel.HIGH ||
                riskLevel == RiskLevel.CRITICAL
    }

    /**
     * Calculate security health percentage.
     */
    fun calculateSecurityHealth(
        riskScore: Int
    ): Double {

        return (100 - riskScore)
            .toDouble()
            .coerceIn(0.0, 100.0)
    }
}
