package com.sentrix.domain.rules

/**
 * SentriX Session Rules
 *
 * Centralized session management rules responsible for
 * validating sessions, enforcing session security,
 * handling expiration, and detecting session anomalies.
 */
object SessionRules {

    enum class SessionStatus {
        ACTIVE,
        IDLE,
        EXPIRED,
        SUSPICIOUS,
        TERMINATED
    }

    enum class SessionRiskLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    private const val DEFAULT_SESSION_TIMEOUT_MINUTES = 30
    private const val HIGH_RISK_TIMEOUT_MINUTES = 15

    /**
     * Determine session status.
     */
    fun determineSessionStatus(
        lastActivityMinutesAgo: Long,
        timeoutMinutes: Int = DEFAULT_SESSION_TIMEOUT_MINUTES,
        suspiciousActivityDetected: Boolean
    ): SessionStatus {

        return when {
            suspiciousActivityDetected ->
                SessionStatus.SUSPICIOUS

            lastActivityMinutesAgo >= timeoutMinutes ->
                SessionStatus.EXPIRED

            lastActivityMinutesAgo >= (timeoutMinutes / 2) ->
                SessionStatus.IDLE

            else ->
                SessionStatus.ACTIVE
        }
    }

    /**
     * Calculate session risk score.
     */
    fun calculateRiskScore(
        failedAuthenticationAttempts: Int,
        suspiciousActivityCount: Int,
        deviceTrustScore: Int,
        networkRiskScore: Int
    ): Int {

        var score = 0

        score += failedAuthenticationAttempts * 10
        score += suspiciousActivityCount * 15
        score += (100 - deviceTrustScore) / 2
        score += networkRiskScore / 2

        return score.coerceIn(0, 100)
    }

    /**
     * Determine session risk level.
     */
    fun determineRiskLevel(
        riskScore: Int
    ): SessionRiskLevel {

        return when {
            riskScore >= 85 ->
                SessionRiskLevel.CRITICAL

            riskScore >= 65 ->
                SessionRiskLevel.HIGH

            riskScore >= 40 ->
                SessionRiskLevel.MEDIUM

            else ->
                SessionRiskLevel.LOW
        }
    }

    /**
     * Check whether session should be terminated.
     */
    fun shouldTerminateSession(
        riskLevel: SessionRiskLevel
    ): Boolean {

        return riskLevel == SessionRiskLevel.CRITICAL
    }

    /**
     * Check whether re-authentication is required.
     */
    fun requiresReAuthentication(
        riskLevel: SessionRiskLevel,
        lastAuthenticationMinutesAgo: Long
    ): Boolean {

        return riskLevel == SessionRiskLevel.HIGH ||
                riskLevel == SessionRiskLevel.CRITICAL ||
                lastAuthenticationMinutesAgo >= 60
    }

    /**
     * Determine session timeout.
     */
    fun determineSessionTimeout(
        riskLevel: SessionRiskLevel
    ): Int {

        return when (riskLevel) {
            SessionRiskLevel.LOW ->
                DEFAULT_SESSION_TIMEOUT_MINUTES

            SessionRiskLevel.MEDIUM ->
                25

            SessionRiskLevel.HIGH ->
                HIGH_RISK_TIMEOUT_MINUTES

            SessionRiskLevel.CRITICAL ->
                5
        }
    }

    /**
     * Detect session hijacking indicators.
     */
    fun detectSessionHijacking(
        ipAddressChanged: Boolean,
        deviceFingerprintChanged: Boolean,
        geoLocationChanged: Boolean
    ): Boolean {

        val suspiciousIndicators =
            listOf(
                ipAddressChanged,
                deviceFingerprintChanged,
                geoLocationChanged
            ).count { it }

        return suspiciousIndicators >= 2
    }

    /**
     * Determine whether MFA is required.
     */
    fun requiresMfa(
        riskLevel: SessionRiskLevel,
        deviceTrusted: Boolean
    ): Boolean {

        return !deviceTrusted ||
                riskLevel == SessionRiskLevel.HIGH ||
                riskLevel == SessionRiskLevel.CRITICAL
    }

    /**
     * Determine whether session activity should be audited.
     */
    fun requiresAuditLogging(
        riskLevel: SessionRiskLevel
    ): Boolean {

        return riskLevel == SessionRiskLevel.HIGH ||
                riskLevel == SessionRiskLevel.CRITICAL
    }

    /**
     * Calculate session trust score.
     */
    fun calculateSessionTrustScore(
        deviceTrustScore: Int,
        authenticationConfidence: Double,
        networkTrustScore: Int
    ): Int {

        return (
            deviceTrustScore * 0.40 +
            authenticationConfidence * 100 * 0.30 +
            networkTrustScore * 0.30
        ).toInt().coerceIn(0, 100)
    }

    /**
     * Generate session summary.
     */
    fun getSessionSummary(
        status: SessionStatus
    ): String {

        return when (status) {

            SessionStatus.ACTIVE ->
                "Session is active and secure."

            SessionStatus.IDLE ->
                "Session is idle and awaiting activity."

            SessionStatus.EXPIRED ->
                "Session has expired."

            SessionStatus.SUSPICIOUS ->
                "Suspicious session activity detected."

            SessionStatus.TERMINATED ->
                "Session has been terminated."
        }
    }

    /**
     * Generate recommended action.
     */
    fun getRecommendedAction(
        status: SessionStatus
    ): String {

        return when (status) {

            SessionStatus.ACTIVE ->
                "No action required."

            SessionStatus.IDLE ->
                "Monitor session activity."

            SessionStatus.EXPIRED ->
                "Require user login."

            SessionStatus.SUSPICIOUS ->
                "Verify identity and review session activity."

            SessionStatus.TERMINATED ->
                "Start a new authenticated session."
        }
    }

    /**
     * Determine whether session alert should be generated.
     */
    fun requiresSessionAlert(
        status: SessionStatus,
        riskLevel: SessionRiskLevel
    ): Boolean {

        return status == SessionStatus.SUSPICIOUS ||
                riskLevel == SessionRiskLevel.HIGH ||
                riskLevel == SessionRiskLevel.CRITICAL
    }
}
