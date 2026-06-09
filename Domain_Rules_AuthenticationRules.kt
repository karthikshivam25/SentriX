package com.sentrix.domain.rules

/**
 * SentriX Authentication Rules
 *
 * Centralized authentication policy engine responsible for
 * login validation, MFA enforcement, authentication risk
 * assessment, account protection, and access decisions.
 */
object AuthenticationRules {

    enum class AuthenticationStatus {
        SUCCESS,
        CHALLENGE_REQUIRED,
        DENIED,
        LOCKED
    }

    enum class AuthenticationRiskLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Calculate authentication risk score.
     */
    fun calculateRiskScore(
        failedLoginAttempts: Int,
        deviceTrustScore: Int,
        networkRiskScore: Int,
        suspiciousActivityCount: Int,
        isNewDevice: Boolean
    ): Int {

        var score = 0

        score += failedLoginAttempts * 10
        score += suspiciousActivityCount * 15
        score += networkRiskScore / 2
        score += (100 - deviceTrustScore) / 2

        if (isNewDevice) {
            score += 15
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Determine authentication risk level.
     */
    fun determineRiskLevel(
        riskScore: Int
    ): AuthenticationRiskLevel {

        return when {
            riskScore >= 85 ->
                AuthenticationRiskLevel.CRITICAL

            riskScore >= 65 ->
                AuthenticationRiskLevel.HIGH

            riskScore >= 40 ->
                AuthenticationRiskLevel.MEDIUM

            else ->
                AuthenticationRiskLevel.LOW
        }
    }

    /**
     * Determine authentication outcome.
     */
    fun determineAuthenticationStatus(
        riskLevel: AuthenticationRiskLevel,
        failedLoginAttempts: Int
    ): AuthenticationStatus {

        return when {

            failedLoginAttempts >= 10 ->
                AuthenticationStatus.LOCKED

            riskLevel == AuthenticationRiskLevel.CRITICAL ->
                AuthenticationStatus.DENIED

            riskLevel == AuthenticationRiskLevel.HIGH ->
                AuthenticationStatus.CHALLENGE_REQUIRED

            else ->
                AuthenticationStatus.SUCCESS
        }
    }

    /**
     * Check whether MFA is required.
     */
    fun requiresMfa(
        riskLevel: AuthenticationRiskLevel,
        isNewDevice: Boolean
    ): Boolean {

        return isNewDevice ||
                riskLevel == AuthenticationRiskLevel.MEDIUM ||
                riskLevel == AuthenticationRiskLevel.HIGH ||
                riskLevel == AuthenticationRiskLevel.CRITICAL
    }

    /**
     * Check whether biometric authentication is allowed.
     */
    fun canUseBiometrics(
        deviceTrustScore: Int,
        realtimeProtectionEnabled: Boolean
    ): Boolean {

        return deviceTrustScore >= 70 &&
                realtimeProtectionEnabled
    }

    /**
     * Check whether login should be blocked.
     */
    fun shouldBlockLogin(
        riskLevel: AuthenticationRiskLevel
    ): Boolean {

        return riskLevel ==
                AuthenticationRiskLevel.CRITICAL
    }

    /**
     * Check whether account should be locked.
     */
    fun shouldLockAccount(
        failedLoginAttempts: Int
    ): Boolean {

        return failedLoginAttempts >= 10
    }

    /**
     * Check whether step-up authentication is required.
     */
    fun requiresStepUpAuthentication(
        riskLevel: AuthenticationRiskLevel
    ): Boolean {

        return riskLevel ==
                AuthenticationRiskLevel.HIGH ||
                riskLevel ==
                AuthenticationRiskLevel.CRITICAL
    }

    /**
     * Detect credential stuffing indicators.
     */
    fun detectCredentialStuffing(
        failedLoginAttempts: Int,
        uniqueUsernameAttempts: Int
    ): Boolean {

        return failedLoginAttempts >= 20 &&
                uniqueUsernameAttempts >= 5
    }

    /**
     * Detect brute-force attack indicators.
     */
    fun detectBruteForceAttack(
        failedLoginAttempts: Int,
        loginAttemptsPerMinute: Int
    ): Boolean {

        return failedLoginAttempts >= 10 &&
                loginAttemptsPerMinute >= 5
    }

    /**
     * Calculate authentication confidence.
     */
    fun calculateAuthenticationConfidence(
        successfulFactors: Int,
        totalFactors: Int
    ): Double {

        if (totalFactors <= 0) {
            return 0.0
        }

        return successfulFactors.toDouble() /
                totalFactors.toDouble()
    }

    /**
     * Determine session duration after authentication.
     */
    fun determineSessionDurationMinutes(
        riskLevel: AuthenticationRiskLevel
    ): Int {

        return when (riskLevel) {
            AuthenticationRiskLevel.LOW -> 60
            AuthenticationRiskLevel.MEDIUM -> 45
            AuthenticationRiskLevel.HIGH -> 20
            AuthenticationRiskLevel.CRITICAL -> 5
        }
    }

    /**
     * Generate authentication summary.
     */
    fun getAuthenticationSummary(
        status: AuthenticationStatus
    ): String {

        return when (status) {

            AuthenticationStatus.SUCCESS ->
                "Authentication completed successfully."

            AuthenticationStatus.CHALLENGE_REQUIRED ->
                "Additional verification is required."

            AuthenticationStatus.DENIED ->
                "Authentication request denied."

            AuthenticationStatus.LOCKED ->
                "Account temporarily locked."
        }
    }

    /**
     * Generate recommended action.
     */
    fun getRecommendedAction(
        status: AuthenticationStatus
    ): String {

        return when (status) {

            AuthenticationStatus.SUCCESS ->
                "Grant access."

            AuthenticationStatus.CHALLENGE_REQUIRED ->
                "Perform multi-factor authentication."

            AuthenticationStatus.DENIED ->
                "Block access and investigate risk factors."

            AuthenticationStatus.LOCKED ->
                "Require account recovery and security review."
        }
    }

    /**
     * Determine whether authentication alert should be generated.
     */
    fun requiresAuthenticationAlert(
        status: AuthenticationStatus,
        riskLevel: AuthenticationRiskLevel
    ): Boolean {

        return status == AuthenticationStatus.DENIED ||
                status == AuthenticationStatus.LOCKED ||
                riskLevel == AuthenticationRiskLevel.HIGH ||
                riskLevel == AuthenticationRiskLevel.CRITICAL
    }
}
