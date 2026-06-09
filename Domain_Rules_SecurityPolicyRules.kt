package com.sentrix.domain.rules

/**
 * SentriX Security Policy Rules
 *
 * Centralized policy engine responsible for enforcing
 * security standards, access restrictions, compliance
 * requirements, and operational security controls.
 */
object SecurityPolicyRules {

    enum class PolicyLevel {
        BASIC,
        STANDARD,
        STRICT,
        MAXIMUM
    }

    enum class PolicyDecision {
        ALLOW,
        RESTRICT,
        DENY
    }

    /**
     * Determine active policy level.
     */
    fun determinePolicyLevel(
        riskScore: Int,
        activeThreats: Int,
        deviceTrusted: Boolean
    ): PolicyLevel {

        return when {
            riskScore >= 85 ||
                    activeThreats >= 5 ->
                PolicyLevel.MAXIMUM

            riskScore >= 65 ||
                    activeThreats >= 3 ->
                PolicyLevel.STRICT

            riskScore >= 35 ||
                    !deviceTrusted ->
                PolicyLevel.STANDARD

            else ->
                PolicyLevel.BASIC
        }
    }

    /**
     * Evaluate sensitive operation access.
     */
    fun evaluateSensitiveOperation(
        policyLevel: PolicyLevel,
        deviceTrusted: Boolean,
        realtimeProtectionEnabled: Boolean
    ): PolicyDecision {

        return when (policyLevel) {

            PolicyLevel.MAXIMUM ->
                PolicyDecision.DENY

            PolicyLevel.STRICT -> {
                if (deviceTrusted &&
                    realtimeProtectionEnabled
                ) {
                    PolicyDecision.ALLOW
                } else {
                    PolicyDecision.RESTRICT
                }
            }

            PolicyLevel.STANDARD -> {
                if (deviceTrusted) {
                    PolicyDecision.ALLOW
                } else {
                    PolicyDecision.RESTRICT
                }
            }

            PolicyLevel.BASIC ->
                PolicyDecision.ALLOW
        }
    }

    /**
     * Evaluate application installation.
     */
    fun evaluateApplicationInstallation(
        appRiskScore: Int,
        policyLevel: PolicyLevel
    ): PolicyDecision {

        return when {

            appRiskScore >= 80 ->
                PolicyDecision.DENY

            appRiskScore >= 50 &&
                    policyLevel >= PolicyLevel.STRICT ->
                PolicyDecision.RESTRICT

            else ->
                PolicyDecision.ALLOW
        }
    }

    /**
     * Evaluate network access.
     */
    fun evaluateNetworkAccess(
        networkRiskScore: Int,
        policyLevel: PolicyLevel
    ): PolicyDecision {

        return when {

            networkRiskScore >= 80 ->
                PolicyDecision.DENY

            networkRiskScore >= 50 &&
                    policyLevel != PolicyLevel.BASIC ->
                PolicyDecision.RESTRICT

            else ->
                PolicyDecision.ALLOW
        }
    }

    /**
     * Check whether USB/file sharing should be allowed.
     */
    fun allowExternalDataTransfer(
        policyLevel: PolicyLevel
    ): Boolean {

        return policyLevel == PolicyLevel.BASIC ||
                policyLevel == PolicyLevel.STANDARD
    }

    /**
     * Check whether screen capture should be allowed.
     */
    fun allowScreenCapture(
        policyLevel: PolicyLevel
    ): Boolean {

        return policyLevel != PolicyLevel.MAXIMUM
    }

    /**
     * Check whether developer options should be allowed.
     */
    fun allowDeveloperOptions(
        policyLevel: PolicyLevel
    ): Boolean {

        return policyLevel == PolicyLevel.BASIC
    }

    /**
     * Check whether unknown sources can be installed.
     */
    fun allowUnknownSources(
        policyLevel: PolicyLevel
    ): Boolean {

        return false
    }

    /**
     * Determine if compliance validation is required.
     */
    fun requiresComplianceCheck(
        policyLevel: PolicyLevel
    ): Boolean {

        return policyLevel == PolicyLevel.STRICT ||
                policyLevel == PolicyLevel.MAXIMUM
    }

    /**
     * Determine if enhanced auditing is required.
     */
    fun requiresEnhancedAuditing(
        policyLevel: PolicyLevel
    ): Boolean {

        return policyLevel == PolicyLevel.MAXIMUM
    }

    /**
     * Calculate policy compliance score.
     */
    fun calculateComplianceScore(
        passedChecks: Int,
        totalChecks: Int
    ): Int {

        if (totalChecks <= 0) {
            return 0
        }

        return (
            passedChecks.toDouble() /
                    totalChecks.toDouble() * 100
            ).toInt()
    }

    /**
     * Determine whether policy violation alert is required.
     */
    fun requiresViolationAlert(
        policyDecision: PolicyDecision
    ): Boolean {

        return policyDecision == PolicyDecision.DENY
    }

    /**
     * Generate policy summary.
     */
    fun getPolicySummary(
        policyLevel: PolicyLevel
    ): String {

        return when (policyLevel) {

            PolicyLevel.BASIC ->
                "Basic security policies are active."

            PolicyLevel.STANDARD ->
                "Standard security policies are enforced."

            PolicyLevel.STRICT ->
                "Strict security policies are enforced."

            PolicyLevel.MAXIMUM ->
                "Maximum security policies are active."
        }
    }

    /**
     * Generate recommended action.
     */
    fun getRecommendedAction(
        policyLevel: PolicyLevel
    ): String {

        return when (policyLevel) {

            PolicyLevel.BASIC ->
                "Continue standard monitoring."

            PolicyLevel.STANDARD ->
                "Review security posture regularly."

            PolicyLevel.STRICT ->
                "Perform compliance checks and enhanced monitoring."

            PolicyLevel.MAXIMUM ->
                "Apply full lockdown procedures and incident response."
        }
    }
}
