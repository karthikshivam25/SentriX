package com.sentrix.domain.rules

/**
 * SentriX Compliance Rules
 *
 * Centralized compliance validation engine responsible for
 * evaluating security controls, regulatory requirements,
 * policy adherence, audit readiness, and compliance scoring.
 */
object ComplianceRules {

    enum class ComplianceStatus {
        COMPLIANT,
        PARTIALLY_COMPLIANT,
        NON_COMPLIANT,
        CRITICAL_VIOLATION
    }

    enum class ComplianceFramework {
        SENTRIX_BASELINE,
        ISO_27001,
        NIST,
        GDPR,
        PCI_DSS,
        CUSTOM
    }

    /**
     * Calculate compliance score.
     */
    fun calculateComplianceScore(
        passedControls: Int,
        failedControls: Int,
        criticalViolations: Int
    ): Int {

        val totalControls = passedControls + failedControls

        if (totalControls <= 0) {
            return 0
        }

        var score =
            (passedControls.toDouble() / totalControls.toDouble()) * 100

        score -= (criticalViolations * 15)

        return score.toInt().coerceIn(0, 100)
    }

    /**
     * Determine compliance status.
     */
    fun determineComplianceStatus(
        complianceScore: Int,
        criticalViolations: Int
    ): ComplianceStatus {

        return when {
            criticalViolations > 0 ->
                ComplianceStatus.CRITICAL_VIOLATION

            complianceScore >= 90 ->
                ComplianceStatus.COMPLIANT

            complianceScore >= 70 ->
                ComplianceStatus.PARTIALLY_COMPLIANT

            else ->
                ComplianceStatus.NON_COMPLIANT
        }
    }

    /**
     * Check device compliance.
     */
    fun isDeviceCompliant(
        isRooted: Boolean,
        securityPatchUpToDate: Boolean,
        realtimeProtectionEnabled: Boolean
    ): Boolean {

        return !isRooted &&
                securityPatchUpToDate &&
                realtimeProtectionEnabled
    }

    /**
     * Check application compliance.
     */
    fun isApplicationCompliant(
        permissionRiskScore: Int,
        malwareDetected: Boolean
    ): Boolean {

        return permissionRiskScore < 50 &&
                !malwareDetected
    }

    /**
     * Check network compliance.
     */
    fun isNetworkCompliant(
        networkRiskScore: Int,
        vpnEnabled: Boolean
    ): Boolean {

        return networkRiskScore < 50 &&
                vpnEnabled
    }

    /**
     * Determine whether audit is required.
     */
    fun requiresAudit(
        complianceStatus: ComplianceStatus
    ): Boolean {

        return complianceStatus ==
                ComplianceStatus.NON_COMPLIANT ||
                complianceStatus ==
                ComplianceStatus.CRITICAL_VIOLATION
    }

    /**
     * Determine whether remediation is required.
     */
    fun requiresRemediation(
        complianceStatus: ComplianceStatus
    ): Boolean {

        return complianceStatus !=
                ComplianceStatus.COMPLIANT
    }

    /**
     * Determine whether access restrictions should be applied.
     */
    fun shouldRestrictAccess(
        complianceStatus: ComplianceStatus
    ): Boolean {

        return complianceStatus ==
                ComplianceStatus.CRITICAL_VIOLATION
    }

    /**
     * Calculate audit readiness score.
     */
    fun calculateAuditReadiness(
        complianceScore: Int,
        documentationCoverage: Int
    ): Int {

        return (
            complianceScore * 0.70 +
            documentationCoverage * 0.30
        ).toInt().coerceIn(0, 100)
    }

    /**
     * Determine whether compliance alert should be generated.
     */
    fun requiresComplianceAlert(
        complianceStatus: ComplianceStatus
    ): Boolean {

        return complianceStatus ==
                ComplianceStatus.NON_COMPLIANT ||
                complianceStatus ==
                ComplianceStatus.CRITICAL_VIOLATION
    }

    /**
     * Generate compliance summary.
     */
    fun getComplianceSummary(
        status: ComplianceStatus
    ): String {

        return when (status) {

            ComplianceStatus.COMPLIANT ->
                "System complies with all required security controls."

            ComplianceStatus.PARTIALLY_COMPLIANT ->
                "Some compliance controls require attention."

            ComplianceStatus.NON_COMPLIANT ->
                "Compliance requirements are not fully satisfied."

            ComplianceStatus.CRITICAL_VIOLATION ->
                "Critical compliance violations detected."
        }
    }

    /**
     * Generate recommended action.
     */
    fun getRecommendedAction(
        status: ComplianceStatus
    ): String {

        return when (status) {

            ComplianceStatus.COMPLIANT ->
                "Maintain current compliance posture."

            ComplianceStatus.PARTIALLY_COMPLIANT ->
                "Review and improve failing compliance controls."

            ComplianceStatus.NON_COMPLIANT ->
                "Implement remediation plan and schedule audit."

            ComplianceStatus.CRITICAL_VIOLATION ->
                "Immediately address violations and restrict sensitive operations."
        }
    }

    /**
     * Validate framework-specific minimum score.
     */
    fun meetsFrameworkRequirement(
        framework: ComplianceFramework,
        complianceScore: Int
    ): Boolean {

        val requiredScore = when (framework) {
            ComplianceFramework.SENTRIX_BASELINE -> 70
            ComplianceFramework.NIST -> 80
            ComplianceFramework.ISO_27001 -> 85
            ComplianceFramework.GDPR -> 85
            ComplianceFramework.PCI_DSS -> 90
            ComplianceFramework.CUSTOM -> 75
        }

        return complianceScore >= requiredScore
    }

    /**
     * Calculate overall governance score.
     */
    fun calculateGovernanceScore(
        complianceScore: Int,
        auditReadinessScore: Int,
        policyComplianceScore: Int
    ): Int {

        return (
            complianceScore * 0.40 +
            auditReadinessScore * 0.30 +
            policyComplianceScore * 0.30
        ).toInt().coerceIn(0, 100)
    }
}
