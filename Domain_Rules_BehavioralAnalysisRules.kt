package com.sentrix.domain.rules

/**
 * SentriX Behavioral Analysis Rules
 *
 * Centralized rules for analyzing application and device behavior,
 * identifying anomalies, suspicious activities, and potential threats
 * based on runtime behavior patterns.
 */
object BehavioralAnalysisRules {

    enum class BehaviorRiskLevel {
        NORMAL,
        SUSPICIOUS,
        HIGH_RISK,
        MALICIOUS
    }

    enum class BehaviorType {
        EXCESSIVE_PERMISSION_USAGE,
        BACKGROUND_ACTIVITY_ABUSE,
        DATA_EXFILTRATION,
        BATTERY_ABUSE,
        NETWORK_ANOMALY,
        FILE_SYSTEM_MANIPULATION,
        PRIVILEGE_ESCALATION,
        PROCESS_INJECTION,
        UNKNOWN
    }

    /**
     * Calculate behavioral risk score.
     */
    fun calculateRiskScore(
        excessivePermissionRequests: Int,
        suspiciousNetworkCalls: Int,
        backgroundProcesses: Int,
        unauthorizedFileAccesses: Int,
        privilegeEscalationAttempts: Int,
        abnormalBatteryConsumption: Boolean
    ): Int {

        var score = 0

        score += excessivePermissionRequests * 3
        score += suspiciousNetworkCalls * 4
        score += backgroundProcesses * 2
        score += unauthorizedFileAccesses * 5
        score += privilegeEscalationAttempts * 10

        if (abnormalBatteryConsumption) {
            score += 15
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Determine behavior risk level.
     */
    fun determineRiskLevel(
        riskScore: Int
    ): BehaviorRiskLevel {

        return when {
            riskScore >= 80 -> BehaviorRiskLevel.MALICIOUS
            riskScore >= 55 -> BehaviorRiskLevel.HIGH_RISK
            riskScore >= 25 -> BehaviorRiskLevel.SUSPICIOUS
            else -> BehaviorRiskLevel.NORMAL
        }
    }

    /**
     * Detect dominant suspicious behavior type.
     */
    fun detectBehaviorType(
        excessivePermissionRequests: Int,
        suspiciousNetworkCalls: Int,
        unauthorizedFileAccesses: Int,
        privilegeEscalationAttempts: Int,
        abnormalBatteryConsumption: Boolean
    ): BehaviorType {

        return when {

            privilegeEscalationAttempts > 0 ->
                BehaviorType.PRIVILEGE_ESCALATION

            unauthorizedFileAccesses >= 5 ->
                BehaviorType.FILE_SYSTEM_MANIPULATION

            suspiciousNetworkCalls >= 10 ->
                BehaviorType.NETWORK_ANOMALY

            excessivePermissionRequests >= 5 ->
                BehaviorType.EXCESSIVE_PERMISSION_USAGE

            abnormalBatteryConsumption ->
                BehaviorType.BATTERY_ABUSE

            else ->
                BehaviorType.UNKNOWN
        }
    }

    /**
     * Detect possible data exfiltration.
     */
    fun isPotentialDataExfiltration(
        outboundTrafficMb: Long,
        normalTrafficMb: Long
    ): Boolean {

        if (normalTrafficMb <= 0) {
            return false
        }

        return outboundTrafficMb >= (normalTrafficMb * 3)
    }

    /**
     * Detect suspicious background execution.
     */
    fun hasBackgroundExecutionAbuse(
        backgroundProcesses: Int
    ): Boolean {
        return backgroundProcesses >= 15
    }

    /**
     * Detect abnormal permission behavior.
     */
    fun hasPermissionAbuse(
        permissionRequests: Int
    ): Boolean {
        return permissionRequests >= 5
    }

    /**
     * Detect privilege escalation attempts.
     */
    fun hasPrivilegeEscalationRisk(
        attempts: Int
    ): Boolean {
        return attempts > 0
    }

    /**
     * Determine whether application should be isolated.
     */
    fun shouldIsolateApplication(
        riskLevel: BehaviorRiskLevel
    ): Boolean {

        return riskLevel == BehaviorRiskLevel.HIGH_RISK ||
                riskLevel == BehaviorRiskLevel.MALICIOUS
    }

    /**
     * Determine whether immediate intervention is required.
     */
    fun requiresImmediateAction(
        riskLevel: BehaviorRiskLevel
    ): Boolean {
        return riskLevel == BehaviorRiskLevel.MALICIOUS
    }

    /**
     * Calculate confidence score.
     */
    fun calculateConfidence(
        detectedIndicators: Int,
        totalIndicators: Int
    ): Double {

        if (totalIndicators <= 0) {
            return 0.0
        }

        return detectedIndicators.toDouble() /
                totalIndicators.toDouble()
    }

    /**
     * Generate behavioral analysis summary.
     */
    fun getAnalysisSummary(
        riskLevel: BehaviorRiskLevel,
        behaviorType: BehaviorType
    ): String {

        return when (riskLevel) {

            BehaviorRiskLevel.NORMAL ->
                "No suspicious behavior detected."

            BehaviorRiskLevel.SUSPICIOUS ->
                "Suspicious behavior detected: $behaviorType"

            BehaviorRiskLevel.HIGH_RISK ->
                "High-risk behavior detected: $behaviorType"

            BehaviorRiskLevel.MALICIOUS ->
                "Malicious behavior detected: $behaviorType"
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        riskLevel: BehaviorRiskLevel
    ): String {

        return when (riskLevel) {

            BehaviorRiskLevel.NORMAL ->
                "No action required."

            BehaviorRiskLevel.SUSPICIOUS ->
                "Monitor application activity."

            BehaviorRiskLevel.HIGH_RISK ->
                "Restrict application activity and investigate."

            BehaviorRiskLevel.MALICIOUS ->
                "Isolate application immediately and alert user."
        }
    }

    /**
     * Determine whether a security alert should be generated.
     */
    fun requiresSecurityAlert(
        riskLevel: BehaviorRiskLevel
    ): Boolean {

        return riskLevel == BehaviorRiskLevel.HIGH_RISK ||
                riskLevel == BehaviorRiskLevel.MALICIOUS
    }
}
