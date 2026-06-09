package com.sentrix.domain.rules

/**
 * SentriX Intrusion Detection Rules
 *
 * Centralized rules for detecting suspicious activity,
 * brute-force attacks, reconnaissance attempts,
 * abnormal traffic patterns, and intrusion indicators.
 */
object IntrusionDetectionRules {

    enum class IntrusionSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum class IntrusionType {
        BRUTE_FORCE,
        PORT_SCAN,
        RECONNAISSANCE,
        DOS_ATTACK,
        DATA_EXFILTRATION,
        SUSPICIOUS_ACTIVITY,
        UNKNOWN
    }

    /**
     * Calculate intrusion risk score.
     */
    fun calculateRiskScore(
        failedLoginAttempts: Int,
        portScanAttempts: Int,
        suspiciousRequests: Int,
        abnormalTrafficVolume: Boolean,
        knownMaliciousIp: Boolean,
        unauthorizedAccessAttempts: Int
    ): Int {

        var score = 0

        score += (failedLoginAttempts * 2)
        score += (portScanAttempts * 3)
        score += (suspiciousRequests * 2)
        score += (unauthorizedAccessAttempts * 5)

        if (abnormalTrafficVolume) score += 20
        if (knownMaliciousIp) score += 30

        return score.coerceIn(0, 100)
    }

    /**
     * Determine intrusion severity.
     */
    fun determineSeverity(
        riskScore: Int
    ): IntrusionSeverity {

        return when {
            riskScore >= 80 -> IntrusionSeverity.CRITICAL
            riskScore >= 60 -> IntrusionSeverity.HIGH
            riskScore >= 30 -> IntrusionSeverity.MEDIUM
            else -> IntrusionSeverity.LOW
        }
    }

    /**
     * Detect intrusion type.
     */
    fun detectIntrusionType(
        failedLoginAttempts: Int,
        portScanAttempts: Int,
        abnormalTrafficVolume: Boolean,
        unauthorizedAccessAttempts: Int,
        largeOutboundTransfers: Boolean
    ): IntrusionType {

        return when {
            failedLoginAttempts >= 10 ->
                IntrusionType.BRUTE_FORCE

            portScanAttempts >= 20 ->
                IntrusionType.PORT_SCAN

            unauthorizedAccessAttempts >= 5 ->
                IntrusionType.RECONNAISSANCE

            abnormalTrafficVolume ->
                IntrusionType.DOS_ATTACK

            largeOutboundTransfers ->
                IntrusionType.DATA_EXFILTRATION

            failedLoginAttempts > 0 ||
            portScanAttempts > 0 ->
                IntrusionType.SUSPICIOUS_ACTIVITY

            else ->
                IntrusionType.UNKNOWN
        }
    }

    /**
     * Detect brute-force attack.
     */
    fun isBruteForceAttack(
        failedLoginAttempts: Int
    ): Boolean {
        return failedLoginAttempts >= 10
    }

    /**
     * Detect port scanning activity.
     */
    fun isPortScanning(
        uniquePortsAccessed: Int
    ): Boolean {
        return uniquePortsAccessed >= 20
    }

    /**
     * Detect data exfiltration attempt.
     */
    fun isDataExfiltration(
        outboundTrafficMb: Long,
        normalBaselineMb: Long
    ): Boolean {

        if (normalBaselineMb <= 0) {
            return false
        }

        return outboundTrafficMb >
                (normalBaselineMb * 3)
    }

    /**
     * Determine whether immediate blocking
     * should occur.
     */
    fun shouldBlockSource(
        severity: IntrusionSeverity
    ): Boolean {

        return severity == IntrusionSeverity.HIGH ||
                severity == IntrusionSeverity.CRITICAL
    }

    /**
     * Determine whether emergency response
     * should be triggered.
     */
    fun requiresEmergencyResponse(
        severity: IntrusionSeverity
    ): Boolean {
        return severity == IntrusionSeverity.CRITICAL
    }

    /**
     * Calculate confidence level.
     */
    fun calculateConfidence(
        indicatorsDetected: Int,
        totalIndicatorsChecked: Int
    ): Double {

        if (totalIndicatorsChecked <= 0) {
            return 0.0
        }

        return indicatorsDetected.toDouble() /
                totalIndicatorsChecked.toDouble()
    }

    /**
     * Generate intrusion summary.
     */
    fun getIntrusionSummary(
        severity: IntrusionSeverity,
        intrusionType: IntrusionType
    ): String {

        return when (severity) {

            IntrusionSeverity.CRITICAL ->
                "Critical intrusion detected: $intrusionType"

            IntrusionSeverity.HIGH ->
                "High-risk intrusion activity detected: $intrusionType"

            IntrusionSeverity.MEDIUM ->
                "Suspicious intrusion activity detected: $intrusionType"

            IntrusionSeverity.LOW ->
                "Minor intrusion indicators detected."
        }
    }

    /**
     * Recommended action.
     */
    fun getRecommendedAction(
        severity: IntrusionSeverity
    ): String {

        return when (severity) {

            IntrusionSeverity.CRITICAL ->
                "Block source immediately and initiate incident response."

            IntrusionSeverity.HIGH ->
                "Restrict access and investigate suspicious activity."

            IntrusionSeverity.MEDIUM ->
                "Increase monitoring and collect additional evidence."

            IntrusionSeverity.LOW ->
                "Continue observation and logging."
        }
    }

    /**
     * Determine whether security alert
     * should be generated.
     */
    fun requiresSecurityAlert(
        severity: IntrusionSeverity
    ): Boolean {

        return severity == IntrusionSeverity.HIGH ||
                severity == IntrusionSeverity.CRITICAL
    }
}
