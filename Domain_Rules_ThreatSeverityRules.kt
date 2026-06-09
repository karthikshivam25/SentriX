package com.sentrix.domain.rules

/**
 * SentriX Threat Severity Rules
 *
 * Centralized rules for determining threat severity levels
 * based on risk scores, confidence, malware indicators,
 * phishing detection, and suspicious behaviors.
 */
object ThreatSeverityRules {

    const val CRITICAL_THRESHOLD = 90
    const val HIGH_THRESHOLD = 70
    const val MEDIUM_THRESHOLD = 40
    const val LOW_THRESHOLD = 15

    enum class ThreatSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Determine severity from overall risk score.
     */
    fun determineSeverity(riskScore: Int): ThreatSeverity {
        return when {
            riskScore >= CRITICAL_THRESHOLD -> ThreatSeverity.CRITICAL
            riskScore >= HIGH_THRESHOLD -> ThreatSeverity.HIGH
            riskScore >= MEDIUM_THRESHOLD -> ThreatSeverity.MEDIUM
            else -> ThreatSeverity.LOW
        }
    }

    /**
     * Determine severity using multiple threat indicators.
     */
    fun determineSeverity(
        riskScore: Int,
        isMalwareDetected: Boolean,
        isPhishingDetected: Boolean,
        isRootAccessDetected: Boolean,
        confidenceScore: Double
    ): ThreatSeverity {

        if (
            confidenceScore >= 0.90 &&
            (isMalwareDetected || isPhishingDetected || isRootAccessDetected)
        ) {
            return ThreatSeverity.CRITICAL
        }

        if (
            isMalwareDetected ||
            isPhishingDetected ||
            isRootAccessDetected
        ) {
            return ThreatSeverity.HIGH
        }

        return determineSeverity(riskScore)
    }

    /**
     * Check whether immediate action is required.
     */
    fun requiresImmediateAction(severity: ThreatSeverity): Boolean {
        return severity == ThreatSeverity.CRITICAL
    }

    /**
     * Check whether user notification is required.
     */
    fun shouldNotifyUser(severity: ThreatSeverity): Boolean {
        return severity == ThreatSeverity.HIGH ||
                severity == ThreatSeverity.CRITICAL
    }

    /**
     * Check whether threat should be automatically blocked.
     */
    fun shouldAutoBlock(severity: ThreatSeverity): Boolean {
        return severity == ThreatSeverity.CRITICAL
    }

    /**
     * Check whether threat should be quarantined.
     */
    fun shouldQuarantine(severity: ThreatSeverity): Boolean {
        return severity == ThreatSeverity.HIGH ||
                severity == ThreatSeverity.CRITICAL
    }

    /**
     * Convert severity to display priority.
     */
    fun getPriority(severity: ThreatSeverity): Int {
        return when (severity) {
            ThreatSeverity.CRITICAL -> 1
            ThreatSeverity.HIGH -> 2
            ThreatSeverity.MEDIUM -> 3
            ThreatSeverity.LOW -> 4
        }
    }

    /**
     * Human-readable description.
     */
    fun getDescription(severity: ThreatSeverity): String {
        return when (severity) {
            ThreatSeverity.CRITICAL ->
                "Critical threat detected. Immediate response required."

            ThreatSeverity.HIGH ->
                "High-risk threat detected. Investigation recommended."

            ThreatSeverity.MEDIUM ->
                "Potential threat detected. Monitor activity."

            ThreatSeverity.LOW ->
                "Low-risk activity detected."
        }
    }
}
