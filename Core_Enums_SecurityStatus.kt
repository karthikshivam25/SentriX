package com.sentrix.core.enums

/**
 * Represents the overall security state of the device/system
 */
enum class SecurityStatus(
    val level: Int,
    val displayName: String,
    val description: String
) {

    SECURE(
        level = 0,
        displayName = "Secure",
        description = "Device is fully protected and operating safely"
    ),

    PROTECTED(
        level = 1,
        displayName = "Protected",
        description = "Security protection is active with no major risks"
    ),

    STABLE(
        level = 2,
        displayName = "Stable",
        description = "System security is stable with minor recommendations"
    ),

    WARNING(
        level = 3,
        displayName = "Warning",
        description = "Potential threats or vulnerabilities detected"
    ),

    AT_RISK(
        level = 4,
        displayName = "At Risk",
        description = "Device security is weakened and requires attention"
    ),

    VULNERABLE(
        level = 5,
        displayName = "Vulnerable",
        description = "Critical vulnerabilities detected in the system"
    ),

    INFECTED(
        level = 6,
        displayName = "Infected",
        description = "Malware or harmful threats detected on the device"
    ),

    COMPROMISED(
        level = 7,
        displayName = "Compromised",
        description = "System integrity has been compromised"
    ),

    UNKNOWN(
        level = 8,
        displayName = "Unknown",
        description = "Security state could not be determined"
    );

    /**
     * Returns true if the system is safe
     */
    fun isSafe(): Boolean {
        return this == SECURE ||
               this == PROTECTED ||
               this == STABLE
    }

    /**
     * Returns true if immediate action is needed
     */
    fun requiresImmediateAction(): Boolean {
        return this == VULNERABLE ||
               this == INFECTED ||
               this == COMPROMISED
    }

    /**
     * Returns true if warnings exist
     */
    fun hasWarnings(): Boolean {
        return this == WARNING ||
               this == AT_RISK
    }

    /**
     * Returns security score percentage
     */
    fun securityScore(): Int {
        return when (this) {
            SECURE -> 100
            PROTECTED -> 90
            STABLE -> 75
            WARNING -> 60
            AT_RISK -> 40
            VULNERABLE -> 25
            INFECTED -> 10
            COMPROMISED -> 0
            UNKNOWN -> 50
        }
    }

    companion object {

        /**
         * Returns SecurityStatus from score
         */
        fun fromScore(score: Int): SecurityStatus {
            return when {
                score >= 95 -> SECURE
                score >= 85 -> PROTECTED
                score >= 70 -> STABLE
                score >= 55 -> WARNING
                score >= 35 -> AT_RISK
                score >= 20 -> VULNERABLE
                score >= 1  -> INFECTED
                score <= 0  -> COMPROMISED
                else -> UNKNOWN
            }
        }
    }
}
