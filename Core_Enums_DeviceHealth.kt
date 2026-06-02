package com.sentrix.core.enums

/**
 * Represents overall device health status
 */
enum class DeviceHealth(
    val level: Int,
    val displayName: String,
    val description: String
) {

    EXCELLENT(
        level = 5,
        displayName = "Excellent",
        description = "Device is operating at optimal performance and security"
    ),

    GOOD(
        level = 4,
        displayName = "Good",
        description = "Device is functioning well with minimal issues"
    ),

    FAIR(
        level = 3,
        displayName = "Fair",
        description = "Device performance is stable but improvements are recommended"
    ),

    POOR(
        level = 2,
        displayName = "Poor",
        description = "Device has noticeable performance or security issues"
    ),

    CRITICAL(
        level = 1,
        displayName = "Critical",
        description = "Device health is severely degraded and requires immediate attention"
    ),

    UNKNOWN(
        level = 0,
        displayName = "Unknown",
        description = "Unable to determine current device health status"
    );

    /**
     * Returns true if device health is acceptable
     */
    fun isHealthy(): Boolean {
        return this == EXCELLENT ||
               this == GOOD
    }

    /**
     * Returns true if maintenance is recommended
     */
    fun requiresOptimization(): Boolean {
        return this == FAIR ||
               this == POOR
    }

    /**
     * Returns true if immediate action is needed
     */
    fun requiresImmediateAttention(): Boolean {
        return this == CRITICAL
    }

    /**
     * Returns health score percentage
     */
    fun healthScore(): Int {
        return when (this) {
            EXCELLENT -> 100
            GOOD -> 80
            FAIR -> 60
            POOR -> 35
            CRITICAL -> 10
            UNKNOWN -> 50
        }
    }

    companion object {

        /**
         * Convert score to DeviceHealth
         */
        fun fromScore(score: Int): DeviceHealth {
            return when {
                score >= 90 -> EXCELLENT
                score >= 75 -> GOOD
                score >= 55 -> FAIR
                score >= 25 -> POOR
                score in 0..24 -> CRITICAL
                else -> UNKNOWN
            }
        }
    }
}
