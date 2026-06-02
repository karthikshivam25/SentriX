package com.sentrix.core.enums

/**
 * Represents permission risk levels used in SentriX
 */
enum class PermissionRisk(
    val level: Int,
    val displayName: String,
    val description: String
) {

    SAFE(
        level = 0,
        displayName = "Safe",
        description = "Permission is considered safe and low risk"
    ),

    LOW(
        level = 1,
        displayName = "Low Risk",
        description = "Permission has minimal security impact"
    ),

    MODERATE(
        level = 2,
        displayName = "Moderate Risk",
        description = "Permission may access limited sensitive data"
    ),

    HIGH(
        level = 3,
        displayName = "High Risk",
        description = "Permission can access sensitive device features"
    ),

    CRITICAL(
        level = 4,
        displayName = "Critical Risk",
        description = "Permission can seriously affect privacy or security"
    ),

    UNKNOWN(
        level = 5,
        displayName = "Unknown",
        description = "Risk level could not be determined"
    );

    /**
     * Returns true if the permission is dangerous
     */
    fun isDangerous(): Boolean {
        return this == HIGH || this == CRITICAL
    }

    /**
     * Returns true if user attention is recommended
     */
    fun requiresAttention(): Boolean {
        return this == MODERATE ||
               this == HIGH ||
               this == CRITICAL
    }

    /**
     * Returns a severity score for analytics/UI
     */
    fun severityScore(): Int {
        return when (this) {
            SAFE -> 0
            LOW -> 25
            MODERATE -> 50
            HIGH -> 75
            CRITICAL -> 100
            UNKNOWN -> 40
        }
    }

    companion object {

        /**
         * Convert integer level to PermissionRisk
         */
        fun fromLevel(level: Int): PermissionRisk {
            return values().find { it.level == level } ?: UNKNOWN
        }
    }
}
