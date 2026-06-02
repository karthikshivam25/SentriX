package com.sentrix.core.enums

/**
 * Represents alert priority levels used across SentriX
 */
enum class AlertPriority(
    val level: Int,
    val displayName: String,
    val description: String
) {

    LOW(
        level = 1,
        displayName = "Low",
        description = "Minor informational alert with low urgency"
    ),

    MEDIUM(
        level = 2,
        displayName = "Medium",
        description = "Moderate alert requiring user awareness"
    ),

    HIGH(
        level = 3,
        displayName = "High",
        description = "Important security alert requiring attention"
    ),

    CRITICAL(
        level = 4,
        displayName = "Critical",
        description = "Severe threat or issue requiring immediate action"
    ),

    EMERGENCY(
        level = 5,
        displayName = "Emergency",
        description = "System-critical emergency alert"
    );

    /**
     * Returns true if the alert is high severity
     */
    fun isHighPriority(): Boolean {
        return this == HIGH ||
               this == CRITICAL ||
               this == EMERGENCY
    }

    /**
     * Returns true if immediate user action is recommended
     */
    fun requiresImmediateAction(): Boolean {
        return this == CRITICAL ||
               this == EMERGENCY
    }

    /**
     * Returns UI severity score
     */
    fun severityScore(): Int {
        return when (this) {
            LOW -> 20
            MEDIUM -> 45
            HIGH -> 70
            CRITICAL -> 90
            EMERGENCY -> 100
        }
    }

    companion object {

        /**
         * Convert integer level into AlertPriority
         */
        fun fromLevel(level: Int): AlertPriority {
            return values().find { it.level == level } ?: LOW
        }
    }
}
