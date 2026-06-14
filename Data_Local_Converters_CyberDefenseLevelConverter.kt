package com.sentrix.data.local.converters

import androidx.room.TypeConverter

/**
 * CyberDefenseLevel
 *
 * Represents the level of protection currently
 * provided by SentriX's Cyber Defense Engine.
 *
 * Used for:
 * - Real-time protection monitoring
 * - Security policy enforcement
 * - Threat response systems
 * - Risk management
 * - Security reporting
 * - Device protection dashboards
 */
enum class CyberDefenseLevel {

    /**
     * Basic protection only.
     * Minimal security monitoring enabled.
     */
    BASIC,

    /**
     * Standard protection level.
     * Suitable for most users.
     */
    STANDARD,

    /**
     * Enhanced monitoring and protection.
     * Additional security controls enabled.
     */
    ADVANCED,

    /**
     * Maximum protection mode.
     * Aggressive threat detection and prevention.
     */
    MAXIMUM,

    /**
     * Emergency defense mode activated.
     * Triggered when critical threats are detected.
     */
    EMERGENCY
}

/**
 * CyberDefenseLevelConverter
 *
 * Room Database cannot directly store enum values.
 * This converter converts CyberDefenseLevel into String
 * for persistence and restores it when reading.
 */
class CyberDefenseLevelConverter {

    /**
     * Converts CyberDefenseLevel enum to String.
     *
     * Example:
     * ADVANCED -> "ADVANCED"
     */
    @TypeConverter
    fun fromCyberDefenseLevel(level: CyberDefenseLevel?): String? {
        return level?.name
    }

    /**
     * Converts String back to CyberDefenseLevel enum.
     *
     * Example:
     * "MAXIMUM" -> CyberDefenseLevel.MAXIMUM
     */
    @TypeConverter
    fun toCyberDefenseLevel(value: String?): CyberDefenseLevel? {
        return value?.let {
            CyberDefenseLevel.valueOf(it)
        }
    }
}
