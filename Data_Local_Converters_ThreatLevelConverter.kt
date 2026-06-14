package com.sentrix.data.local.converters

import androidx.room.TypeConverter

/**
 * ThreatLevel
 *
 * Represents the severity of a detected threat.
 * Used throughout SentriX for:
 * - Threat analysis
 * - Risk scoring
 * - Security reporting
 * - Alert prioritization
 * - Recommendation generation
 */
enum class ThreatLevel {

    /**
     * Minimal risk.
     * Informational threat with little or no impact.
     */
    LOW,

    /**
     * Moderate risk.
     * Should be monitored and reviewed.
     */
    MEDIUM,

    /**
     * Significant risk.
     * Requires user attention and mitigation.
     */
    HIGH,

    /**
     * Severe threat.
     * Immediate action is recommended.
     */
    CRITICAL
}

/**
 * ThreatLevelConverter
 *
 * Room cannot directly store enum types.
 * This converter transforms ThreatLevel into String
 * for database storage and converts it back when retrieved.
 */
class ThreatLevelConverter {

    /**
     * Converts ThreatLevel enum to String.
     *
     * Example:
     * HIGH -> "HIGH"
     */
    @TypeConverter
    fun fromThreatLevel(level: ThreatLevel?): String? {
        return level?.name
    }

    /**
     * Converts String back to ThreatLevel enum.
     *
     * Example:
     * "CRITICAL" -> ThreatLevel.CRITICAL
     */
    @TypeConverter
    fun toThreatLevel(value: String?): ThreatLevel? {
        return value?.let { ThreatLevel.valueOf(it) }
    }
}
