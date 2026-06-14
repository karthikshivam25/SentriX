package com.sentrix.data.local.converters

import androidx.room.TypeConverter

/**
 * SecurityStatus
 *
 * Represents the overall security state of
 * a device, scan, report, or security event
 * within the SentriX platform.
 *
 * Used for:
 * - Security dashboards
 * - Device trust evaluation
 * - Security reports
 * - Risk analysis
 * - Compliance monitoring
 */
enum class SecurityStatus {

    /**
     * No security issues detected.
     */
    SECURE,

    /**
     * Minor security concerns detected.
     * User attention is recommended.
     */
    WARNING,

    /**
     * Significant security risks detected.
     * Action should be taken soon.
     */
    AT_RISK,

    /**
     * Critical security issues detected.
     * Immediate action is required.
     */
    COMPROMISED,

    /**
     * Security assessment is currently running.
     */
    SCANNING,

    /**
     * Security status could not be determined.
     */
    UNKNOWN
}

/**
 * SecurityStatusConverter
 *
 * Room Database cannot directly store enum values.
 * This converter converts SecurityStatus into String
 * for persistence and restores it when reading.
 */
class SecurityStatusConverter {

    /**
     * Converts SecurityStatus enum to String.
     *
     * Example:
     * SECURE -> "SECURE"
     */
    @TypeConverter
    fun fromSecurityStatus(status: SecurityStatus?): String? {
        return status?.name
    }

    /**
     * Converts String back into SecurityStatus enum.
     *
     * Example:
     * "COMPROMISED" -> SecurityStatus.COMPROMISED
     */
    @TypeConverter
    fun toSecurityStatus(value: String?): SecurityStatus? {
        return value?.let {
            SecurityStatus.valueOf(it)
        }
    }
}
