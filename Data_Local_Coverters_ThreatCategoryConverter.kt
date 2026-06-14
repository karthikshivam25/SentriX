package com.sentrix.data.local.converters

import androidx.room.TypeConverter

/**
 * ThreatCategory
 *
 * Defines the various categories of threats
 * that can be detected and analyzed by SentriX.
 *
 * These categories are used for:
 * - Threat classification
 * - Security reporting
 * - Analytics
 * - Recommendation generation
 * - Alert prioritization
 */
enum class ThreatCategory {

    /**
     * Malicious software designed to harm
     * devices or steal information.
     */
    MALWARE,

    /**
     * Fraudulent attempts to steal
     * sensitive user information.
     */
    PHISHING,

    /**
     * Software that secretly monitors
     * user activity and collects data.
     */
    SPYWARE,

    /**
     * Malware that encrypts files and
     * demands payment for recovery.
     */
    RANSOMWARE,

    /**
     * Ad-supported software that may
     * display unwanted advertisements.
     */
    ADWARE,

    /**
     * Rooting or privilege escalation
     * attempts on the device.
     */
    ROOT_ACCESS,

    /**
     * Suspicious or unauthorized
     * network activity.
     */
    NETWORK_ATTACK,

    /**
     * Unauthorized exposure or theft
     * of sensitive information.
     */
    DATA_LEAK,

    /**
     * Unauthorized access attempts
     * against user accounts.
     */
    ACCOUNT_COMPROMISE,

    /**
     * Unsafe application behavior
     * or potentially harmful apps.
     */
    APPLICATION_THREAT,

    /**
     * Excessive permissions or privacy
     * violations by applications.
     */
    PRIVACY_RISK,

    /**
     * Device configuration weaknesses
     * that reduce security.
     */
    SECURITY_MISCONFIGURATION,

    /**
     * Threat category could not
     * be determined.
     */
    UNKNOWN
}

/**
 * ThreatCategoryConverter
 *
 * Room Database cannot directly store enums.
 * This converter converts ThreatCategory to String
 * for storage and restores it when reading.
 */
class ThreatCategoryConverter {

    /**
     * Converts ThreatCategory enum to String.
     *
     * Example:
     * MALWARE -> "MALWARE"
     */
    @TypeConverter
    fun fromThreatCategory(category: ThreatCategory?): String? {
        return category?.name
    }

    /**
     * Converts String back to ThreatCategory enum.
     *
     * Example:
     * "PHISHING" -> ThreatCategory.PHISHING
     */
    @TypeConverter
    fun toThreatCategory(value: String?): ThreatCategory? {
        return value?.let {
            ThreatCategory.valueOf(it)
        }
    }
}
