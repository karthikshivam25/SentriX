package com.sentrix.data.local.converters

import androidx.room.TypeConverter

/**
 * ScanType
 *
 * Defines the different types of security scans
 * that can be performed by SentriX.
 */
enum class ScanType {

    /**
     * Scans the entire device including apps,
     * files, storage, and system components.
     */
    FULL_SCAN,

    /**
     * Quick scan of commonly targeted areas.
     * Faster but less comprehensive.
     */
    QUICK_SCAN,

    /**
     * Scans installed applications only.
     */
    APP_SCAN,

    /**
     * Scans device storage for suspicious files.
     */
    FILE_SCAN,

    /**
     * Scans network connections and activity.
     */
    NETWORK_SCAN,

    /**
     * Checks device configuration and security posture.
     */
    SECURITY_AUDIT,

    /**
     * Reviews app permissions, trackers,
     * and privacy-related risks.
     */
    PRIVACY_SCAN,

    /**
     * User-selected custom scan.
     */
    CUSTOM_SCAN
}

/**
 * ScanTypeConverter
 *
 * Room Database cannot directly store enum values.
 * This converter transforms ScanType to String
 * when saving and restores it when reading.
 */
class ScanTypeConverter {

    /**
     * Converts ScanType enum to String.
     *
     * Example:
     * QUICK_SCAN -> "QUICK_SCAN"
     */
    @TypeConverter
    fun fromScanType(scanType: ScanType?): String? {
        return scanType?.name
    }

    /**
     * Converts String back to ScanType enum.
     *
     * Example:
     * "FULL_SCAN" -> ScanType.FULL_SCAN
     */
    @TypeConverter
    fun toScanType(value: String?): ScanType? {
        return value?.let {
            ScanType.valueOf(it)
        }
    }
}
