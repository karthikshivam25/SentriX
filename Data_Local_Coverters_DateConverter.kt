package com.sentrix.data.local.converters

import androidx.room.TypeConverter
import java.util.Date

/**
 * DateConverter
 *
 * Room Database cannot directly store java.util.Date objects.
 * This converter transforms Date objects into Long timestamps
 * for storage and converts them back when retrieving data.
 *
 * Timestamp Format:
 * - Stored as milliseconds since Unix Epoch
 * - Example: 1718352000000
 *
 * Used by:
 * - UserEntity
 * - ThreatEntity
 * - ThreatHistoryEntity
 * - ScanHistoryEntity
 * - SecurityReportEntity
 * - SecurityEventEntity
 * - PrivacyAuditEntity
 * - DeviceTrustEntity
 * - SessionEntity
 * - NotificationEntity
 */
class DateConverter {

    /**
     * Converts Date to Long timestamp.
     *
     * Example:
     * Date -> 1718352000000
     */
    @TypeConverter
    fun fromDate(date: Date?): Long? {
        return date?.time
    }

    /**
     * Converts Long timestamp back to Date.
     *
     * Example:
     * 1718352000000 -> Date
     */
    @TypeConverter
    fun toDate(timestamp: Long?): Date? {
        return timestamp?.let {
            Date(it)
        }
    }
}
