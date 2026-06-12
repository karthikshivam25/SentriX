package com.sentrix.data.local.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters

import com.sentrix.data.local.converters.DateConverter
import com.sentrix.data.local.converters.ThreatLevelConverter
import com.sentrix.data.local.converters.ThreatCategoryConverter

import com.sentrix.data.local.dao.UserDao
import com.sentrix.data.local.dao.ThreatDao
import com.sentrix.data.local.dao.ScanHistoryDao
import com.sentrix.data.local.dao.SecurityEventDao
import com.sentrix.data.local.dao.SecurityReportDao
import com.sentrix.data.local.dao.NotificationDao
import com.sentrix.data.local.dao.DeviceTrustDao
import com.sentrix.data.local.dao.SessionDao

import com.sentrix.data.local.entities.UserEntity
import com.sentrix.data.local.entities.ThreatEntity
import com.sentrix.data.local.entities.ScanHistoryEntity
import com.sentrix.data.local.entities.SecurityEventEntity
import com.sentrix.data.local.entities.SecurityReportEntity
import com.sentrix.data.local.entities.NotificationEntity
import com.sentrix.data.local.entities.DeviceTrustEntity
import com.sentrix.data.local.entities.SessionEntity

/**
 * SentriXDatabase
 *
 * Central Room database for
 * storing security-related data.
 *
 * Responsibilities:
 * - Threat storage
 * - Scan history
 * - Security reports
 * - User sessions
 * - Device trust records
 * - Notifications
 */
@Database(
    entities = [
        UserEntity::class,
        ThreatEntity::class,
        ScanHistoryEntity::class,
        SecurityEventEntity::class,
        SecurityReportEntity::class,
        NotificationEntity::class,
        DeviceTrustEntity::class,
        SessionEntity::class
    ],
    version = 1,
    exportSchema = true
)
@TypeConverters(
    DateConverter::class,
    ThreatLevelConverter::class,
    ThreatCategoryConverter::class
)
abstract class SentriXDatabase : RoomDatabase() {

    /**
     * User data access.
     */
    abstract fun userDao(): UserDao

    /**
     * Threat data access.
     */
    abstract fun threatDao(): ThreatDao

    /**
     * Scan history access.
     */
    abstract fun scanHistoryDao(): ScanHistoryDao

    /**
     * Security event access.
     */
    abstract fun securityEventDao(): SecurityEventDao

    /**
     * Security report access.
     */
    abstract fun securityReportDao(): SecurityReportDao

    /**
     * Notification access.
     */
    abstract fun notificationDao(): NotificationDao

    /**
     * Device trust access.
     */
    abstract fun deviceTrustDao(): DeviceTrustDao

    /**
     * Session access.
     */
    abstract fun sessionDao(): SessionDao

    companion object {

        const val DATABASE_NAME =
            "sentrix_security_database"

        const val DATABASE_VERSION = 1
    }
}
