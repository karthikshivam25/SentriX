package com.sentrix.data.di

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.sentrix.data.local.SentriXDatabase
import com.sentrix.data.local.dao.AnalyticsDao
import com.sentrix.data.local.dao.DataProtectionDao
import com.sentrix.data.local.dao.DeviceTrustDao
import com.sentrix.data.local.dao.NotificationDao
import com.sentrix.data.local.dao.PrivacyAuditDao
import com.sentrix.data.local.dao.PrivacyDao
import com.sentrix.data.local.dao.PrivacyScoreDao
import com.sentrix.data.local.dao.ScanHistoryDao
import com.sentrix.data.local.dao.SecurityEventDao
import com.sentrix.data.local.dao.SecurityMetricsDao
import com.sentrix.data.local.dao.SecurityReportDao
import com.sentrix.data.local.dao.SessionDao
import com.sentrix.data.local.dao.ThreatDao
import com.sentrix.data.local.dao.ThreatHistoryDao
import com.sentrix.data.local.dao.ThreatPredictionDao
import com.sentrix.data.local.dao.ThreatIntelDao
import com.sentrix.data.local.dao.TrackerBlockingDao
import com.sentrix.data.local.dao.UserDao
import com.sentrix.data.local.dao.VPNConnectionDao
import com.sentrix.data.local.dao.VPNServerDao
import com.sentrix.data.local.dao.VPNStatisticsDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * SentriX - Database Dependency Injection Module
 *
 * Package:
 * com.sentrix.data.di
 *
 * Responsibility
 * ------------------------------------------------------------
 * Provides the SentriX Room database and all Data-layer DAO
 * dependencies through Hilt.
 *
 * Architecture:
 *
 * Application
 *      │
 *      ▼
 * DatabaseModule
 *      │
 *      ▼
 * SentriXDatabase
 *      │
 *      ├── ThreatDao
 *      ├── ThreatHistoryDao
 *      ├── ThreatPredictionDao
 *      ├── ThreatIntelDao
 *      ├── UserDao
 *      ├── SessionDao
 *      ├── ScanHistoryDao
 *      ├── SecurityMetricsDao
 *      ├── SecurityReportDao
 *      ├── PrivacyDao
 *      ├── PrivacyAuditDao
 *      ├── TrackerBlockingDao
 *      ├── DataProtectionDao
 *      ├── PrivacyScoreDao
 *      ├── VPNConnectionDao
 *      ├── VPNServerDao
 *      ├── VPNStatisticsDao
 *      ├── DeviceTrustDao
 *      ├── SecurityEventDao
 *      ├── NotificationDao
 *      └── AnalyticsDao
 *
 * Hilt Scope:
 * ------------------------------------------------------------
 * SingletonComponent
 *
 * The database and DAO instances live for the lifetime of the
 * application process.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * DatabaseModule is responsible only for dependency
 * construction.
 *
 * It must NOT contain:
 *
 * - Business logic.
 * - Threat analysis.
 * - Security scoring.
 * - Repository logic.
 * - API calls.
 * - Cache logic.
 */
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    // ========================================================================
    // DATABASE
    // ========================================================================

    /**
     * Provides the application-level Room database.
     *
     * RoomDatabase is expensive to create and should therefore
     * be instantiated only once per application process.
     *
     * @param context Application context supplied by Hilt.
     *
     * @return Singleton SentriXDatabase instance.
     */
    @Provides
    @Singleton
    fun provideSentriXDatabase(
        @ApplicationContext context: Context
    ): SentriXDatabase {

        return Room.databaseBuilder(
            context,
            SentriXDatabase::class.java,
            DATABASE_NAME
        )
            /**
             * Database migrations should be added here as the
             * schema evolves.
             *
             * Example:
             *
             * .addMigrations(
             *     MIGRATION_1_2,
             *     MIGRATION_2_3
             * )
             */

            /**
             * Destructive migration is intentionally NOT enabled.
             *
             * Security history such as:
             *
             * - Threat history
             * - Scan history
             * - Security reports
             * - Privacy audits
             *
             * should not be silently deleted because of a schema
             * mismatch.
             *
             * Production migration scripts should be supplied
             * instead.
             */

            .fallbackToDestructiveMigrationOnDowngrade()

            .build()
    }

    // ========================================================================
    // THREAT DAOS
    // ========================================================================

    /**
     * Provides ThreatDao.
     */
    @Provides
    @Singleton
    fun provideThreatDao(
        database: SentriXDatabase
    ): ThreatDao {

        return database.threatDao()
    }

    /**
     * Provides ThreatHistoryDao.
     */
    @Provides
    @Singleton
    fun provideThreatHistoryDao(
        database: SentriXDatabase
    ): ThreatHistoryDao {

        return database.threatHistoryDao()
    }

    /**
     * Provides ThreatPredictionDao.
     */
    @Provides
    @Singleton
    fun provideThreatPredictionDao(
        database: SentriXDatabase
    ): ThreatPredictionDao {

        return database.threatPredictionDao()
    }

    /**
     * Provides ThreatIntelDao.
     */
    @Provides
    @Singleton
    fun provideThreatIntelDao(
        database: SentriXDatabase
    ): ThreatIntelDao {

        return database.threatIntelDao()
    }

    // ========================================================================
    // AUTHENTICATION DAOS
    // ========================================================================

    /**
     * Provides UserDao.
     */
    @Provides
    @Singleton
    fun provideUserDao(
        database: SentriXDatabase
    ): UserDao {

        return database.userDao()
    }

    /**
     * Provides SessionDao.
     */
    @Provides
    @Singleton
    fun provideSessionDao(
        database: SentriXDatabase
    ): SessionDao {

        return database.sessionDao()
    }

    // ========================================================================
    // SCANNER DAOS
    // ========================================================================

    /**
     * Provides ScanHistoryDao.
     */
    @Provides
    @Singleton
    fun provideScanHistoryDao(
        database: SentriXDatabase
    ): ScanHistoryDao {

        return database.scanHistoryDao()
    }

    // ========================================================================
    // ANALYTICS DAOS
    // ========================================================================

    /**
     * Provides AnalyticsDao.
     */
    @Provides
    @Singleton
    fun provideAnalyticsDao(
        database: SentriXDatabase
    ): AnalyticsDao {

        return database.analyticsDao()
    }

    /**
     * Provides SecurityMetricsDao.
     */
    @Provides
    @Singleton
    fun provideSecurityMetricsDao(
        database: SentriXDatabase
    ): SecurityMetricsDao {

        return database.securityMetricsDao()
    }

    /**
     * Provides SecurityReportDao.
     */
    @Provides
    @Singleton
    fun provideSecurityReportDao(
        database: SentriXDatabase
    ): SecurityReportDao {

        return database.securityReportDao()
    }

    // ========================================================================
    // PRIVACY DAOS
    // ========================================================================

    /**
     * Provides PrivacyDao.
     */
    @Provides
    @Singleton
    fun providePrivacyDao(
        database: SentriXDatabase
    ): PrivacyDao {

        return database.privacyDao()
    }

    /**
     * Provides PrivacyAuditDao.
     */
    @Provides
    @Singleton
    fun providePrivacyAuditDao(
        database: SentriXDatabase
    ): PrivacyAuditDao {

        return database.privacyAuditDao()
    }

    /**
     * Provides TrackerBlockingDao.
     */
    @Provides
    @Singleton
    fun provideTrackerBlockingDao(
        database: SentriXDatabase
    ): TrackerBlockingDao {

        return database.trackerBlockingDao()
    }

    /**
     * Provides DataProtectionDao.
     */
    @Provides
    @Singleton
    fun provideDataProtectionDao(
        database: SentriXDatabase
    ): DataProtectionDao {

        return database.dataProtectionDao()
    }

    /**
     * Provides PrivacyScoreDao.
     */
    @Provides
    @Singleton
    fun providePrivacyScoreDao(
        database: SentriXDatabase
    ): PrivacyScoreDao {

        return database.privacyScoreDao()
    }

    // ========================================================================
    // VPN DAOS
    // ========================================================================

    /**
     * Provides VPNConnectionDao.
     */
    @Provides
    @Singleton
    fun provideVPNConnectionDao(
        database: SentriXDatabase
    ): VPNConnectionDao {

        return database.vpnConnectionDao()
    }

    /**
     * Provides VPNServerDao.
     */
    @Provides
    @Singleton
    fun provideVPNServerDao(
        database: SentriXDatabase
    ): VPNServerDao {

        return database.vpnServerDao()
    }

    /**
     * Provides VPNStatisticsDao.
     */
    @Provides
    @Singleton
    fun provideVPNStatisticsDao(
        database: SentriXDatabase
    ): VPNStatisticsDao {

        return database.vpnStatisticsDao()
    }

    // ========================================================================
    // SECURITY / DEVICE DAOS
    // ========================================================================

    /**
     * Provides DeviceTrustDao.
     */
    @Provides
    @Singleton
    fun provideDeviceTrustDao(
        database: SentriXDatabase
    ): DeviceTrustDao {

        return database.deviceTrustDao()
    }

    /**
     * Provides SecurityEventDao.
     */
    @Provides
    @Singleton
    fun provideSecurityEventDao(
        database: SentriXDatabase
    ): SecurityEventDao {

        return database.securityEventDao()
    }

    /**
     * Provides NotificationDao.
     */
    @Provides
    @Singleton
    fun provideNotificationDao(
        database: SentriXDatabase
    ): NotificationDao {

        return database.notificationDao()
    }

    // ========================================================================
    // DATABASE CONSTANTS
    // ========================================================================

    /**
     * Database filename.
     *
     * Keeping this in one location avoids hard-coded database
     * names throughout the Data layer.
     */
    private const val DATABASE_NAME =
        "sentrix_database"
}
