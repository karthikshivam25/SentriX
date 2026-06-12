package com.sentrix.data.local.database

import android.content.Context

import androidx.room.Room

import com.sentrix.data.local.dao.DeviceTrustDao
import com.sentrix.data.local.dao.NotificationDao
import com.sentrix.data.local.dao.ScanHistoryDao
import com.sentrix.data.local.dao.SecurityEventDao
import com.sentrix.data.local.dao.SecurityReportDao
import com.sentrix.data.local.dao.SessionDao
import com.sentrix.data.local.dao.ThreatDao
import com.sentrix.data.local.dao.UserDao

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent

import javax.inject.Singleton

/**
 * DatabaseModule
 *
 * Provides Room database
 * dependencies for SentriX.
 *
 * Responsibilities:
 * - Create database instance
 * - Provide DAOs
 * - Manage database lifecycle
 */
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    /**
     * Provides SentriX database.
     */
    @Provides
    @Singleton
    fun provideSentriXDatabase(
        @ApplicationContext
        context: Context
    ): SentriXDatabase {

        return Room.databaseBuilder(
            context,
            SentriXDatabase::class.java,
            SentriXDatabase.DATABASE_NAME
        )
            .fallbackToDestructiveMigration()
            .build()
    }

    /**
     * Provides UserDao.
     */
    @Provides
    fun provideUserDao(
        database: SentriXDatabase
    ): UserDao =
        database.userDao()

    /**
     * Provides ThreatDao.
     */
    @Provides
    fun provideThreatDao(
        database: SentriXDatabase
    ): ThreatDao =
        database.threatDao()

    /**
     * Provides ScanHistoryDao.
     */
    @Provides
    fun provideScanHistoryDao(
        database: SentriXDatabase
    ): ScanHistoryDao =
        database.scanHistoryDao()

    /**
     * Provides SecurityEventDao.
     */
    @Provides
    fun provideSecurityEventDao(
        database: SentriXDatabase
    ): SecurityEventDao =
        database.securityEventDao()

    /**
     * Provides SecurityReportDao.
     */
    @Provides
    fun provideSecurityReportDao(
        database: SentriXDatabase
    ): SecurityReportDao =
        database.securityReportDao()

    /**
     * Provides NotificationDao.
     */
    @Provides
    fun provideNotificationDao(
        database: SentriXDatabase
    ): NotificationDao =
        database.notificationDao()

    /**
     * Provides DeviceTrustDao.
     */
    @Provides
    fun provideDeviceTrustDao(
        database: SentriXDatabase
    ): DeviceTrustDao =
        database.deviceTrustDao()

    /**
     * Provides SessionDao.
     */
    @Provides
    fun provideSessionDao(
        database: SentriXDatabase
    ): SessionDao =
        database.sessionDao()
}
