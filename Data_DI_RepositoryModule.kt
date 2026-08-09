package com.sentrix.data.di

import com.sentrix.data.repository.analytics.AnalyticsRepositoryImpl
import com.sentrix.data.repository.analytics.CyberDefenseRepositoryImpl
import com.sentrix.data.repository.analytics.DashboardRepositoryImpl
import com.sentrix.data.repository.analytics.SecurityMetricsRepositoryImpl
import com.sentrix.data.repository.analytics.SecurityReportRepositoryImpl

import com.sentrix.data.repository.auth.AuthRepositoryImpl
import com.sentrix.data.repository.auth.SessionRepositoryImpl
import com.sentrix.data.repository.auth.UserRepositoryImpl

import com.sentrix.data.repository.privacy.DataProtectionRepositoryImpl
import com.sentrix.data.repository.privacy.PrivacyAuditRepositoryImpl
import com.sentrix.data.repository.privacy.PrivacyRepositoryImpl
import com.sentrix.data.repository.privacy.PrivacyScoreRepositoryImpl
import com.sentrix.data.repository.privacy.TrackerBlockingRepositoryImpl

import com.sentrix.data.repository.scanner.QuickScanRepositoryImpl
import com.sentrix.data.repository.scanner.ScanHistoryRepositoryImpl
import com.sentrix.data.repository.scanner.ScanOptimizationRepositoryImpl
import com.sentrix.data.repository.scanner.SmartScanRepositoryImpl

import com.sentrix.data.repository.threads.MalwareRepositoryImpl
import com.sentrix.data.repository.threads.ThreatHistoryRepositoryImpl
import com.sentrix.data.repository.threads.ThreatIntelRepositoryImpl
import com.sentrix.data.repository.threads.ThreatPredictionRepositoryImpl
import com.sentrix.data.repository.threads.ThreatRepositoryImpl

import com.sentrix.data.repository.vpn.VPNConnectionRepositoryImpl
import com.sentrix.data.repository.vpn.VPNRepositoryImpl
import com.sentrix.data.repository.vpn.VPNServerRepositoryImpl
import com.sentrix.data.repository.vpn.VPNStatisticsRepositoryImpl

import com.sentrix.domain.repository.analytics.AnalyticsRepository
import com.sentrix.domain.repository.analytics.CyberDefenseRepository
import com.sentrix.domain.repository.analytics.DashboardRepository
import com.sentrix.domain.repository.analytics.SecurityMetricsRepository
import com.sentrix.domain.repository.analytics.SecurityReportRepository

import com.sentrix.domain.repository.auth.AuthRepository
import com.sentrix.domain.repository.auth.SessionRepository
import com.sentrix.domain.repository.auth.UserRepository

import com.sentrix.domain.repository.privacy.DataProtectionRepository
import com.sentrix.domain.repository.privacy.PrivacyAuditRepository
import com.sentrix.domain.repository.privacy.PrivacyRepository
import com.sentrix.domain.repository.privacy.PrivacyScoreRepository
import com.sentrix.domain.repository.privacy.TrackerBlockingRepository

import com.sentrix.domain.repository.scanner.QuickScanRepository
import com.sentrix.domain.repository.scanner.ScanHistoryRepository
import com.sentrix.domain.repository.scanner.ScanOptimizationRepository
import com.sentrix.domain.repository.scanner.SmartScanRepository

import com.sentrix.domain.repository.threads.MalwareRepository
import com.sentrix.domain.repository.threads.ThreatHistoryRepository
import com.sentrix.domain.repository.threads.ThreatIntelRepository
import com.sentrix.domain.repository.threads.ThreatPredictionRepository
import com.sentrix.domain.repository.threads.ThreatRepository

import com.sentrix.domain.repository.vpn.VPNConnectionRepository
import com.sentrix.domain.repository.vpn.VPNRepository
import com.sentrix.domain.repository.vpn.VPNServerRepository
import com.sentrix.domain.repository.vpn.VPNStatisticsRepository

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

/**
 * SentriX - Repository Dependency Injection Module
 *
 * Package:
 * com.sentrix.data.di
 *
 * Responsibility
 * ------------------------------------------------------------
 * Binds Domain repository interfaces to their concrete
 * Data-layer implementations.
 *
 * Clean Architecture dependency direction:
 *
 *                DOMAIN
 *                  │
 *                  │ defines
 *                  ▼
 *         Repository Interfaces
 *                  ▲
 *                  │ implements
 *                  │
 *                 DATA
 *                  │
 *                  ▼
 *         Repository Implementations
 *
 * Example:
 *
 * AuthRepository
 *      ▲
 *      │
 *      └── AuthRepositoryImpl
 *
 * Hilt resolves the dependency automatically:
 *
 * AuthRepository
 *      │
 *      ▼
 * AuthRepositoryImpl
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This module does NOT create repository instances manually.
 *
 * @Binds tells Hilt:
 *
 * "Whenever a class requests the interface, provide the
 * corresponding implementation."
 *
 * This keeps UseCases dependent on abstractions rather than
 * concrete Data-layer classes.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    // ========================================================================
    // AUTHENTICATION REPOSITORIES
    // ========================================================================

    /**
     * Binds AuthRepository to AuthRepositoryImpl.
     *
     * Used by authentication-related UseCases.
     */
    @Binds
    abstract fun bindAuthRepository(
        implementation: AuthRepositoryImpl
    ): AuthRepository

    /**
     * Binds SessionRepository to SessionRepositoryImpl.
     *
     * Handles session persistence and session state operations.
     */
    @Binds
    abstract fun bindSessionRepository(
        implementation: SessionRepositoryImpl
    ): SessionRepository

    /**
     * Binds UserRepository to UserRepositoryImpl.
     *
     * Handles user profile and user-related persistence.
     */
    @Binds
    abstract fun bindUserRepository(
        implementation: UserRepositoryImpl
    ): UserRepository

    // ========================================================================
    // THREAT REPOSITORIES
    // ========================================================================

    /**
     * Binds ThreatRepository to ThreatRepositoryImpl.
     *
     * Central repository for threat information.
     */
    @Binds
    abstract fun bindThreatRepository(
        implementation: ThreatRepositoryImpl
    ): ThreatRepository

    /**
     * Binds ThreatHistoryRepository to
     * ThreatHistoryRepositoryImpl.
     *
     * Handles historical threat records.
     */
    @Binds
    abstract fun bindThreatHistoryRepository(
        implementation: ThreatHistoryRepositoryImpl
    ): ThreatHistoryRepository

    /**
     * Binds ThreatPredictionRepository to
     * ThreatPredictionRepositoryImpl.
     *
     * Handles persisted and remote threat predictions.
     */
    @Binds
    abstract fun bindThreatPredictionRepository(
        implementation: ThreatPredictionRepositoryImpl
    ): ThreatPredictionRepository

    /**
     * Binds ThreatIntelRepository to
     * ThreatIntelRepositoryImpl.
     *
     * Handles threat-intelligence information.
     */
    @Binds
    abstract fun bindThreatIntelRepository(
        implementation: ThreatIntelRepositoryImpl
    ): ThreatIntelRepository

    /**
     * Binds MalwareRepository to MalwareRepositoryImpl.
     *
     * Handles malware-related data.
     */
    @Binds
    abstract fun bindMalwareRepository(
        implementation: MalwareRepositoryImpl
    ): MalwareRepository

    // ========================================================================
    // SCANNER REPOSITORIES
    // ========================================================================

    /**
     * Binds QuickScanRepository to QuickScanRepositoryImpl.
     *
     * Handles quick-scan data operations.
     */
    @Binds
    abstract fun bindQuickScanRepository(
        implementation: QuickScanRepositoryImpl
    ): QuickScanRepository

    /**
     * Binds SmartScanRepository to SmartScanRepositoryImpl.
     *
     * Handles intelligent/deep scanning operations.
     */
    @Binds
    abstract fun bindSmartScanRepository(
        implementation: SmartScanRepositoryImpl
    ): SmartScanRepository

    /**
     * Binds ScanOptimizationRepository to
     * ScanOptimizationRepositoryImpl.
     *
     * Handles scan optimization configuration and data.
     */
    @Binds
    abstract fun bindScanOptimizationRepository(
        implementation: ScanOptimizationRepositoryImpl
    ): ScanOptimizationRepository

    /**
     * Binds ScanHistoryRepository to
     * ScanHistoryRepositoryImpl.
     *
     * Handles historical scan records.
     */
    @Binds
    abstract fun bindScanHistoryRepository(
        implementation: ScanHistoryRepositoryImpl
    ): ScanHistoryRepository

    // ========================================================================
    // ANALYTICS REPOSITORIES
    // ========================================================================

    /**
     * Binds AnalyticsRepository to AnalyticsRepositoryImpl.
     */
    @Binds
    abstract fun bindAnalyticsRepository(
        implementation: AnalyticsRepositoryImpl
    ): AnalyticsRepository

    /**
     * Binds SecurityMetricsRepository to
     * SecurityMetricsRepositoryImpl.
     */
    @Binds
    abstract fun bindSecurityMetricsRepository(
        implementation: SecurityMetricsRepositoryImpl
    ): SecurityMetricsRepository

    /**
     * Binds SecurityReportRepository to
     * SecurityReportRepositoryImpl.
     */
    @Binds
    abstract fun bindSecurityReportRepository(
        implementation: SecurityReportRepositoryImpl
    ): SecurityReportRepository

    /**
     * Binds DashboardRepository to DashboardRepositoryImpl.
     */
    @Binds
    abstract fun bindDashboardRepository(
        implementation: DashboardRepositoryImpl
    ): DashboardRepository

    /**
     * Binds CyberDefenseRepository to
     * CyberDefenseRepositoryImpl.
     */
    @Binds
    abstract fun bindCyberDefenseRepository(
        implementation: CyberDefenseRepositoryImpl
    ): CyberDefenseRepository

    // ========================================================================
    // VPN REPOSITORIES
    // ========================================================================

    /**
     * Binds VPNRepository to VPNRepositoryImpl.
     *
     * Handles primary VPN operations.
     */
    @Binds
    abstract fun bindVPNRepository(
        implementation: VPNRepositoryImpl
    ): VPNRepository

    /**
     * Binds VPNConnectionRepository to
     * VPNConnectionRepositoryImpl.
     */
    @Binds
    abstract fun bindVPNConnectionRepository(
        implementation: VPNConnectionRepositoryImpl
    ): VPNConnectionRepository

    /**
     * Binds VPNServerRepository to
     * VPNServerRepositoryImpl.
     */
    @Binds
    abstract fun bindVPNServerRepository(
        implementation: VPNServerRepositoryImpl
    ): VPNServerRepository

    /**
     * Binds VPNStatisticsRepository to
     * VPNStatisticsRepositoryImpl.
     */
    @Binds
    abstract fun bindVPNStatisticsRepository(
        implementation: VPNStatisticsRepositoryImpl
    ): VPNStatisticsRepository

    // ========================================================================
    // PRIVACY REPOSITORIES
    // ========================================================================

    /**
     * Binds PrivacyRepository to PrivacyRepositoryImpl.
     */
    @Binds
    abstract fun bindPrivacyRepository(
        implementation: PrivacyRepositoryImpl
    ): PrivacyRepository

    /**
     * Binds PrivacyAuditRepository to
     * PrivacyAuditRepositoryImpl.
     */
    @Binds
    abstract fun bindPrivacyAuditRepository(
        implementation: PrivacyAuditRepositoryImpl
    ): PrivacyAuditRepository

    /**
     * Binds TrackerBlockingRepository to
     * TrackerBlockingRepositoryImpl.
     */
    @Binds
    abstract fun bindTrackerBlockingRepository(
        implementation: TrackerBlockingRepositoryImpl
    ): TrackerBlockingRepository

    /**
     * Binds DataProtectionRepository to
     * DataProtectionRepositoryImpl.
     */
    @Binds
    abstract fun bindDataProtectionRepository(
        implementation: DataProtectionRepositoryImpl
    ): DataProtectionRepository

    /**
     * Binds PrivacyScoreRepository to
     * PrivacyScoreRepositoryImpl.
     */
    @Binds
    abstract fun bindPrivacyScoreRepository(
        implementation: PrivacyScoreRepositoryImpl
    ): PrivacyScoreRepository
}
