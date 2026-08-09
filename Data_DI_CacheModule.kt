package com.sentrix.data.di

import com.sentrix.data.cache.CacheManager
import com.sentrix.data.cache.MemoryCache
import com.sentrix.data.cache.ScanCache
import com.sentrix.data.cache.SecurityMetricsCache
import com.sentrix.data.cache.SecurityReportCache
import com.sentrix.data.cache.ThreatCache
import com.sentrix.data.cache.ThreatHistoryCache
import com.sentrix.data.cache.UserCache
import com.sentrix.data.cache.VPNCache
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * SentriX - Cache Dependency Injection Module
 *
 * Package:
 * com.sentrix.data.di
 *
 * Responsibility
 * ------------------------------------------------------------
 * Provides SentriX cache implementations through Hilt.
 *
 * Cache architecture:
 *
 *                         CacheModule
 *                              │
 *                    ┌─────────┴─────────┐
 *                    ▼                   ▼
 *              MemoryCache          CacheManager
 *                                        │
 *              ┌─────────────────────────┼──────────────────────┐
 *              │                         │                      │
 *              ▼                         ▼                      ▼
 *         ThreatCache            UserCache              ScanCache
 *              │
 *              ├── ThreatHistoryCache
 *              ├── SecurityMetricsCache
 *              ├── SecurityReportCache
 *              └── VPNCache
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * Cache implementations belong to the Data layer.
 *
 * Domain UseCases should not directly depend on concrete
 * cache implementations.
 *
 * Repository implementations may use these caches to implement
 * caching strategies.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This module only creates and provides cache dependencies.
 *
 * It must NOT:
 *
 * - Perform network calls.
 * - Execute database operations.
 * - Analyze threats.
 * - Calculate security scores.
 * - Make security decisions.
 * - Modify Domain business rules.
 */
@Module
@InstallIn(SingletonComponent::class)
object CacheModule {

    // ========================================================================
    // MEMORY CACHE
    // ========================================================================

    /**
     * Provides the central in-memory cache.
     *
     * MemoryCache is shared throughout the application process.
     *
     * Typical responsibilities:
     *
     * - Fast temporary data access.
     * - Generic key/value caching.
     * - Memory-based cache invalidation.
     *
     * The cache must not be treated as permanent storage.
     */
    @Provides
    @Singleton
    fun provideMemoryCache(): MemoryCache {

        return MemoryCache()
    }

    // ========================================================================
    // THREAT CACHE
    // ========================================================================

    /**
     * Provides the SentriX threat cache.
     *
     * Used by ThreatRepositoryImpl and related threat
     * components to reduce unnecessary network/database reads.
     */
    @Provides
    @Singleton
    fun provideThreatCache(
        memoryCache: MemoryCache
    ): ThreatCache {

        return ThreatCache(
            memoryCache = memoryCache
        )
    }

    // ========================================================================
    // THREAT HISTORY CACHE
    // ========================================================================

    /**
     * Provides the threat-history cache.
     *
     * Stores recently accessed threat-history information
     * for fast retrieval.
     */
    @Provides
    @Singleton
    fun provideThreatHistoryCache(
        memoryCache: MemoryCache
    ): ThreatHistoryCache {

        return ThreatHistoryCache(
            memoryCache = memoryCache
        )
    }

    // ========================================================================
    // SECURITY METRICS CACHE
    // ========================================================================

    /**
     * Provides the security-metrics cache.
     *
     * Used to temporarily retain frequently requested
     * security analytics.
     */
    @Provides
    @Singleton
    fun provideSecurityMetricsCache(
        memoryCache: MemoryCache
    ): SecurityMetricsCache {

        return SecurityMetricsCache(
            memoryCache = memoryCache
        )
    }

    // ========================================================================
    // VPN CACHE
    // ========================================================================

    /**
     * Provides the VPN cache.
     *
     * Used for frequently accessed VPN state, server
     * information, and related runtime data.
     */
    @Provides
    @Singleton
    fun provideVPNCache(
        memoryCache: MemoryCache
    ): VPNCache {

        return VPNCache(
            memoryCache = memoryCache
        )
    }

    // ========================================================================
    // USER CACHE
    // ========================================================================

    /**
     * Provides the user cache.
     *
     * Used for frequently accessed user information.
     *
     * IMPORTANT:
     * ------------------------------------------------------------
     * Authentication credentials, refresh tokens, passwords,
     * private keys, or other secrets should not be placed into
     * a generic memory cache unless explicitly required by the
     * authentication architecture.
     */
    @Provides
    @Singleton
    fun provideUserCache(
        memoryCache: MemoryCache
    ): UserCache {

        return UserCache(
            memoryCache = memoryCache
        )
    }

    // ========================================================================
    // SCAN CACHE
    // ========================================================================

    /**
     * Provides the scan cache.
     *
     * Used for recently requested scan results and scan state.
     */
    @Provides
    @Singleton
    fun provideScanCache(
        memoryCache: MemoryCache
    ): ScanCache {

        return ScanCache(
            memoryCache = memoryCache
        )
    }

    // ========================================================================
    // SECURITY REPORT CACHE
    // ========================================================================

    /**
     * Provides the security-report cache.
     *
     * Used for recently generated or retrieved security
     * reports.
     */
    @Provides
    @Singleton
    fun provideSecurityReportCache(
        memoryCache: MemoryCache
    ): SecurityReportCache {

        return SecurityReportCache(
            memoryCache = memoryCache
        )
    }

    // ========================================================================
    // CENTRAL CACHE MANAGER
    // ========================================================================

    /**
     * Provides the centralized CacheManager.
     *
     * CacheManager coordinates the specialized SentriX caches.
     *
     * Instead of repositories needing to know about every cache
     * implementation, CacheManager can provide a centralized
     * cache-management API.
     *
     * Example architecture:
     *
     * Repository
     *      │
     *      ▼
     * CacheManager
     *      │
     *      ├── ThreatCache
     *      ├── ThreatHistoryCache
     *      ├── SecurityMetricsCache
     *      ├── SecurityReportCache
     *      ├── VPNCache
     *      ├── UserCache
     *      └── ScanCache
     */
    @Provides
    @Singleton
    fun provideCacheManager(
        memoryCache: MemoryCache,
        threatCache: ThreatCache,
        threatHistoryCache: ThreatHistoryCache,
        securityMetricsCache: SecurityMetricsCache,
        vpnCache: VPNCache,
        userCache: UserCache,
        scanCache: ScanCache,
        securityReportCache: SecurityReportCache
    ): CacheManager {

        return CacheManager(
            memoryCache = memoryCache,
            threatCache = threatCache,
            threatHistoryCache = threatHistoryCache,
            securityMetricsCache = securityMetricsCache,
            vpnCache = vpnCache,
            userCache = userCache,
            scanCache = scanCache,
            securityReportCache = securityReportCache
        )
    }
}
