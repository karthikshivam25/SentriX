package com.sentrix.data.cache

import com.sentrix.domain.models.SecurityMetrics
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Security Metrics Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Feature-specific cache for SentriX security metrics.
 *
 * SecurityMetricsCache provides a strongly typed abstraction
 * over the generic CacheManager.
 *
 * It is responsible for caching:
 *
 * - Overall security metrics.
 * - Security metric snapshots.
 * - Application-specific metrics.
 * - Threat metrics.
 * - Malware metrics.
 * - Scan metrics.
 * - Privacy metrics.
 * - Network metrics.
 * - VPN metrics.
 * - Security score metrics.
 * - Risk metrics.
 * - Dashboard metric data.
 * - Historical metric queries.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class does NOT calculate security metrics.
 *
 * Metric calculation belongs to the Domain layer, for example:
 *
 * - AnalyticsService.
 * - SecurityMetricsService.
 * - RiskScoringService.
 * - ThreatAnalysisService.
 *
 * SecurityMetricsCache only stores and retrieves already
 * calculated metric data.
 *
 * Clean Architecture:
 *
 * SecurityMetricsRepositoryImpl
 *              │
 *              ▼
 *      SecurityMetricsCache
 *              │
 *              ▼
 *         CacheManager
 *              │
 *              ▼
 *        In-Memory Cache
 */
@Singleton
class SecurityMetricsCache @Inject constructor(
    private val cacheManager: CacheManager
) {

    // -------------------------------------------------------------------------
    // Overall Security Metrics
    // -------------------------------------------------------------------------

    /**
     * Stores the latest overall security metrics.
     *
     * A short TTL is used because security metrics can change
     * frequently as scans, threats, and network events occur.
     */
    fun putMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = CacheKeys.SECURITY_METRICS,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the latest cached security metrics.
     */
    fun getMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            CacheKeys.SECURITY_METRICS
        )
    }

    /**
     * Checks whether current security metrics exist
     * in the cache.
     */
    fun containsMetrics(): Boolean {

        return cacheManager.contains(
            CacheKeys.SECURITY_METRICS
        )
    }

    /**
     * Removes the latest security metrics from cache.
     */
    fun removeMetrics(): Boolean {

        return cacheManager.remove(
            CacheKeys.SECURITY_METRICS
        )
    }

    /**
     * Refreshes the current security metrics cache.
     */
    fun refreshMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.refresh(
            key = CacheKeys.SECURITY_METRICS,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves metrics from cache or loads them using the
     * supplied loader.
     *
     * Implements the cache-aside pattern.
     */
    suspend fun getMetricsOrLoad(
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS,
        loader: suspend () -> SecurityMetrics
    ): SecurityMetrics {

        return cacheManager.getOrPut(
            key = CacheKeys.SECURITY_METRICS,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Application Metrics
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for application-specific metrics.
     */
    private fun applicationMetricsKey(
        packageName: String
    ): String {

        return "analytics:security_metrics:app:" +
            packageName.trim().lowercase()
    }

    /**
     * Stores security metrics for a specific application.
     */
    fun putApplicationMetrics(
        packageName: String,
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        if (packageName.isBlank()) {
            return
        }

        cacheManager.put(
            key = applicationMetricsKey(
                packageName
            ),
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves application-specific security metrics.
     */
    fun getApplicationMetrics(
        packageName: String
    ): SecurityMetrics? {

        if (packageName.isBlank()) {
            return null
        }

        return cacheManager.get(
            applicationMetricsKey(
                packageName
            )
        )
    }

    /**
     * Checks whether application metrics exist in cache.
     */
    fun containsApplicationMetrics(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.contains(
            applicationMetricsKey(
                packageName
            )
        )
    }

    /**
     * Removes metrics for a specific application.
     */
    fun removeApplicationMetrics(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.remove(
            applicationMetricsKey(
                packageName
            )
        )
    }

    // -------------------------------------------------------------------------
    // Time-Range Metrics
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for metrics associated with a
     * specific time range.
     *
     * This is useful for:
     *
     * - Daily dashboards.
     * - Weekly reports.
     * - Monthly analytics.
     * - Security trend charts.
     */
    private fun timeRangeKey(
        startTime: Long,
        endTime: Long
    ): String {

        return "analytics:security_metrics:" +
            "range:$startTime:$endTime"
    }

    /**
     * Stores metrics for a time range.
     */
    fun putTimeRangeMetrics(
        startTime: Long,
        endTime: Long,
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        if (startTime > endTime) {
            return
        }

        cacheManager.put(
            key = timeRangeKey(
                startTime,
                endTime
            ),
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves metrics for a time range.
     */
    fun getTimeRangeMetrics(
        startTime: Long,
        endTime: Long
    ): SecurityMetrics? {

        if (startTime > endTime) {
            return null
        }

        return cacheManager.get(
            timeRangeKey(
                startTime,
                endTime
            )
        )
    }

    /**
     * Removes metrics associated with a time range.
     */
    fun removeTimeRangeMetrics(
        startTime: Long,
        endTime: Long
    ): Boolean {

        if (startTime > endTime) {
            return false
        }

        return cacheManager.remove(
            timeRangeKey(
                startTime,
                endTime
            )
        )
    }

    // -------------------------------------------------------------------------
    // Threat Metrics
    // -------------------------------------------------------------------------

    /**
     * Cache key for threat metrics.
     */
    private const val THREAT_METRICS_KEY =
        "analytics:security_metrics:threats"

    /**
     * Stores threat-related metrics.
     *
     * The generic SecurityMetrics object is used here so the
     * cache remains aligned with the SentriX Domain model.
     */
    fun putThreatMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = THREAT_METRICS_KEY,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached threat metrics.
     */
    fun getThreatMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            THREAT_METRICS_KEY
        )
    }

    /**
     * Removes cached threat metrics.
     */
    fun removeThreatMetrics(): Boolean {

        return cacheManager.remove(
            THREAT_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Scan Metrics
    // -------------------------------------------------------------------------

    /**
     * Cache key for scanner metrics.
     */
    private const val SCAN_METRICS_KEY =
        "analytics:security_metrics:scans"

    /**
     * Stores scanner-related metrics.
     */
    fun putScanMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = SCAN_METRICS_KEY,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves scanner metrics.
     */
    fun getScanMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            SCAN_METRICS_KEY
        )
    }

    /**
     * Removes scanner metrics.
     */
    fun removeScanMetrics(): Boolean {

        return cacheManager.remove(
            SCAN_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Privacy Metrics
    // -------------------------------------------------------------------------

    /**
     * Cache key for privacy metrics.
     */
    private const val PRIVACY_METRICS_KEY =
        "analytics:security_metrics:privacy"

    /**
     * Stores privacy-related security metrics.
     */
    fun putPrivacyMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = PRIVACY_METRICS_KEY,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves privacy metrics.
     */
    fun getPrivacyMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            PRIVACY_METRICS_KEY
        )
    }

    /**
     * Removes privacy metrics.
     */
    fun removePrivacyMetrics(): Boolean {

        return cacheManager.remove(
            PRIVACY_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Network Metrics
    // -------------------------------------------------------------------------

    /**
     * Cache key for network security metrics.
     */
    private const val NETWORK_METRICS_KEY =
        "analytics:security_metrics:network"

    /**
     * Stores network-related metrics.
     */
    fun putNetworkMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = NETWORK_METRICS_KEY,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves network metrics.
     */
    fun getNetworkMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            NETWORK_METRICS_KEY
        )
    }

    /**
     * Removes network metrics.
     */
    fun removeNetworkMetrics(): Boolean {

        return cacheManager.remove(
            NETWORK_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // VPN Metrics
    // -------------------------------------------------------------------------

    /**
     * Cache key for VPN security metrics.
     */
    private const val VPN_METRICS_KEY =
        "analytics:security_metrics:vpn"

    /**
     * Stores VPN-related metrics.
     */
    fun putVpnMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = VPN_METRICS_KEY,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves VPN metrics.
     */
    fun getVpnMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            VPN_METRICS_KEY
        )
    }

    /**
     * Removes VPN metrics.
     */
    fun removeVpnMetrics(): Boolean {

        return cacheManager.remove(
            VPN_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Risk Metrics
    // -------------------------------------------------------------------------

    /**
     * Cache key for risk metrics.
     */
    private const val RISK_METRICS_KEY =
        "analytics:security_metrics:risk"

    /**
     * Stores risk-related metrics.
     *
     * Risk calculation is performed by Domain services.
     */
    fun putRiskMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = RISK_METRICS_KEY,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached risk metrics.
     */
    fun getRiskMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            RISK_METRICS_KEY
        )
    }

    /**
     * Removes cached risk metrics.
     */
    fun removeRiskMetrics(): Boolean {

        return cacheManager.remove(
            RISK_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Dashboard Metrics
    // -------------------------------------------------------------------------

    /**
     * Dashboard metric cache.
     *
     * Dashboard metrics are normally assembled from several
     * backend/local sources, therefore keeping the assembled
     * result temporarily can reduce repeated work.
     */
    private const val DASHBOARD_METRICS_KEY =
        "analytics:security_metrics:dashboard"

    /**
     * Stores dashboard metrics.
     */
    fun putDashboardMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = DASHBOARD_METRICS_KEY,
            value = metrics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached dashboard metrics.
     */
    fun getDashboardMetrics():
        SecurityMetrics? {

        return cacheManager.get(
            DASHBOARD_METRICS_KEY
        )
    }

    /**
     * Removes dashboard metrics.
     */
    fun removeDashboardMetrics(): Boolean {

        return cacheManager.remove(
            DASHBOARD_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Metric Refresh
    // -------------------------------------------------------------------------

    /**
     * Refreshes all important current metric caches using
     * the same SecurityMetrics object.
     *
     * This is useful when a repository has already received a
     * complete metric snapshot from the backend.
     */
    fun refreshCurrentMetrics(
        metrics: SecurityMetrics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        putMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )

        putThreatMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )

        putScanMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )

        putPrivacyMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )

        putNetworkMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )

        putVpnMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )

        putRiskMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )

        putDashboardMetrics(
            metrics = metrics,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates the complete security-metrics cache.
     *
     * This does not clear:
     *
     * - Threat cache.
     * - Privacy cache.
     * - Scanner cache.
     * - VPN cache.
     *
     * Only analytics/security-metrics entries are removed.
     */
    suspend fun invalidateAll() {

        cacheManager.invalidatePrefix(
            "analytics:security_metrics:"
        )
    }

    /**
     * Invalidates the current overall metrics.
     */
    suspend fun invalidateCurrentMetrics() {

        cacheManager.remove(
            CacheKeys.SECURITY_METRICS
        )

        cacheManager.remove(
            DASHBOARD_METRICS_KEY
        )
    }

    /**
     * Invalidates application-specific metric caches.
     */
    suspend fun invalidateApplicationMetrics() {

        cacheManager.invalidatePrefix(
            "analytics:security_metrics:app:"
        )
    }

    /**
     * Invalidates time-range metric caches.
     */
    suspend fun invalidateTimeRangeMetrics() {

        cacheManager.invalidatePrefix(
            "analytics:security_metrics:range:"
        )
    }

    /**
     * Invalidates threat-related metrics.
     */
    suspend fun invalidateThreatMetrics() {

        cacheManager.remove(
            THREAT_METRICS_KEY
        )
    }

    /**
     * Invalidates scanner metrics.
     */
    suspend fun invalidateScanMetrics() {

        cacheManager.remove(
            SCAN_METRICS_KEY
        )
    }

    /**
     * Invalidates privacy metrics.
     */
    suspend fun invalidatePrivacyMetrics() {

        cacheManager.remove(
            PRIVACY_METRICS_KEY
        )
    }

    /**
     * Invalidates network metrics.
     */
    suspend fun invalidateNetworkMetrics() {

        cacheManager.remove(
            NETWORK_METRICS_KEY
        )
    }

    /**
     * Invalidates VPN metrics.
     */
    suspend fun invalidateVpnMetrics() {

        cacheManager.remove(
            VPN_METRICS_KEY
        )
    }

    /**
     * Invalidates risk metrics.
     */
    suspend fun invalidateRiskMetrics() {

        cacheManager.remove(
            RISK_METRICS_KEY
        )
    }

    /**
     * Invalidates dashboard metrics.
     */
    suspend fun invalidateDashboardMetrics() {

        cacheManager.remove(
            DASHBOARD_METRICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Cache Maintenance
    // -------------------------------------------------------------------------

    /**
     * Removes expired metric entries.
     *
     * CacheManager performs the actual expiration handling.
     */
    suspend fun removeExpiredEntries(): Int {

        return cacheManager.removeExpiredEntries()
    }

    /**
     * Returns cache statistics.
     */
    fun getStatistics():
        CacheStatistics {

        return cacheManager.getStatistics()
    }
}
