package com.sentrix.data.cache

import com.sentrix.domain.models.ThreatHistory
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Threat History Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Feature-specific cache for historical threat information.
 *
 * ThreatHistoryCache is built on top of CacheManager and
 * provides strongly typed cache operations for the
 * Threat History subsystem.
 *
 * Cached information can include:
 *
 * - Complete threat history.
 * - Recent threat history.
 * - History for a specific threat.
 * - History for a specific application.
 * - History by severity.
 * - History by event type.
 * - History within a time range.
 * - Threat history trend snapshots.
 * - Historical threat counts.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class does NOT:
 *
 * - Analyze threats.
 * - Calculate threat severity.
 * - Predict future threats.
 * - Decide whether a threat is malicious.
 * - Modify threat intelligence.
 * - Perform network requests.
 * - Apply security policies.
 *
 * It only manages cached historical data.
 *
 * Clean Architecture:
 *
 * ThreatHistoryRepositoryImpl
 *          │
 *          ▼
 *   ThreatHistoryCache
 *          │
 *          ▼
 *     CacheManager
 *          │
 *          ▼
 *    In-Memory Cache
 */
@Singleton
class ThreatHistoryCache @Inject constructor(
    private val cacheManager: CacheManager
) {

    // -------------------------------------------------------------------------
    // Cache Prefix
    // -------------------------------------------------------------------------

    /**
     * Root namespace for all threat-history cache entries.
     *
     * Keeping a dedicated namespace makes it possible to
     * invalidate the entire threat-history cache without
     * affecting other SentriX caches.
     */
    private companion object {

        const val PREFIX =
            "threat_history:"

        const val ALL_HISTORY_KEY =
            "${PREFIX}all"

        const val RECENT_HISTORY_KEY =
            "${PREFIX}recent"

        const val TREND_KEY =
            "${PREFIX}trend"

        const val STATISTICS_KEY =
            "${PREFIX}statistics"

        const val SEVERITY_PREFIX =
            "${PREFIX}severity:"

        const val EVENT_TYPE_PREFIX =
            "${PREFIX}event:"

        const val THREAT_PREFIX =
            "${PREFIX}threat:"

        const val PACKAGE_PREFIX =
            "${PREFIX}package:"

        const val RANGE_PREFIX =
            "${PREFIX}range:"

        /**
         * Historical information generally changes less
         * frequently than live threat data.
         */
        const val DEFAULT_HISTORY_TTL =
            CacheManager.MEDIUM_TTL_MILLIS
    }

    // -------------------------------------------------------------------------
    // Complete Threat History
    // -------------------------------------------------------------------------

    /**
     * Stores the complete cached threat history.
     *
     * This should normally be used for relatively small
     * history datasets.
     */
    fun putAllHistory(
        history: List<ThreatHistory>,
        ttlMillis: Long = DEFAULT_HISTORY_TTL
    ) {

        cacheManager.put(
            key = ALL_HISTORY_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the complete cached threat history.
     */
    fun getAllHistory():
        List<ThreatHistory>? {

        return cacheManager.get(
            ALL_HISTORY_KEY
        )
    }

    /**
     * Checks whether complete threat history exists.
     */
    fun containsAllHistory(): Boolean {

        return cacheManager.contains(
            ALL_HISTORY_KEY
        )
    }

    /**
     * Removes the complete threat history cache.
     */
    fun removeAllHistory(): Boolean {

        return cacheManager.remove(
            ALL_HISTORY_KEY
        )
    }

    /**
     * Refreshes the complete threat history cache.
     */
    fun refreshAllHistory(
        history: List<ThreatHistory>,
        ttlMillis: Long = DEFAULT_HISTORY_TTL
    ) {

        cacheManager.refresh(
            key = ALL_HISTORY_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads complete threat history using cache-aside
     * behavior.
     */
    suspend fun getAllHistoryOrLoad(
        ttlMillis: Long = DEFAULT_HISTORY_TTL,
        loader: suspend () -> List<ThreatHistory>
    ): List<ThreatHistory> {

        return cacheManager.getOrPut(
            key = ALL_HISTORY_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Recent Threat History
    // -------------------------------------------------------------------------

    /**
     * Stores recent threat history.
     *
     * Recent history gets a shorter TTL because new security
     * events can be added frequently.
     */
    fun putRecentHistory(
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = RECENT_HISTORY_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves recent threat history.
     */
    fun getRecentHistory():
        List<ThreatHistory>? {

        return cacheManager.get(
            RECENT_HISTORY_KEY
        )
    }

    /**
     * Checks whether recent threat history is cached.
     */
    fun containsRecentHistory(): Boolean {

        return cacheManager.contains(
            RECENT_HISTORY_KEY
        )
    }

    /**
     * Removes recent threat history.
     */
    fun removeRecentHistory(): Boolean {

        return cacheManager.remove(
            RECENT_HISTORY_KEY
        )
    }

    /**
     * Refreshes recent threat history.
     */
    fun refreshRecentHistory(
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.refresh(
            key = RECENT_HISTORY_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads recent history using cache-aside behavior.
     */
    suspend fun getRecentHistoryOrLoad(
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS,
        loader: suspend () -> List<ThreatHistory>
    ): List<ThreatHistory> {

        return cacheManager.getOrPut(
            key = RECENT_HISTORY_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Threat-Specific History
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for a specific threat.
     */
    private fun threatHistoryKey(
        threatId: String
    ): String {

        return THREAT_PREFIX +
            threatId.trim()
    }

    /**
     * Stores history for one threat.
     */
    fun putThreatHistory(
        threatId: String,
        history: List<ThreatHistory>,
        ttlMillis: Long = DEFAULT_HISTORY_TTL
    ) {

        if (threatId.isBlank()) {
            return
        }

        cacheManager.put(
            key = threatHistoryKey(
                threatId
            ),
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves history for one threat.
     */
    fun getThreatHistory(
        threatId: String
    ): List<ThreatHistory>? {

        if (threatId.isBlank()) {
            return null
        }

        return cacheManager.get(
            threatHistoryKey(
                threatId
            )
        )
    }

    /**
     * Checks whether a threat's history is cached.
     */
    fun containsThreatHistory(
        threatId: String
    ): Boolean {

        if (threatId.isBlank()) {
            return false
        }

        return cacheManager.contains(
            threatHistoryKey(
                threatId
            )
        )
    }

    /**
     * Removes history for one threat.
     */
    fun removeThreatHistory(
        threatId: String
    ): Boolean {

        if (threatId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            threatHistoryKey(
                threatId
            )
        )
    }

    /**
     * Refreshes history for one threat.
     */
    fun refreshThreatHistory(
        threatId: String,
        history: List<ThreatHistory>,
        ttlMillis: Long = DEFAULT_HISTORY_TTL
    ) {

        if (threatId.isBlank()) {
            return
        }

        cacheManager.refresh(
            key = threatHistoryKey(
                threatId
            ),
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads threat history using cache-aside behavior.
     */
    suspend fun getThreatHistoryOrLoad(
        threatId: String,
        ttlMillis: Long = DEFAULT_HISTORY_TTL,
        loader: suspend () -> List<ThreatHistory>
    ): List<ThreatHistory> {

        require(threatId.isNotBlank()) {
            "Threat ID cannot be blank."
        }

        return cacheManager.getOrPut(
            key = threatHistoryKey(
                threatId
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Application-Specific History
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for application history.
     */
    private fun packageHistoryKey(
        packageName: String
    ): String {

        return PACKAGE_PREFIX +
            packageName.trim().lowercase()
    }

    /**
     * Stores threat history associated with an Android
     * application package.
     */
    fun putPackageHistory(
        packageName: String,
        history: List<ThreatHistory>,
        ttlMillis: Long = DEFAULT_HISTORY_TTL
    ) {

        if (packageName.isBlank()) {
            return
        }

        cacheManager.put(
            key = packageHistoryKey(
                packageName
            ),
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves threat history for an application.
     */
    fun getPackageHistory(
        packageName: String
    ): List<ThreatHistory>? {

        if (packageName.isBlank()) {
            return null
        }

        return cacheManager.get(
            packageHistoryKey(
                packageName
            )
        )
    }

    /**
     * Checks whether application history is cached.
     */
    fun containsPackageHistory(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.contains(
            packageHistoryKey(
                packageName
            )
        )
    }

    /**
     * Removes application-specific history.
     */
    fun removePackageHistory(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.remove(
            packageHistoryKey(
                packageName
            )
        )
    }

    /**
     * Loads application history using cache-aside behavior.
     */
    suspend fun getPackageHistoryOrLoad(
        packageName: String,
        ttlMillis: Long = DEFAULT_HISTORY_TTL,
        loader: suspend () -> List<ThreatHistory>
    ): List<ThreatHistory> {

        require(packageName.isNotBlank()) {
            "Application package name cannot be blank."
        }

        return cacheManager.getOrPut(
            key = packageHistoryKey(
                packageName
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Severity History
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for severity-filtered history.
     *
     * Examples:
     *
     * - CRITICAL
     * - HIGH
     * - MEDIUM
     * - LOW
     */
    private fun severityHistoryKey(
        severity: String
    ): String {

        return SEVERITY_PREFIX +
            severity.trim().uppercase()
    }

    /**
     * Stores history filtered by severity.
     */
    fun putSeverityHistory(
        severity: String,
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        if (severity.isBlank()) {
            return
        }

        cacheManager.put(
            key = severityHistoryKey(
                severity
            ),
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves history filtered by severity.
     */
    fun getSeverityHistory(
        severity: String
    ): List<ThreatHistory>? {

        if (severity.isBlank()) {
            return null
        }

        return cacheManager.get(
            severityHistoryKey(
                severity
            )
        )
    }

    /**
     * Removes a severity-filtered history cache.
     */
    fun removeSeverityHistory(
        severity: String
    ): Boolean {

        if (severity.isBlank()) {
            return false
        }

        return cacheManager.remove(
            severityHistoryKey(
                severity
            )
        )
    }

    // -------------------------------------------------------------------------
    // Event-Type History
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for event-type history.
     */
    private fun eventTypeHistoryKey(
        eventType: String
    ): String {

        return EVENT_TYPE_PREFIX +
            eventType.trim().uppercase()
    }

    /**
     * Stores history filtered by event type.
     */
    fun putEventTypeHistory(
        eventType: String,
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        if (eventType.isBlank()) {
            return
        }

        cacheManager.put(
            key = eventTypeHistoryKey(
                eventType
            ),
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves history filtered by event type.
     */
    fun getEventTypeHistory(
        eventType: String
    ): List<ThreatHistory>? {

        if (eventType.isBlank()) {
            return null
        }

        return cacheManager.get(
            eventTypeHistoryKey(
                eventType
            )
        )
    }

    /**
     * Removes event-type history cache.
     */
    fun removeEventTypeHistory(
        eventType: String
    ): Boolean {

        if (eventType.isBlank()) {
            return false
        }

        return cacheManager.remove(
            eventTypeHistoryKey(
                eventType
            )
        )
    }

    // -------------------------------------------------------------------------
    // Time-Range History
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for a time range.
     */
    private fun rangeHistoryKey(
        startTime: Long,
        endTime: Long
    ): String {

        return RANGE_PREFIX +
            "$startTime:$endTime"
    }

    /**
     * Stores threat history for a specific time range.
     */
    fun putRangeHistory(
        startTime: Long,
        endTime: Long,
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        if (startTime > endTime) {
            return
        }

        cacheManager.put(
            key = rangeHistoryKey(
                startTime,
                endTime
            ),
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves history for a specific time range.
     */
    fun getRangeHistory(
        startTime: Long,
        endTime: Long
    ): List<ThreatHistory>? {

        if (startTime > endTime) {
            return null
        }

        return cacheManager.get(
            rangeHistoryKey(
                startTime,
                endTime
            )
        )
    }

    /**
     * Removes history for a specific time range.
     */
    fun removeRangeHistory(
        startTime: Long,
        endTime: Long
    ): Boolean {

        if (startTime > endTime) {
            return false
        }

        return cacheManager.remove(
            rangeHistoryKey(
                startTime,
                endTime
            )
        )
    }

    /**
     * Loads range-based history using cache-aside behavior.
     */
    suspend fun getRangeHistoryOrLoad(
        startTime: Long,
        endTime: Long,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS,
        loader: suspend () -> List<ThreatHistory>
    ): List<ThreatHistory> {

        require(startTime <= endTime) {
            "Start time cannot be after end time."
        }

        return cacheManager.getOrPut(
            key = rangeHistoryKey(
                startTime,
                endTime
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Trend Snapshots
    // -------------------------------------------------------------------------

    /**
     * Stores a trend snapshot.
     *
     * The snapshot can contain precomputed historical trend
     * data represented by the ThreatHistory domain model.
     */
    fun putTrend(
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        cacheManager.put(
            key = TREND_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the cached threat trend.
     */
    fun getTrend():
        List<ThreatHistory>? {

        return cacheManager.get(
            TREND_KEY
        )
    }

    /**
     * Removes cached threat trend data.
     */
    fun removeTrend(): Boolean {

        return cacheManager.remove(
            TREND_KEY
        )
    }

    /**
     * Refreshes the cached threat trend.
     */
    fun refreshTrend(
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        cacheManager.refresh(
            key = TREND_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Historical Statistics
    // -------------------------------------------------------------------------

    /**
     * Stores historical statistics.
     *
     * The type is generic because the exact statistics model
     * may evolve independently from ThreatHistory.
     */
    fun <T : Any> putStatistics(
        statistics: T,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        cacheManager.put(
            key = STATISTICS_KEY,
            value = statistics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached historical statistics.
     */
    inline fun <reified T : Any> getStatistics():
        T? {

        return cacheManager.get(
            STATISTICS_KEY
        )
    }

    /**
     * Removes historical statistics.
     */
    fun removeStatistics(): Boolean {

        return cacheManager.remove(
            STATISTICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Cache Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates all threat-history cache entries.
     *
     * This is the primary invalidation method to use when
     * history has changed significantly.
     */
    suspend fun invalidateAll() {

        cacheManager.invalidatePrefix(
            PREFIX
        )
    }

    /**
     * Invalidates the general history cache.
     */
    suspend fun invalidateGeneralHistory() {

        cacheManager.remove(
            ALL_HISTORY_KEY
        )

        cacheManager.remove(
            RECENT_HISTORY_KEY
        )

        cacheManager.remove(
            TREND_KEY
        )

        cacheManager.remove(
            STATISTICS_KEY
        )
    }

    /**
     * Invalidates all threat-specific history.
     */
    suspend fun invalidateThreatHistories() {

        cacheManager.invalidatePrefix(
            THREAT_PREFIX
        )
    }

    /**
     * Invalidates all application-specific history.
     */
    suspend fun invalidatePackageHistories() {

        cacheManager.invalidatePrefix(
            PACKAGE_PREFIX
        )
    }

    /**
     * Invalidates all severity-filtered history.
     */
    suspend fun invalidateSeverityHistories() {

        cacheManager.invalidatePrefix(
            SEVERITY_PREFIX
        )
    }

    /**
     * Invalidates all event-type history.
     */
    suspend fun invalidateEventTypeHistories() {

        cacheManager.invalidatePrefix(
            EVENT_TYPE_PREFIX
        )
    }

    /**
     * Invalidates all time-range history.
     */
    suspend fun invalidateRangeHistories() {

        cacheManager.invalidatePrefix(
            RANGE_PREFIX
        )
    }

    /**
     * Invalidates all caches associated with a particular
     * threat.
     *
     * This is useful when a threat's historical state changes.
     */
    suspend fun invalidateForThreat(
        threatId: String
    ) {

        if (threatId.isBlank()) {
            return
        }

        cacheManager.remove(
            threatHistoryKey(
                threatId
            )
        )

        /**
         * General history and trend data may now be stale.
         */
        cacheManager.remove(
            ALL_HISTORY_KEY
        )

        cacheManager.remove(
            RECENT_HISTORY_KEY
        )

        cacheManager.remove(
            TREND_KEY
        )

        cacheManager.remove(
            STATISTICS_KEY
        )
    }

    /**
     * Invalidates all caches associated with an application.
     */
    suspend fun invalidateForPackage(
        packageName: String
    ) {

        if (packageName.isBlank()) {
            return
        }

        cacheManager.remove(
            packageHistoryKey(
                packageName
            )
        )

        /**
         * Application history changed, so aggregate history
         * can also be stale.
         */
        cacheManager.remove(
            ALL_HISTORY_KEY
        )

        cacheManager.remove(
            RECENT_HISTORY_KEY
        )

        cacheManager.remove(
            TREND_KEY
        )

        cacheManager.remove(
            STATISTICS_KEY
        )
    }

    /**
     * Removes expired threat-history entries.
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
