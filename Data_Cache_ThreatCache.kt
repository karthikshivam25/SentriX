package com.sentrix.data.cache

import com.sentrix.domain.models.Threat
import com.sentrix.domain.models.ThreatHistory
import com.sentrix.domain.models.ThreatPrediction
import com.sentrix.domain.models.ThreatIntel
import com.sentrix.domain.models.Malware
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Threat Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Feature-specific cache for the SentriX Threat Intelligence
 * subsystem.
 *
 * ThreatCache provides a strongly typed caching layer for:
 *
 * - Threat details.
 * - Threat lists.
 * - Threat history.
 * - Threat predictions.
 * - Threat intelligence.
 * - Malware information.
 * - Threat search results.
 * - Threat statistics.
 * - Recently detected threats.
 *
 * This class is intentionally built on top of CacheManager.
 *
 * CacheManager
 *      │
 *      ▼
 * ThreatCache
 *      │
 *      ├── ThreatRepositoryImpl
 *      ├── ThreatHistoryRepositoryImpl
 *      ├── ThreatPredictionRepositoryImpl
 *      ├── ThreatIntelRepositoryImpl
 *      └── MalwareRepositoryImpl
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * ThreatCache does NOT:
 *
 * - Analyze threats.
 * - Calculate threat severity.
 * - Predict threats.
 * - Determine whether malware is malicious.
 * - Make security decisions.
 * - Perform network requests.
 *
 * All security intelligence decisions remain in the Domain
 * layer.
 *
 * ThreatCache only manages cached threat DATA.
 *
 * Clean Architecture:
 *
 * Data Repository
 *       │
 *       ▼
 *   ThreatCache
 *       │
 *       ▼
 *  CacheManager
 *       │
 *       ▼
 * In-Memory Cache
 */
@Singleton
class ThreatCache @Inject constructor(
    private val cacheManager: CacheManager
) {

    // -------------------------------------------------------------------------
    // Threats
    // -------------------------------------------------------------------------

    /**
     * Stores a single threat.
     *
     * Individual threat records use a medium TTL because
     * threat metadata may change but normally does not need
     * second-by-second refreshing.
     */
    fun putThreat(
        threat: Threat,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        cacheManager.put(
            key = CacheKeys.threat(
                threat.threatId
            ),
            value = threat,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves a cached threat.
     */
    fun getThreat(
        threatId: String
    ): Threat? {

        if (threatId.isBlank()) {
            return null
        }

        return cacheManager.get(
            CacheKeys.threat(
                threatId
            )
        )
    }

    /**
     * Checks whether a threat exists in cache.
     */
    fun containsThreat(
        threatId: String
    ): Boolean {

        if (threatId.isBlank()) {
            return false
        }

        return cacheManager.contains(
            CacheKeys.threat(
                threatId
            )
        )
    }

    /**
     * Removes one threat from cache.
     */
    fun removeThreat(
        threatId: String
    ): Boolean {

        if (threatId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            CacheKeys.threat(
                threatId
            )
        )
    }

    /**
     * Stores a list of threats.
     *
     * The list receives a shorter TTL than individual threat
     * records because collection results can become stale faster.
     */
    fun putThreatList(
        threats: List<Threat>,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = CacheKeys.THREAT_LIST,
            value = threats,
            ttlMillis = ttlMillis
        )

        /**
         * Also populate individual threat entries.
         *
         * This allows:
         *
         * getThreat(id)
         *
         * to work even after the list has been retrieved.
         */
        threats.forEach { threat ->

            putThreat(
                threat = threat
            )
        }
    }

    /**
     * Retrieves cached threat list.
     */
    fun getThreatList():
        List<Threat>? {

        return cacheManager.get(
            CacheKeys.THREAT_LIST
        )
    }

    /**
     * Removes the cached threat list.
     */
    fun removeThreatList(): Boolean {

        return cacheManager.remove(
            CacheKeys.THREAT_LIST
        )
    }

    /**
     * Replaces the complete threat list.
     */
    fun refreshThreatList(
        threats: List<Threat>,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.refresh(
            key = CacheKeys.THREAT_LIST,
            value = threats,
            ttlMillis = ttlMillis
        )

        threats.forEach { threat ->

            putThreat(
                threat = threat
            )
        }
    }

    /**
     * Retrieves threats from cache or loads them through the
     * supplied loader.
     *
     * This supports the cache-aside pattern.
     */
    suspend fun getThreatListOrLoad(
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS,
        loader: suspend () -> List<Threat>
    ): List<Threat> {

        return cacheManager.getOrPut(
            key = CacheKeys.THREAT_LIST,
            ttlMillis = ttlMillis
        ) {

            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Threat History
    // -------------------------------------------------------------------------

    /**
     * Stores threat history.
     *
     * History is generally more stable than live threat data,
     * therefore it can use a medium TTL.
     */
    fun putThreatHistory(
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        cacheManager.put(
            key = CacheKeys.THREAT_HISTORY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached threat history.
     */
    fun getThreatHistory():
        List<ThreatHistory>? {

        return cacheManager.get(
            CacheKeys.THREAT_HISTORY
        )
    }

    /**
     * Removes cached threat history.
     */
    fun removeThreatHistory(): Boolean {

        return cacheManager.remove(
            CacheKeys.THREAT_HISTORY
        )
    }

    /**
     * Refreshes threat history cache.
     */
    fun refreshThreatHistory(
        history: List<ThreatHistory>,
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS
    ) {

        cacheManager.refresh(
            key = CacheKeys.THREAT_HISTORY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads threat history using cache-aside behavior.
     */
    suspend fun getThreatHistoryOrLoad(
        ttlMillis: Long = CacheManager.MEDIUM_TTL_MILLIS,
        loader: suspend () -> List<ThreatHistory>
    ): List<ThreatHistory> {

        return cacheManager.getOrPut(
            key = CacheKeys.THREAT_HISTORY,
            ttlMillis = ttlMillis
        ) {

            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Threat Prediction
    // -------------------------------------------------------------------------

    /**
     * Generates a unique cache key for threat predictions.
     *
     * Predictions can be device-wide or application-specific.
     */
    private fun predictionKey(
        packageName: String?
    ): String {

        return if (
            packageName.isNullOrBlank()
        ) {
            "threat:prediction:global"
        } else {
            "threat:prediction:$packageName"
        }
    }

    /**
     * Stores threat prediction data.
     *
     * Prediction data should normally have a short TTL because
     * predictions can become stale as new telemetry arrives.
     */
    fun putThreatPrediction(
        prediction: ThreatPrediction,
        packageName: String? = null,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = predictionKey(
                packageName
            ),
            value = prediction,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached threat prediction.
     */
    fun getThreatPrediction(
        packageName: String? = null
    ): ThreatPrediction? {

        return cacheManager.get(
            predictionKey(
                packageName
            )
        )
    }

    /**
     * Removes cached threat prediction.
     */
    fun removeThreatPrediction(
        packageName: String? = null
    ): Boolean {

        return cacheManager.remove(
            predictionKey(
                packageName
            )
        )
    }

    // -------------------------------------------------------------------------
    // Threat Intelligence
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for threat intelligence.
     *
     * Indicator types can include:
     *
     * - IP
     * - DOMAIN
     * - URL
     * - HASH
     * - PACKAGE
     */
    private fun intelligenceKey(
        indicator: String,
        indicatorType: String
    ): String {

        return "threat:intel:" +
            "$indicatorType:" +
            indicator.lowercase()
    }

    /**
     * Stores threat intelligence information.
     *
     * Intelligence may be relatively stable, so a longer TTL
     * can be used when appropriate.
     */
    fun putThreatIntel(
        indicator: String,
        indicatorType: String,
        intelligence: ThreatIntel,
        ttlMillis: Long = CacheManager.LONG_TTL_MILLIS
    ) {

        if (
            indicator.isBlank() ||
            indicatorType.isBlank()
        ) {
            return
        }

        cacheManager.put(
            key = intelligenceKey(
                indicator = indicator,
                indicatorType = indicatorType
            ),
            value = intelligence,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached threat intelligence.
     */
    fun getThreatIntel(
        indicator: String,
        indicatorType: String
    ): ThreatIntel? {

        if (
            indicator.isBlank() ||
            indicatorType.isBlank()
        ) {
            return null
        }

        return cacheManager.get(
            intelligenceKey(
                indicator = indicator,
                indicatorType = indicatorType
            )
        )
    }

    /**
     * Removes cached threat intelligence.
     */
    fun removeThreatIntel(
        indicator: String,
        indicatorType: String
    ): Boolean {

        if (
            indicator.isBlank() ||
            indicatorType.isBlank()
        ) {
            return false
        }

        return cacheManager.remove(
            intelligenceKey(
                indicator = indicator,
                indicatorType = indicatorType
            )
        )
    }

    // -------------------------------------------------------------------------
    // Malware
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for malware information.
     */
    private fun malwareKey(
        malwareId: String
    ): String {

        return "threat:malware:$malwareId"
    }

    /**
     * Stores malware information.
     *
     * Malware signatures and metadata are generally more stable
     * than live threat events.
     */
    fun putMalware(
        malware: Malware,
        ttlMillis: Long = CacheManager.LONG_TTL_MILLIS
    ) {

        if (malware.malwareId.isBlank()) {
            return
        }

        cacheManager.put(
            key = malwareKey(
                malware.malwareId
            ),
            value = malware,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached malware information.
     */
    fun getMalware(
        malwareId: String
    ): Malware? {

        if (malwareId.isBlank()) {
            return null
        }

        return cacheManager.get(
            malwareKey(
                malwareId
            )
        )
    }

    /**
     * Checks whether malware information exists in cache.
     */
    fun containsMalware(
        malwareId: String
    ): Boolean {

        if (malwareId.isBlank()) {
            return false
        }

        return cacheManager.contains(
            malwareKey(
                malwareId
            )
        )
    }

    /**
     * Removes cached malware information.
     */
    fun removeMalware(
        malwareId: String
    ): Boolean {

        if (malwareId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            malwareKey(
                malwareId
            )
        )
    }

    // -------------------------------------------------------------------------
    // Threat Search
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for threat search results.
     */
    private fun searchKey(
        query: String
    ): String {

        return "threat:search:" +
            query.trim().lowercase()
    }

    /**
     * Stores threat search results.
     */
    fun putSearchResult(
        query: String,
        results: List<Threat>,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        if (query.isBlank()) {
            return
        }

        cacheManager.put(
            key = searchKey(query),
            value = results,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached threat search results.
     */
    fun getSearchResult(
        query: String
    ): List<Threat>? {

        if (query.isBlank()) {
            return null
        }

        return cacheManager.get(
            searchKey(query)
        )
    }

    /**
     * Removes cached search results for a query.
     */
    fun removeSearchResult(
        query: String
    ): Boolean {

        if (query.isBlank()) {
            return false
        }

        return cacheManager.remove(
            searchKey(query)
        )
    }

    // -------------------------------------------------------------------------
    // Cache Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates the complete threat cache.
     *
     * This removes:
     *
     * - Threats.
     * - Threat history.
     * - Threat predictions.
     * - Threat intelligence.
     * - Malware.
     * - Threat search results.
     *
     * It does not clear caches belonging to other SentriX
     * subsystems.
     */
    suspend fun invalidateAll() {

        cacheManager.invalidatePrefix(
            "threat:"
        )
    }

    /**
     * Invalidates live threat information.
     *
     * Useful after:
     *
     * - Threat database update.
     * - Threat scan completion.
     * - Backend synchronization.
     */
    suspend fun invalidateThreatData() {

        cacheManager.remove(
            CacheKeys.THREAT_LIST
        )

        cacheManager.invalidatePrefix(
            "threat:search:"
        )
    }

    /**
     * Invalidates threat intelligence.
     */
    suspend fun invalidateThreatIntelligence() {

        cacheManager.invalidatePrefix(
            "threat:intel:"
        )
    }

    /**
     * Invalidates malware cache.
     */
    suspend fun invalidateMalware() {

        cacheManager.invalidatePrefix(
            "threat:malware:"
        )
    }

    /**
     * Invalidates prediction cache.
     */
    suspend fun invalidatePredictions() {

        cacheManager.invalidatePrefix(
            "threat:prediction:"
        )
    }

    /**
     * Invalidates history cache.
     */
    suspend fun invalidateHistory() {

        cacheManager.remove(
            CacheKeys.THREAT_HISTORY
        )
    }

    /**
     * Returns cache statistics.
     */
    fun getStatistics():
        CacheStatistics {

        return cacheManager.getStatistics()
    }
}
