package com.sentrix.data.cache

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Cache Manager
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Central manager for application-level in-memory caching.
 *
 * The CacheManager provides a single abstraction for:
 *
 * - Storing cached values.
 * - Retrieving cached values.
 * - Checking cache availability.
 * - Cache expiration.
 * - Removing individual entries.
 * - Removing entries by prefix.
 * - Clearing the complete cache.
 * - Updating existing cache entries.
 * - Tracking cache statistics.
 *
 * This class is intentionally generic so that it can be used
 * by different SentriX data repositories.
 *
 * Examples:
 *
 * - ThreatRepositoryImpl
 * - ThreatIntelRepositoryImpl
 * - MalwareRepositoryImpl
 * - PrivacyRepositoryImpl
 * - PrivacyScoreRepositoryImpl
 * - SecurityMetricsRepositoryImpl
 * - VPNRepositoryImpl
 *
 * Clean Architecture:
 *
 * Repository
 *      │
 *      ▼
 * CacheManager
 *      │
 *      ▼
 * In-Memory Cache
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class is a DATA-layer component.
 *
 * It must NOT:
 *
 * - Calculate security scores.
 * - Determine threat severity.
 * - Make blocking decisions.
 * - Perform business validation.
 * - Access UI components.
 * - Contain domain-specific security rules.
 *
 * CacheManager only manages cached data.
 *
 * Thread Safety:
 * ------------------------------------------------------------
 * ConcurrentHashMap provides thread-safe basic operations.
 *
 * Mutex is additionally used for operations that modify
 * multiple cache entries atomically.
 */
@Singleton
class CacheManager @Inject constructor() {

    /**
     * Internal cache storage.
     *
     * Every entry contains:
     *
     * - The cached value.
     * - Creation timestamp.
     * - Expiration timestamp.
     */
    private val cache =
        ConcurrentHashMap<String, CacheEntry>()

    /**
     * Mutex used for compound cache operations.
     */
    private val cacheMutex =
        Mutex()

    /**
     * Cache statistics.
     */
    @Volatile
    private var hitCount: Long = 0L

    @Volatile
    private var missCount: Long = 0L

    @Volatile
    private var evictionCount: Long = 0L

    /**
     * Stores a value in the cache.
     *
     * @param key Unique cache key.
     * @param value Value to cache.
     * @param ttlMillis Time-to-live in milliseconds.
     *
     * Example:
     *
     * cacheManager.put(
     *     key = CacheKeys.THREAT_LIST,
     *     value = threats,
     *     ttlMillis = 60_000L
     * )
     */
    fun <T : Any> put(
        key: String,
        value: T,
        ttlMillis: Long = DEFAULT_TTL_MILLIS
    ) {

        require(key.isNotBlank()) {
            "Cache key cannot be blank."
        }

        require(ttlMillis > 0L) {
            "Cache TTL must be greater than zero."
        }

        val now =
            System.currentTimeMillis()

        val expiresAt =
            calculateExpirationTime(
                now,
                ttlMillis
            )

        cache[key] =
            CacheEntry(
                value = value,
                createdAt = now,
                expiresAt = expiresAt
            )
    }

    /**
     * Retrieves a cached value.
     *
     * Returns null when:
     *
     * - Key does not exist.
     * - Entry has expired.
     * - Cached value type does not match T.
     *
     * Expired entries are automatically removed.
     */
    @Suppress("UNCHECKED_CAST")
    fun <T : Any> get(
        key: String
    ): T? {

        if (key.isBlank()) {
            return null
        }

        val entry =
            cache[key]
                ?: run {
                    missCount++
                    return null
                }

        if (entry.isExpired()) {

            cache.remove(
                key,
                entry
            )

            evictionCount++
            missCount++

            return null
        }

        hitCount++

        return entry.value as? T
    }

    /**
     * Retrieves a cached value or creates it when missing.
     *
     * This is useful for repositories that want a simple
     * cache-aside pattern.
     *
     * Example:
     *
     * val threats =
     *     cacheManager.getOrPut(
     *         key = "threats",
     *         ttlMillis = 60_000L
     *     ) {
     *         api.getThreats()
     *     }
     */
    suspend fun <T : Any> getOrPut(
        key: String,
        ttlMillis: Long = DEFAULT_TTL_MILLIS,
        loader: suspend () -> T
    ): T {

        require(key.isNotBlank()) {
            "Cache key cannot be blank."
        }

        get<T>(key)?.let {
            return it
        }

        return cacheMutex.withLock {

            /**
             * Double-check after acquiring the lock.
             *
             * Another coroutine may have populated the cache
             * while this coroutine was waiting.
             */
            get<T>(key)?.let {
                return@withLock it
            }

            val value =
                loader()

            put(
                key = key,
                value = value,
                ttlMillis = ttlMillis
            )

            value
        }
    }

    /**
     * Checks whether a valid cache entry exists.
     *
     * Expired entries are treated as missing.
     */
    fun contains(
        key: String
    ): Boolean {

        if (key.isBlank()) {
            return false
        }

        val entry =
            cache[key]
                ?: return false

        if (entry.isExpired()) {

            cache.remove(
                key,
                entry
            )

            evictionCount++

            return false
        }

        return true
    }

    /**
     * Returns the remaining cache lifetime.
     *
     * Returns:
     *
     * - Remaining milliseconds when valid.
     * - 0 when expired.
     * - null when the key does not exist.
     */
    fun getRemainingTtl(
        key: String
    ): Long? {

        if (key.isBlank()) {
            return null
        }

        val entry =
            cache[key]
                ?: return null

        val remaining =
            entry.expiresAt -
                System.currentTimeMillis()

        if (remaining <= 0L) {

            cache.remove(
                key,
                entry
            )

            evictionCount++

            return 0L
        }

        return remaining
    }

    /**
     * Removes a specific cache entry.
     *
     * @return true if an entry was removed.
     */
    fun remove(
        key: String
    ): Boolean {

        if (key.isBlank()) {
            return false
        }

        return cache.remove(key) != null
    }

    /**
     * Removes all entries whose keys begin with the
     * supplied prefix.
     *
     * Useful when invalidating a complete feature cache.
     *
     * Example:
     *
     * invalidatePrefix("privacy:")
     */
    suspend fun invalidatePrefix(
        prefix: String
    ): Int {

        if (prefix.isBlank()) {
            return 0
        }

        return cacheMutex.withLock {

            val keysToRemove =
                cache.keys
                    .filter {
                        it.startsWith(prefix)
                    }

            keysToRemove.forEach {
                cache.remove(it)
            }

            keysToRemove.size
        }
    }

    /**
     * Removes expired entries.
     *
     * Useful for periodic cache maintenance.
     *
     * @return Number of entries removed.
     */
    suspend fun removeExpiredEntries(): Int {

        return cacheMutex.withLock {

            val expiredKeys =
                cache.entries
                    .filter {
                        it.value.isExpired()
                    }
                    .map {
                        it.key
                    }

            expiredKeys.forEach {
                cache.remove(it)
            }

            evictionCount +=
                expiredKeys.size.toLong()

            expiredKeys.size
        }
    }

    /**
     * Clears the entire cache.
     */
    suspend fun clear() {

        cacheMutex.withLock {

            evictionCount +=
                cache.size.toLong()

            cache.clear()
        }
    }

    /**
     * Clears the cache without locking.
     *
     * This method should only be used when the caller already
     * controls synchronization.
     *
     * Normally prefer clear().
     */
    fun clearImmediately() {

        evictionCount +=
            cache.size.toLong()

        cache.clear()
    }

    /**
     * Returns the number of currently stored entries.
     *
     * Expired entries are not counted.
     */
    fun size(): Int {

        return cache.entries.count {
            !it.value.isExpired()
        }
    }

    /**
     * Returns all currently active cache keys.
     */
    fun getActiveKeys(): Set<String> {

        return cache.entries
            .filter {
                !it.value.isExpired()
            }
            .map {
                it.key
            }
            .toSet()
    }

    /**
     * Returns all cache keys.
     *
     * This method also removes expired entries first.
     */
    suspend fun getKeys(): Set<String> {

        removeExpiredEntries()

        return cache.keys.toSet()
    }

    /**
     * Replaces an existing cache value.
     *
     * Returns false when the key does not currently exist.
     */
    fun <T : Any> replace(
        key: String,
        value: T,
        ttlMillis: Long = DEFAULT_TTL_MILLIS
    ): Boolean {

        if (!contains(key)) {
            return false
        }

        put(
            key = key,
            value = value,
            ttlMillis = ttlMillis
        )

        return true
    }

    /**
     * Removes an existing value and inserts a new value.
     *
     * Useful when repositories explicitly want to refresh
     * an entry.
     */
    fun <T : Any> refresh(
        key: String,
        value: T,
        ttlMillis: Long = DEFAULT_TTL_MILLIS
    ) {

        remove(key)

        put(
            key = key,
            value = value,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Returns cache statistics.
     */
    fun getStatistics():
        CacheStatistics {

        return CacheStatistics(
            size = size(),
            hitCount = hitCount,
            missCount = missCount,
            evictionCount = evictionCount
        )
    }

    /**
     * Resets cache statistics.
     *
     * This does not remove cached data.
     */
    fun resetStatistics() {

        hitCount = 0L
        missCount = 0L
        evictionCount = 0L
    }

    /**
     * Calculates cache expiration time.
     *
     * Protects against Long overflow.
     */
    private fun calculateExpirationTime(
        currentTime: Long,
        ttlMillis: Long
    ): Long {

        if (
            Long.MAX_VALUE - currentTime <
            ttlMillis
        ) {
            return Long.MAX_VALUE
        }

        return currentTime + ttlMillis
    }

    /**
     * Internal cache entry.
     */
    private data class CacheEntry(
        val value: Any,
        val createdAt: Long,
        val expiresAt: Long
    ) {

        /**
         * Determines whether this entry has expired.
         */
        fun isExpired(): Boolean {

            return System.currentTimeMillis() >=
                expiresAt
        }
    }

    companion object {

        /**
         * Default cache lifetime.
         *
         * Five minutes.
         */
        const val DEFAULT_TTL_MILLIS =
            5 * 60 * 1000L

        /**
         * Short-lived cache.
         *
         * Useful for rapidly changing security information.
         */
        const val SHORT_TTL_MILLIS =
            30 * 1000L

        /**
         * Medium-lived cache.
         */
        const val MEDIUM_TTL_MILLIS =
            5 * 60 * 1000L

        /**
         * Long-lived cache.
         *
         * Useful for relatively stable reference data.
         */
        const val LONG_TTL_MILLIS =
            60 * 60 * 1000L
    }
}

/**
 * Cache statistics exposed by CacheManager.
 *
 * Useful for:
 *
 * - Debugging.
 * - Performance monitoring.
 * - Analytics.
 * - Development diagnostics.
 */
data class CacheStatistics(
    val size: Int,
    val hitCount: Long,
    val missCount: Long,
    val evictionCount: Long
) {

    /**
     * Calculates cache hit ratio.
     */
    val hitRatio: Double
        get() {

            val totalRequests =
                hitCount + missCount

            if (totalRequests == 0L) {
                return 0.0
            }

            return hitCount.toDouble() /
                totalRequests.toDouble()
        }
}
