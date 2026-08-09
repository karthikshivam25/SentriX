package com.sentrix.data.cache

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - In-Memory Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Low-level, process-local, in-memory cache implementation.
 *
 * MemoryCache stores arbitrary application objects in RAM and
 * provides:
 *
 * - Thread-safe reads.
 * - Thread-safe writes.
 * - TTL-based expiration.
 * - Cache removal.
 * - Prefix-based invalidation.
 * - Expired-entry cleanup.
 * - Cache statistics.
 * - Cache size inspection.
 *
 * Architecture:
 *
 * Feature Cache
 *      │
 *      ▼
 * CacheManager
 *      │
 *      ▼
 * MemoryCache
 *      │
 *      ▼
 * RAM
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * MemoryCache is NOT persistent storage.
 *
 * All entries can disappear when:
 *
 * - The Android process is killed.
 * - The application is force-stopped.
 * - The device reclaims memory.
 * - The cache is explicitly cleared.
 *
 * Therefore:
 *
 * MemoryCache MUST NOT be the source of truth for:
 *
 * - Authentication credentials.
 * - Passwords.
 * - Refresh tokens.
 * - Security-critical persistent records.
 * - Scan history.
 * - Threat history.
 * - Security reports.
 *
 * Persistent data belongs in Room/DataStore/Secure Storage
 * according to the responsibility.
 *
 * Security Principle:
 * ------------------------------------------------------------
 * Cache only derived or reloadable information.
 */
@Singleton
class MemoryCache @Inject constructor() {

    // -------------------------------------------------------------------------
    // Internal Cache Entry
    // -------------------------------------------------------------------------

    /**
     * Represents one cached value.
     *
     * expiresAt:
     * --------------------------------------------------------
     * Absolute expiration timestamp in milliseconds.
     *
     * A value of Long.MAX_VALUE means the entry does not
     * expire automatically.
     */
    private data class CacheEntry(
        val value: Any,
        val createdAt: Long,
        val expiresAt: Long,
        val lastAccessedAt: Long
    )

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /**
     * ConcurrentHashMap provides safe concurrent access for
     * normal read/write operations.
     *
     * The Mutex is used when multiple cache entries need to
     * be inspected or modified as one logical operation.
     */
    private val cache =
        ConcurrentHashMap<String, CacheEntry>()

    /**
     * Protects compound operations such as:
     *
     * - Prefix invalidation.
     * - Expired-entry cleanup.
     * - Statistics calculation.
     */
    private val mutex =
        Mutex()

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    /**
     * Number of successful cache reads.
     */
    @Volatile
    private var hitCount: Long = 0L

    /**
     * Number of cache misses.
     */
    @Volatile
    private var missCount: Long = 0L

    /**
     * Number of values inserted.
     */
    @Volatile
    private var putCount: Long = 0L

    /**
     * Number of values removed.
     */
    @Volatile
    private var removeCount: Long = 0L

    /**
     * Number of expired entries encountered.
     */
    @Volatile
    private var expirationCount: Long = 0L

    // -------------------------------------------------------------------------
    // Put
    // -------------------------------------------------------------------------

    /**
     * Stores a value in memory.
     *
     * @param key unique cache key
     * @param value object to cache
     * @param ttlMillis time-to-live in milliseconds
     *
     * @return true when the value was stored successfully
     */
    fun put(
        key: String,
        value: Any,
        ttlMillis: Long
    ): Boolean {

        if (key.isBlank()) {
            return false
        }

        if (ttlMillis < 0L) {
            return false
        }

        val now =
            System.currentTimeMillis()

        val expiresAt =
            calculateExpiration(
                now = now,
                ttlMillis = ttlMillis
            )

        cache[key] =
            CacheEntry(
                value = value,
                createdAt = now,
                expiresAt = expiresAt,
                lastAccessedAt = now
            )

        putCount++

        return true
    }

    // -------------------------------------------------------------------------
    // Get
    // -------------------------------------------------------------------------

    /**
     * Retrieves a cached value.
     *
     * The value is returned as the requested generic type.
     *
     * Expired entries are automatically removed.
     */
    @Suppress("UNCHECKED_CAST")
    fun <T : Any> get(
        key: String
    ): T? {

        if (key.isBlank()) {
            missCount++
            return null
        }

        val entry =
            cache[key]

        if (entry == null) {
            missCount++
            return null
        }

        val now =
            System.currentTimeMillis()

        if (isExpired(entry, now)) {

            cache.remove(key)

            expirationCount++
            missCount++

            return null
        }

        /**
         * Update the last-access timestamp.
         *
         * This creates a new immutable CacheEntry rather than
         * mutating the existing entry.
         */
        cache[key] =
            entry.copy(
                lastAccessedAt = now
            )

        hitCount++

        return entry.value as? T
    }

    // -------------------------------------------------------------------------
    // Contains
    // -------------------------------------------------------------------------

    /**
     * Checks whether a valid cache entry exists.
     *
     * Expired entries are treated as absent.
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

        val now =
            System.currentTimeMillis()

        if (isExpired(entry, now)) {

            cache.remove(key)

            expirationCount++

            return false
        }

        return true
    }

    // -------------------------------------------------------------------------
    // Remove
    // -------------------------------------------------------------------------

    /**
     * Removes a single cache entry.
     *
     * @return true when an entry was removed.
     */
    fun remove(
        key: String
    ): Boolean {

        if (key.isBlank()) {
            return false
        }

        val removed =
            cache.remove(key)

        if (removed != null) {
            removeCount++
            return true
        }

        return false
    }

    // -------------------------------------------------------------------------
    // Refresh
    // -------------------------------------------------------------------------

    /**
     * Replaces an existing cache value and resets its TTL.
     *
     * If the key does not currently exist, the value is still
     * inserted.
     */
    fun refresh(
        key: String,
        value: Any,
        ttlMillis: Long
    ): Boolean {

        return put(
            key = key,
            value = value,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Get Or Put
    // -------------------------------------------------------------------------

    /**
     * Cache-aside helper.
     *
     * Flow:
     *
     * 1. Try cache.
     * 2. If found, return cached value.
     * 3. Otherwise execute loader.
     * 4. Store loaded value.
     * 5. Return loaded value.
     *
     * The loader is intentionally supplied by the repository
     * or CacheManager rather than by MemoryCache itself.
     */
    suspend fun <T : Any> getOrPut(
        key: String,
        ttlMillis: Long,
        loader: suspend () -> T
    ): T {

        val cached =
            get<T>(key)

        if (cached != null) {
            return cached
        }

        /**
         * Prevent multiple concurrent cache misses from
         * unnecessarily executing the loader at the same time.
         */
        return mutex.withLock {

            /**
             * Another coroutine may have populated the cache
             * while this coroutine was waiting for the mutex.
             */
            val secondCheck =
                get<T>(key)

            if (secondCheck != null) {
                return@withLock secondCheck
            }

            val loaded =
                loader()

            put(
                key = key,
                value = loaded,
                ttlMillis = ttlMillis
            )

            loaded
        }
    }

    // -------------------------------------------------------------------------
    // Prefix Invalidation
    // -------------------------------------------------------------------------

    /**
     * Removes every cache entry whose key starts with the
     * supplied prefix.
     *
     * Example:
     *
     * prefix = "threat:"
     *
     * removes:
     *
     * threat:all
     * threat:recent
     * threat:123
     * threat:456
     */
    suspend fun invalidatePrefix(
        prefix: String
    ): Int {

        if (prefix.isBlank()) {
            return 0
        }

        return mutex.withLock {

            val keysToRemove =
                cache.keys
                    .filter {
                        it.startsWith(prefix)
                    }

            keysToRemove.forEach { key ->

                if (cache.remove(key) != null) {
                    removeCount++
                }
            }

            keysToRemove.size
        }
    }

    // -------------------------------------------------------------------------
    // Clear
    // -------------------------------------------------------------------------

    /**
     * Removes every cache entry.
     *
     * This is a complete in-memory cache reset.
     */
    suspend fun clear(): Int {

        return mutex.withLock {

            val size =
                cache.size

            cache.clear()

            removeCount +=
                size.toLong()

            size
        }
    }

    // -------------------------------------------------------------------------
    // Expired Entries
    // -------------------------------------------------------------------------

    /**
     * Removes all currently expired entries.
     *
     * @return number of removed expired entries.
     */
    suspend fun removeExpiredEntries(): Int {

        val now =
            System.currentTimeMillis()

        return mutex.withLock {

            val expiredKeys =
                cache.entries
                    .filter {
                        isExpired(
                            entry = it.value,
                            now = now
                        )
                    }
                    .map {
                        it.key
                    }

            expiredKeys.forEach { key ->

                if (cache.remove(key) != null) {

                    expirationCount++
                    removeCount++
                }
            }

            expiredKeys.size
        }
    }

    // -------------------------------------------------------------------------
    // Size
    // -------------------------------------------------------------------------

    /**
     * Returns the number of entries currently stored.
     *
     * Expired entries are removed before calculating size.
     */
    suspend fun size(): Int {

        removeExpiredEntries()

        return cache.size
    }

    /**
     * Returns true when the cache has no valid entries.
     */
    suspend fun isEmpty(): Boolean {

        return size() == 0
    }

    // -------------------------------------------------------------------------
    // Key Inspection
    // -------------------------------------------------------------------------

    /**
     * Returns all currently valid cache keys.
     *
     * Useful for diagnostics and debugging.
     */
    suspend fun getKeys(): Set<String> {

        removeExpiredEntries()

        return cache.keys.toSet()
    }

    /**
     * Returns all cache keys matching a prefix.
     */
    suspend fun getKeysByPrefix(
        prefix: String
    ): Set<String> {

        if (prefix.isBlank()) {
            return emptySet()
        }

        removeExpiredEntries()

        return cache.keys
            .filter {
                it.startsWith(prefix)
            }
            .toSet()
    }

    // -------------------------------------------------------------------------
    // Entry Information
    // -------------------------------------------------------------------------

    /**
     * Returns the creation timestamp of an entry.
     */
    fun getCreatedAt(
        key: String
    ): Long? {

        val entry =
            cache[key]
                ?: return null

        if (isExpired(
                entry,
                System.currentTimeMillis()
            )
        ) {

            cache.remove(key)

            expirationCount++

            return null
        }

        return entry.createdAt
    }

    /**
     * Returns the last-access timestamp of an entry.
     */
    fun getLastAccessedAt(
        key: String
    ): Long? {

        val entry =
            cache[key]
                ?: return null

        if (isExpired(
                entry,
                System.currentTimeMillis()
            )
        ) {

            cache.remove(key)

            expirationCount++

            return null
        }

        return entry.lastAccessedAt
    }

    /**
     * Returns the expiration timestamp of an entry.
     */
    fun getExpiresAt(
        key: String
    ): Long? {

        val entry =
            cache[key]
                ?: return null

        if (isExpired(
                entry,
                System.currentTimeMillis()
            )
        ) {

            cache.remove(key)

            expirationCount++

            return null
        }

        return entry.expiresAt
    }

    // -------------------------------------------------------------------------
    // TTL
    // -------------------------------------------------------------------------

    /**
     * Returns remaining TTL for a cache entry.
     *
     * Returns:
     *
     * - Positive value = milliseconds remaining.
     * - 0 = expires immediately.
     * - null = entry does not exist.
     */
    fun getRemainingTtl(
        key: String
    ): Long? {

        val entry =
            cache[key]
                ?: return null

        val now =
            System.currentTimeMillis()

        if (isExpired(entry, now)) {

            cache.remove(key)

            expirationCount++

            return null
        }

        if (
            entry.expiresAt ==
            Long.MAX_VALUE
        ) {
            return Long.MAX_VALUE
        }

        return (
            entry.expiresAt - now
        ).coerceAtLeast(0L)
    }

    // -------------------------------------------------------------------------
    // Cache Statistics
    // -------------------------------------------------------------------------

    /**
     * Returns low-level memory-cache statistics.
     */
    fun getStatistics():
        MemoryCacheStatistics {

        val totalRequests =
            hitCount + missCount

        val hitRate =
            if (totalRequests == 0L) {
                0.0
            } else {
                hitCount.toDouble() /
                    totalRequests.toDouble()
            }

        return MemoryCacheStatistics(
            entryCount = cache.size,
            hitCount = hitCount,
            missCount = missCount,
            putCount = putCount,
            removeCount = removeCount,
            expirationCount = expirationCount,
            hitRate = hitRate
        )
    }

    /**
     * Resets cache counters.
     *
     * This does NOT clear cached values.
     */
    fun resetStatistics() {

        hitCount = 0L
        missCount = 0L
        putCount = 0L
        removeCount = 0L
        expirationCount = 0L
    }

    // -------------------------------------------------------------------------
    // Internal Helpers
    // -------------------------------------------------------------------------

    /**
     * Determines whether an entry has expired.
     */
    private fun isExpired(
        entry: CacheEntry,
        now: Long
    ): Boolean {

        return entry.expiresAt != Long.MAX_VALUE &&
            now >= entry.expiresAt
    }

    /**
     * Calculates absolute expiration time while protecting
     * against Long overflow.
     */
    private fun calculateExpiration(
        now: Long,
        ttlMillis: Long
    ): Long {

        if (ttlMillis == Long.MAX_VALUE) {
            return Long.MAX_VALUE
        }

        if (
            ttlMillis > 0L &&
            now > Long.MAX_VALUE - ttlMillis
        ) {
            return Long.MAX_VALUE
        }

        return now + ttlMillis
    }
}

/**
 * MemoryCache statistics.
 *
 * These statistics are useful for:
 *
 * - Debugging.
 * - Performance monitoring.
 * - Cache tuning.
 * - Analytics.
 * - Development diagnostics.
 */
data class MemoryCacheStatistics(
    val entryCount: Int,
    val hitCount: Long,
    val missCount: Long,
    val putCount: Long,
    val removeCount: Long,
    val expirationCount: Long,
    val hitRate: Double
)
