package com.sentrix.core.managers

import android.content.Context
import android.util.LruCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * CacheManager
 *
 * Responsibilities:
 * - In-memory caching
 * - Disk caching
 * - Cache expiration handling
 * - Cache size monitoring
 * - Cache cleanup
 * - Temporary data storage
 */
class CacheManager(
    private val context: Context
) {

    private val memoryCache = object : LruCache<String, CacheEntry>(
        DEFAULT_MEMORY_CACHE_SIZE
    ) {
        override fun sizeOf(
            key: String,
            value: CacheEntry
        ): Int {
            return 1
        }
    }

    private val expirationMap =
        ConcurrentHashMap<String, Long>()

    /**
     * Store data in memory cache.
     */
    fun put(
        key: String,
        value: String,
        expiryMillis: Long = DEFAULT_EXPIRY_TIME
    ) {

        memoryCache.put(
            key,
            CacheEntry(
                value = value,
                timestamp = System.currentTimeMillis()
            )
        )

        expirationMap[key] =
            System.currentTimeMillis() + expiryMillis
    }

    /**
     * Retrieve cached data.
     */
    fun get(
        key: String
    ): String? {

        if (isExpired(key)) {
            remove(key)
            return null
        }

        return memoryCache.get(key)?.value
    }

    /**
     * Check cache existence.
     */
    fun contains(
        key: String
    ): Boolean {
        return get(key) != null
    }

    /**
     * Remove cache item.
     */
    fun remove(
        key: String
    ) {
        memoryCache.remove(key)
        expirationMap.remove(key)
    }

    /**
     * Clear memory cache.
     */
    fun clearMemoryCache() {
        memoryCache.evictAll()
        expirationMap.clear()
    }

    /**
     * Save data to disk cache.
     */
    suspend fun saveToDisk(
        fileName: String,
        data: String
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val file = File(
                context.cacheDir,
                fileName
            )

            file.writeText(data)

            true

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Read cached file.
     */
    suspend fun readFromDisk(
        fileName: String
    ): String? = withContext(Dispatchers.IO) {

        try {

            val file = File(
                context.cacheDir,
                fileName
            )

            if (!file.exists()) {
                return@withContext null
            }

            file.readText()

        } catch (_: Exception) {
            null
        }
    }

    /**
     * Delete cached file.
     */
    suspend fun deleteFromDisk(
        fileName: String
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val file = File(
                context.cacheDir,
                fileName
            )

            if (file.exists()) {
                file.delete()
            } else {
                false
            }

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Clear entire disk cache.
     */
    suspend fun clearDiskCache(): Boolean =
        withContext(Dispatchers.IO) {

            try {

                context.cacheDir.deleteRecursively()
                context.cacheDir.mkdirs()

                true

            } catch (_: Exception) {
                false
            }
        }

    /**
     * Get total cache size.
     */
    fun getCacheSizeBytes(): Long {
        return calculateDirectorySize(
            context.cacheDir
        )
    }

    /**
     * Get formatted cache size.
     */
    fun getFormattedCacheSize(): String {
        return formatBytes(
            getCacheSizeBytes()
        )
    }

    /**
     * Cleanup expired entries.
     */
    fun cleanupExpiredEntries() {

        val keys =
            expirationMap.keys.toList()

        keys.forEach { key ->

            if (isExpired(key)) {
                remove(key)
            }
        }
    }

    /**
     * Check if cache item expired.
     */
    private fun isExpired(
        key: String
    ): Boolean {

        val expiry =
            expirationMap[key]
                ?: return true

        return System.currentTimeMillis() > expiry
    }

    /**
     * Calculate directory size.
     */
    private fun calculateDirectorySize(
        file: File
    ): Long {

        if (!file.exists()) {
            return 0L
        }

        if (file.isFile) {
            return file.length()
        }

        return file.listFiles()?.sumOf {
            calculateDirectorySize(it)
        } ?: 0L
    }

    /**
     * Format bytes.
     */
    private fun formatBytes(
        bytes: Long
    ): String {

        if (bytes <= 0) {
            return "0 B"
        }

        val units =
            arrayOf("B", "KB", "MB", "GB", "TB")

        val digitGroup =
            (Math.log10(bytes.toDouble()) /
                    Math.log10(1024.0)).toInt()

        return String.format(
            "%.2f %s",
            bytes / Math.pow(
                1024.0,
                digitGroup.toDouble()
            ),
            units[digitGroup]
        )
    }

    /**
     * Generate cache report.
     */
    fun generateCacheReport(): String {

        return buildString {

            appendLine("Cache Report")
            appendLine("---------------------")
            appendLine(
                "Memory Entries : ${
                    memoryCache.snapshot().size
                }"
            )
            appendLine(
                "Disk Cache Size: ${
                    getFormattedCacheSize()
                }"
            )
            appendLine(
                "Cache Directory: ${
                    context.cacheDir.absolutePath
                }"
            )
        }
    }

    /**
     * Cache entry model.
     */
    data class CacheEntry(
        val value: String,
        val timestamp: Long
    )

    companion object {

        private const val DEFAULT_MEMORY_CACHE_SIZE = 200

        const val DEFAULT_EXPIRY_TIME =
            60 * 60 * 1000L // 1 hour
    }
}
