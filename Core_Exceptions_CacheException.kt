package com.sentrix.core.exceptions

/**
 * CacheException
 *
 * Base exception for all cache-related
 * failures within the SentriX platform.
 *
 * Used by:
 * - CacheManager
 * - ThreatManager
 * - MalwareManager
 * - AIManager
 * - NetworkManager
 * - AnalyticsManager
 * - UpdateManager
 */
open class CacheException : Exception {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Generic cache operation failure.
 */
class CacheOperationException(
    message: String = "Cache operation failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache initialization failure.
 */
class CacheInitializationException(
    message: String = "Cache initialization failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache read failure.
 */
class CacheReadException(
    message: String = "Failed to read cache data.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache write failure.
 */
class CacheWriteException(
    message: String = "Failed to write cache data.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache deletion failure.
 */
class CacheDeleteException(
    message: String = "Failed to delete cache entry.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache entry not found.
 */
class CacheEntryNotFoundException(
    key: String
) : CacheException(
    "Cache entry not found: $key"
)

/**
 * Cache entry expired.
 */
class CacheExpiredException(
    key: String
) : CacheException(
    "Cache entry expired: $key"
)

/**
 * Cache key invalid.
 */
class InvalidCacheKeyException(
    message: String = "Invalid cache key."
) : CacheException(message)

/**
 * Cache value invalid.
 */
class InvalidCacheValueException(
    message: String = "Invalid cache value."
) : CacheException(message)

/**
 * Cache size limit exceeded.
 */
class CacheSizeExceededException(
    message: String = "Cache size limit exceeded."
) : CacheException(message)

/**
 * Memory cache full.
 */
class MemoryCacheFullException(
    message: String = "Memory cache is full."
) : CacheException(message)

/**
 * Disk cache full.
 */
class DiskCacheFullException(
    message: String = "Disk cache is full."
) : CacheException(message)

/**
 * Cache directory unavailable.
 */
class CacheDirectoryException(
    message: String = "Cache directory unavailable."
) : CacheException(message)

/**
 * Cache file corrupted.
 */
class CacheCorruptionException(
    message: String = "Cache corruption detected."
) : CacheException(message)

/**
 * Cache serialization failure.
 */
class CacheSerializationException(
    message: String = "Cache serialization failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache deserialization failure.
 */
class CacheDeserializationException(
    message: String = "Cache deserialization failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache encryption failure.
 */
class CacheEncryptionException(
    message: String = "Cache encryption failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache decryption failure.
 */
class CacheDecryptionException(
    message: String = "Cache decryption failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache cleanup failure.
 */
class CacheCleanupException(
    message: String = "Cache cleanup failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache synchronization failure.
 */
class CacheSynchronizationException(
    message: String = "Cache synchronization failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache timeout.
 */
class CacheTimeoutException(
    message: String = "Cache operation timed out."
) : CacheException(message)

/**
 * Cache permission denied.
 */
class CachePermissionException(
    message: String = "Cache access permission denied."
) : CacheException(message)

/**
 * Distributed cache failure.
 */
class DistributedCacheException(
    message: String = "Distributed cache failure.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Cache migration failure.
 */
class CacheMigrationException(
    message: String = "Cache migration failed.",
    cause: Throwable? = null
) : CacheException(message, cause)

/**
 * Critical cache failure.
 */
class CriticalCacheException(
    message: String = "Critical cache subsystem failure."
) : CacheException(message)
