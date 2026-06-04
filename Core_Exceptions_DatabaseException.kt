package com.sentrix.core.exceptions

import java.sql.SQLException

/**
 * DatabaseException
 *
 * Base exception for all database-related
 * failures within the SentriX platform.
 *
 * Used by:
 * - Room Database
 * - CacheManager
 * - AnalyticsManager
 * - ThreatManager
 * - ScanManager
 * - Preferences Storage
 * - Cloud Sync Persistence
 */
open class DatabaseException : SQLException {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Generic database operation failure.
 */
class DatabaseOperationException(
    message: String = "Database operation failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database connection failure.
 */
class DatabaseConnectionException(
    message: String = "Unable to connect to database.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database initialization failure.
 */
class DatabaseInitializationException(
    message: String = "Database initialization failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database migration failure.
 */
class DatabaseMigrationException(
    message: String = "Database migration failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database corruption detected.
 */
class DatabaseCorruptionException(
    message: String = "Database corruption detected."
) : DatabaseException(message)

/**
 * Database locked.
 */
class DatabaseLockedException(
    message: String = "Database is locked."
) : DatabaseException(message)

/**
 * Query execution failure.
 */
class QueryExecutionException(
    message: String = "Database query execution failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Insert operation failure.
 */
class InsertException(
    message: String = "Failed to insert data.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Update operation failure.
 */
class UpdateException(
    message: String = "Failed to update data.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Delete operation failure.
 */
class DeleteException(
    message: String = "Failed to delete data.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Record not found.
 */
class RecordNotFoundException(
    message: String = "Requested record not found."
) : DatabaseException(message)

/**
 * Duplicate record detected.
 */
class DuplicateRecordException(
    message: String = "Duplicate record detected."
) : DatabaseException(message)

/**
 * Transaction failure.
 */
class TransactionException(
    message: String = "Database transaction failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Rollback failure.
 */
class RollbackException(
    message: String = "Database rollback failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Constraint violation.
 */
class ConstraintViolationException(
    message: String = "Database constraint violation."
) : DatabaseException(message)

/**
 * Foreign key violation.
 */
class ForeignKeyViolationException(
    message: String = "Foreign key constraint violation."
) : DatabaseException(message)

/**
 * Unique constraint violation.
 */
class UniqueConstraintException(
    message: String = "Unique constraint violation."
) : DatabaseException(message)

/**
 * Database backup failure.
 */
class DatabaseBackupException(
    message: String = "Database backup failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database restore failure.
 */
class DatabaseRestoreException(
    message: String = "Database restore failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database export failure.
 */
class DatabaseExportException(
    message: String = "Database export failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database import failure.
 */
class DatabaseImportException(
    message: String = "Database import failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database encryption failure.
 */
class DatabaseEncryptionException(
    message: String = "Database encryption failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Database decryption failure.
 */
class DatabaseDecryptionException(
    message: String = "Database decryption failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Schema validation failure.
 */
class SchemaValidationException(
    message: String = "Database schema validation failed."
) : DatabaseException(message)

/**
 * Version mismatch detected.
 */
class DatabaseVersionMismatchException(
    message: String = "Database version mismatch detected."
) : DatabaseException(message)

/**
 * Database synchronization failure.
 */
class DatabaseSyncException(
    message: String = "Database synchronization failed.",
    cause: Throwable? = null
) : DatabaseException(message, cause)

/**
 * Critical database failure.
 */
class CriticalDatabaseException(
    message: String = "Critical database failure detected."
) : DatabaseException(message)
