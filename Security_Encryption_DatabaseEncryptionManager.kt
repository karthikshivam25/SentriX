package com.sentrix.security.encryption

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * SentriX Database Encryption Manager
 *
 * Provides encryption and decryption for sensitive database data.
 *
 * This manager is designed for:
 *
 * - Room entities containing sensitive fields.
 * - Security events.
 * - Threat information.
 * - User security metadata.
 * - Security reports.
 * - Privacy audit records.
 * - Authentication/session metadata.
 * - Sensitive cached database values.
 *
 * IMPORTANT:
 *
 * This class performs APPLICATION-LEVEL DATA ENCRYPTION.
 *
 * It encrypts individual values before they are persisted into the
 * database and decrypts them after retrieval.
 *
 * It does NOT encrypt the entire SQLite database file.
 *
 * Architecture:
 *
 *      Repository
 *           │
 *           ▼
 * DatabaseEncryptionManager
 *           │
 *           ▼
 * SecureDataEncryptor
 *           │
 *           ▼
 * EncryptionEngine
 *           │
 *           ▼
 * EncryptionKeyManager
 *           │
 *           ▼
 * Android Keystore
 *
 * Cryptographic format:
 *
 *      [Version][IV][Ciphertext + Authentication Tag]
 *
 * Storage representation:
 *
 *      Base64 String
 */
object DatabaseEncryptionManager {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /**
     * Prefix used for identifying SentriX database-encrypted values.
     *
     * This makes it possible to distinguish encrypted values from
     * ordinary database strings.
     */
    private const val DATABASE_PREFIX =
        "SXDB1:"

    /**
     * Current database encryption format version.
     */
    private const val DATABASE_FORMAT_VERSION = 1

    /**
     * Maximum reasonable field size for String-based database encryption.
     *
     * This is a defensive application-level limit.
     *
     * Large binary/file data should use FileEncryptionManager instead.
     */
    private const val DEFAULT_MAX_FIELD_SIZE =
        1024 * 1024

    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /**
     * Initializes the database encryption subsystem.
     *
     * Ensures that the SentriX Keystore-backed encryption key exists.
     */
    fun initialize() {

        EncryptionKeyManager.ensureMasterKey()
    }

    /**
     * Returns whether database encryption is currently available.
     */
    fun isEncryptionAvailable(): Boolean {

        return try {

            EncryptionKeyManager
                .validateMasterKey() is
                    KeyValidationResult.Valid

        } catch (_: Exception) {

            false
        }
    }

    // -------------------------------------------------------------------------
    // String / Field Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts a sensitive database field.
     *
     * The returned value contains a SentriX database prefix:
     *
     *      SXDB1:<Base64 encrypted payload>
     *
     * This makes the stored format self-identifying.
     *
     * @param value Sensitive database value.
     *
     * @return Encrypted database-safe String.
     */
    suspend fun encryptField(
        value: String
    ): String = withContext(Dispatchers.Default) {

        require(value.isNotEmpty()) {
            "Database value cannot be empty."
        }

        validateFieldSize(
            value
        )

        ensureEncryptionAvailable()

        val encrypted =
            SecureDataEncryptor.encrypt(
                value
            )

        DATABASE_PREFIX + encrypted
    }

    /**
     * Encrypts a nullable database field.
     *
     * Null remains null.
     */
    suspend fun encryptNullableField(
        value: String?
    ): String? {

        return value?.let {
            encryptField(it)
        }
    }

    /**
     * Decrypts a database-encrypted field.
     *
     * The method verifies that the value belongs to the current
     * SentriX database encryption format before attempting decryption.
     */
    suspend fun decryptField(
        encryptedValue: String
    ): String = withContext(Dispatchers.Default) {

        require(encryptedValue.isNotBlank()) {
            "Encrypted database value cannot be blank."
        }

        validateDatabasePrefix(
            encryptedValue
        )

        ensureEncryptionAvailable()

        val payload =
            removeDatabasePrefix(
                encryptedValue
            )

        SecureDataDecryptor.decrypt(
            payload
        )
    }

    /**
     * Decrypts a nullable database field.
     *
     * Null remains null.
     */
    suspend fun decryptNullableField(
        encryptedValue: String?
    ): String? {

        return encryptedValue?.let {
            decryptField(it)
        }
    }

    // -------------------------------------------------------------------------
    // Safe Field Operations
    // -------------------------------------------------------------------------

    /**
     * Attempts to encrypt a database value.
     *
     * Returns null when encryption fails.
     *
     * This method is useful for optional database/cache workflows.
     */
    suspend fun tryEncryptField(
        value: String
    ): String? {

        return try {

            encryptField(
                value
            )

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Attempts to decrypt a database value.
     *
     * Returns null when decryption fails.
     *
     * This is useful when processing old/corrupted database records
     * without crashing an entire database query.
     */
    suspend fun tryDecryptField(
        encryptedValue: String
    ): String? {

        return try {

            decryptField(
                encryptedValue
            )

        } catch (_: Exception) {

            null
        }
    }

    // -------------------------------------------------------------------------
    // Batch Operations
    // -------------------------------------------------------------------------

    /**
     * Encrypts multiple database fields.
     *
     * Each value receives its own AES-GCM encryption operation and
     * therefore its own unique IV.
     */
    suspend fun encryptFields(
        values: List<String>
    ): List<String> = withContext(Dispatchers.Default) {

        values.map { value ->

            encryptField(
                value
            )
        }
    }

    /**
     * Decrypts multiple database fields.
     */
    suspend fun decryptFields(
        values: List<String>
    ): List<String> = withContext(Dispatchers.Default) {

        values.map { value ->

            decryptField(
                value
            )
        }
    }

    /**
     * Encrypts a map of database fields.
     *
     * Useful when mapping dynamic security metadata.
     */
    suspend fun encryptFieldMap(
        values: Map<String, String>
    ): Map<String, String> =
        withContext(Dispatchers.Default) {

            values.mapValues { (_, value) ->

                encryptField(
                    value
                )
            }
        }

    /**
     * Decrypts a map of database fields.
     */
    suspend fun decryptFieldMap(
        values: Map<String, String>
    ): Map<String, String> =
        withContext(Dispatchers.Default) {

            values.mapValues { (_, value) ->

                decryptField(
                    value
                )
            }
        }

    // -------------------------------------------------------------------------
    // ByteArray / Blob Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts binary database data.
     *
     * Useful for:
     *
     * - Encrypted blobs.
     * - Serialized security metadata.
     * - Small encrypted reports.
     * - Binary security artifacts.
     *
     * Large files should use FileEncryptionManager instead.
     */
    suspend fun encryptBlob(
        data: ByteArray
    ): ByteArray = withContext(Dispatchers.Default) {

        require(data.isNotEmpty()) {
            "Database blob cannot be empty."
        }

        validateBlobSize(
            data
        )

        ensureEncryptionAvailable()

        val encoded =
            SecureDataEncryptor.encryptBytes(
                data
            )

        val prefixBytes =
            DATABASE_PREFIX.toByteArray(
                Charsets.UTF_8
            )

        val encryptedBytes =
            encoded.toByteArray(
                Charsets.UTF_8
            )

        ByteArray(
            prefixBytes.size +
                    encryptedBytes.size
        ).also { result ->

            prefixBytes.copyInto(
                result,
                destinationOffset = 0
            )

            encryptedBytes.copyInto(
                result,
                destinationOffset =
                    prefixBytes.size
            )
        }
    }

    /**
     * Decrypts an encrypted database blob.
     */
    suspend fun decryptBlob(
        encryptedData: ByteArray
    ): ByteArray = withContext(Dispatchers.Default) {

        require(encryptedData.isNotEmpty()) {
            "Encrypted database blob cannot be empty."
        }

        val encodedValue =
            String(
                encryptedData,
                Charsets.UTF_8
            )

        validateDatabasePrefix(
            encodedValue
        )

        ensureEncryptionAvailable()

        val payload =
            removeDatabasePrefix(
                encodedValue
            )

        SecureDataDecryptor.decryptBytes(
            payload
        )
    }

    // -------------------------------------------------------------------------
    // Database Value Detection
    // -------------------------------------------------------------------------

    /**
     * Determines whether a database String is a SentriX encrypted value.
     *
     * This is useful during migrations where a database may contain
     * both legacy plaintext values and encrypted values.
     */
    fun isEncryptedField(
        value: String?
    ): Boolean {

        if (value.isNullOrBlank()) {
            return false
        }

        if (!value.startsWith(DATABASE_PREFIX)) {
            return false
        }

        val payload =
            value.removePrefix(
                DATABASE_PREFIX
            )

        return SecureDataDecryptor
            .isValidEncryptedData(
                payload
            )
    }

    /**
     * Determines whether a binary database value is a SentriX
     * encrypted blob.
     */
    fun isEncryptedBlob(
        data: ByteArray?
    ): Boolean {

        if (data == null || data.isEmpty()) {
            return false
        }

        return try {

            val value =
                String(
                    data,
                    Charsets.UTF_8
                )

            isEncryptedField(
                value
            )

        } catch (_: Exception) {

            false
        }
    }

    // -------------------------------------------------------------------------
    // Migration Helpers
    // -------------------------------------------------------------------------

    /**
     * Encrypts a legacy plaintext value only if it is not already
     * encrypted.
     *
     * This is useful during Room/database migrations.
     *
     * Example:
     *
     *      migrateField(oldValue)
     */
    suspend fun migrateField(
        value: String
    ): String {

        if (
            isEncryptedField(
                value
            )
        ) {
            return value
        }

        return encryptField(
            value
        )
    }

    /**
     * Migrates a nullable database field.
     */
    suspend fun migrateNullableField(
        value: String?
    ): String? {

        if (value == null) {
            return null
        }

        return migrateField(
            value
        )
    }

    /**
     * Migrates multiple database fields.
     */
    suspend fun migrateFields(
        values: List<String>
    ): List<String> {

        return values.map { value ->

            migrateField(
                value
            )
        }
    }

    // -------------------------------------------------------------------------
    // Database Format Information
    // -------------------------------------------------------------------------

    /**
     * Returns the current database encryption format version.
     */
    fun getFormatVersion(): Int {
        return DATABASE_FORMAT_VERSION
    }

    /**
     * Returns the prefix used by SentriX encrypted database values.
     */
    fun getDatabasePrefix(): String {
        return DATABASE_PREFIX
    }

    /**
     * Returns the default maximum field size.
     */
    fun getDefaultMaximumFieldSize(): Int {
        return DEFAULT_MAX_FIELD_SIZE
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /**
     * Ensures that the database encryption key is available.
     */
    private fun ensureEncryptionAvailable() {

        require(
            isEncryptionAvailable()
        ) {
            "SentriX database encryption is unavailable."
        }
    }

    /**
     * Validates a database field size.
     *
     * The limit prevents accidentally passing very large files or blobs
     * through a String-based database encryption API.
     */
    private fun validateFieldSize(
        value: String
    ) {

        val size =
            value.toByteArray(
                Charsets.UTF_8
            ).size

        require(
            size <= DEFAULT_MAX_FIELD_SIZE
        ) {
            "Database field exceeds the maximum supported size."
        }
    }

    /**
     * Validates a database blob size.
     */
    private fun validateBlobSize(
        data: ByteArray
    ) {

        require(
            data.size <= DEFAULT_MAX_FIELD_SIZE
        ) {
            "Database blob exceeds the maximum supported size."
        }
    }

    /**
     * Validates the SentriX database encryption prefix.
     */
    private fun validateDatabasePrefix(
        value: String
    ) {

        require(
            value.startsWith(
                DATABASE_PREFIX
            )
        ) {
            "Value is not a SentriX encrypted database value."
        }
    }

    /**
     * Removes the database prefix.
     */
    private fun removeDatabasePrefix(
        value: String
    ): String {

        validateDatabasePrefix(
            value
        )

        val payload =
            value.removePrefix(
                DATABASE_PREFIX
            )

        require(
            payload.isNotBlank()
        ) {
            "Encrypted database payload is empty."
        }

        return payload
    }
}
