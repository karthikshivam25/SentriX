package com.sentrix.security.encryption

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * SentriX Encryption Service
 *
 * Provides a higher-level security service around [EncryptionManager].
 *
 * Responsibilities:
 * - Encrypt sensitive application data.
 * - Decrypt encrypted application data.
 * - Generate secure hashes.
 * - Compare hashes safely.
 * - Encrypt nullable values.
 * - Validate encrypted payloads.
 * - Provide encryption initialization/status operations.
 *
 * Architecture:
 *
 *      Presentation
 *           │
 *           ▼
 *      Domain / UseCase
 *           │
 *           ▼
 *      EncryptionService
 *           │
 *           ▼
 *      EncryptionManager
 *           │
 *           ▼
 *      Android Keystore
 *
 * The service deliberately does NOT manage the Android Keystore directly.
 * That responsibility belongs to EncryptionManager.
 */
object EncryptionService {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /**
     * SHA-256 produces a 256-bit digest.
     *
     * Hashing is one-way and should NOT be confused with encryption.
     */
    private const val SHA_256 = "SHA-256"

    /**
     * Standard hexadecimal characters used for hash representation.
     */
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /**
     * Initializes the SentriX encryption subsystem.
     *
     * This should normally be called during application startup,
     * before sensitive information is persisted.
     */
    fun initialize() {
        EncryptionManager.initialize()
    }

    /**
     * Determines whether the SentriX encryption key is available.
     */
    fun isEncryptionAvailable(): Boolean {
        return EncryptionManager.isEncryptionKeyAvailable()
    }

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts sensitive plaintext.
     *
     * Example:
     *
     *      val result = EncryptionService.encrypt("Sensitive information")
     *
     * The returned data is Base64 encoded and can safely be stored
     * as a String.
     *
     * @param plainText Data to encrypt.
     *
     * @return EncryptionResult.
     */
    suspend fun encrypt(
        plainText: String
    ): EncryptionResult {

        require(plainText.isNotEmpty()) {
            "Plaintext cannot be empty."
        }

        return EncryptionManager.encrypt(
            plainText = plainText
        )
    }

    /**
     * Encrypts data only when a value is available.
     *
     * Null values remain null.
     */
    suspend fun encryptNullable(
        value: String?
    ): EncryptionResult? {

        return value?.let {
            encrypt(it)
        }
    }

    /**
     * Encrypts multiple values.
     *
     * The operation is performed sequentially so that every encryption
     * operation receives its own unique AES-GCM IV.
     */
    suspend fun encryptAll(
        values: List<String>
    ): List<EncryptionResult> {

        return withContext(Dispatchers.Default) {

            values.map { value ->
                encrypt(value)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypts an encrypted SentriX payload.
     *
     * @param encryptedData Base64 encoded encrypted data.
     *
     * @return EncryptionResult containing plaintext on success.
     */
    suspend fun decrypt(
        encryptedData: String
    ): EncryptionResult {

        require(encryptedData.isNotEmpty()) {
            "Encrypted data cannot be empty."
        }

        return EncryptionManager.decrypt(
            encryptedData = encryptedData
        )
    }

    /**
     * Decrypts a nullable encrypted value.
     *
     * Null values remain null.
     */
    suspend fun decryptNullable(
        value: String?
    ): EncryptionResult? {

        return value?.let {
            decrypt(it)
        }
    }

    /**
     * Decrypts multiple encrypted values.
     */
    suspend fun decryptAll(
        values: List<String>
    ): List<EncryptionResult> {

        return withContext(Dispatchers.Default) {

            values.map { value ->
                decrypt(value)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Encrypt / Decrypt Convenience Methods
    // -------------------------------------------------------------------------

    /**
     * Encrypts a value and returns only the encrypted String.
     *
     * This method throws an IllegalStateException when encryption fails.
     *
     * Useful for internal repository/data-layer operations where failure
     * should immediately stop persistence.
     */
    suspend fun encryptOrThrow(
        plainText: String
    ): String {

        return when (
            val result = encrypt(plainText)
        ) {

            is EncryptionResult.Success -> {
                result.data
            }

            is EncryptionResult.Error -> {
                throw IllegalStateException(
                    result.message,
                    result.cause
                )
            }
        }
    }

    /**
     * Decrypts a value and returns only the plaintext.
     *
     * Throws IllegalStateException if decryption fails.
     */
    suspend fun decryptOrThrow(
        encryptedData: String
    ): String {

        return when (
            val result = decrypt(encryptedData)
        ) {

            is EncryptionResult.Success -> {
                result.data
            }

            is EncryptionResult.Error -> {
                throw IllegalStateException(
                    result.message,
                    result.cause
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // Hashing
    // -------------------------------------------------------------------------

    /**
     * Generates a SHA-256 hash.
     *
     * Hashing is appropriate when the original value does not need
     * to be recovered.
     *
     * Examples:
     * - Integrity fingerprints
     * - Non-secret identifiers
     * - File fingerprints
     * - Comparison values
     *
     * Do NOT use this method for passwords.
     * Passwords should use a password-specific slow hashing algorithm
     * such as Argon2id, scrypt, or bcrypt with appropriate parameters.
     *
     * @param value Input value.
     *
     * @return Lowercase hexadecimal SHA-256 digest.
     */
    suspend fun sha256(
        value: String
    ): String = withContext(Dispatchers.Default) {

        require(value.isNotEmpty()) {
            "Value cannot be empty."
        }

        val digest = MessageDigest.getInstance(SHA_256)

        val hashBytes = digest.digest(
            value.toByteArray(Charsets.UTF_8)
        )

        bytesToHex(hashBytes)
    }

    /**
     * Generates SHA-256 from raw bytes.
     *
     * Useful for file/content integrity calculations.
     */
    suspend fun sha256(
        data: ByteArray
    ): String = withContext(Dispatchers.Default) {

        require(data.isNotEmpty()) {
            "Data cannot be empty."
        }

        val digest = MessageDigest.getInstance(SHA_256)

        val hashBytes = digest.digest(data)

        bytesToHex(hashBytes)
    }

    /**
     * Converts a byte array into lowercase hexadecimal.
     */
    private fun bytesToHex(
        bytes: ByteArray
    ): String {

        val result = CharArray(bytes.size * 2)

        bytes.forEachIndexed { index, byte ->

            val value = byte.toInt() and 0xFF

            result[index * 2] =
                HEX_CHARS[value ushr 4]

            result[index * 2 + 1] =
                HEX_CHARS[value and 0x0F]
        }

        return String(result)
    }

    // -------------------------------------------------------------------------
    // Hash Verification
    // -------------------------------------------------------------------------

    /**
     * Verifies that a value matches a SHA-256 hash.
     *
     * Constant-time comparison is used to reduce timing leakage.
     */
    suspend fun verifySha256(
        value: String,
        expectedHash: String
    ): Boolean = withContext(Dispatchers.Default) {

        if (value.isEmpty() || expectedHash.isEmpty()) {
            return@withContext false
        }

        val calculatedHash = sha256(value)

        MessageDigest.isEqual(
            calculatedHash.toByteArray(Charsets.UTF_8),
            expectedHash.lowercase().toByteArray(Charsets.UTF_8)
        )
    }

    // -------------------------------------------------------------------------
    // Encrypted Payload Validation
    // -------------------------------------------------------------------------

    /**
     * Performs basic validation of an encrypted payload.
     *
     * This does NOT decrypt the payload.
     *
     * It only verifies that the supplied value:
     *
     * - Is not empty.
     * - Can be Base64 decoded.
     * - Contains enough bytes for an IV and encrypted content.
     *
     * Cryptographic authenticity is only confirmed during decryption.
     */
    fun isValidEncryptedPayload(
        encryptedData: String
    ): Boolean {

        if (encryptedData.isBlank()) {
            return false
        }

        return try {

            val decoded = Base64.decode(
                encryptedData,
                Base64.NO_WRAP
            )

            /**
             * EncryptionManager currently uses a 12-byte GCM IV.
             *
             * We only perform a basic minimum-length check here.
             */
            decoded.size > 12

        } catch (_: IllegalArgumentException) {

            false
        }
    }

    // -------------------------------------------------------------------------
    // Secure Comparison
    // -------------------------------------------------------------------------

    /**
     * Performs a constant-time comparison between two strings.
     *
     * Useful for security-sensitive comparisons where timing
     * information should be minimized.
     */
    fun secureEquals(
        first: String,
        second: String
    ): Boolean {

        return MessageDigest.isEqual(
            first.toByteArray(Charsets.UTF_8),
            second.toByteArray(Charsets.UTF_8)
        )
    }

    /**
     * Performs a constant-time comparison between byte arrays.
     */
    fun secureEquals(
        first: ByteArray,
        second: ByteArray
    ): Boolean {

        return MessageDigest.isEqual(
            first,
            second
        )
    }

    // -------------------------------------------------------------------------
    // Secure Data Removal
    // -------------------------------------------------------------------------

    /**
     * Attempts to clear sensitive data from a mutable byte array.
     *
     * IMPORTANT:
     *
     * JVM/Android memory management does not provide a guarantee that
     * all copies of data are immediately removed.
     *
     * Therefore this should be considered a best-effort memory hygiene
     * operation rather than a cryptographic guarantee.
     */
    fun clearSensitiveData(
        data: ByteArray
    ) {

        data.fill(0)
    }

    /**
     * Deletes the SentriX encryption key.
     *
     * WARNING:
     *
     * All data encrypted using the deleted key becomes permanently
     * undecryptable.
     *
     * This should only be used for controlled security operations such as:
     *
     * - Secure application reset
     * - Enterprise wipe
     * - Device security response
     * - Controlled logout/key rotation workflow
     */
    fun deleteEncryptionKey() {
        EncryptionManager.deleteEncryptionKey()
    }
}
