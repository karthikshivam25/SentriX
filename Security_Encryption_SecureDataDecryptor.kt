package com.sentrix.security.encryption

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * SentriX Secure Data Decryptor
 *
 * Dedicated data decryption facade for the SentriX security subsystem.
 *
 * Responsibilities:
 *
 * - Decrypt String values.
 * - Decrypt ByteArray values.
 * - Decode Base64 encrypted payloads.
 * - Validate encrypted payload structure.
 * - Validate encryption payload version.
 * - Handle nullable encrypted values.
 * - Provide safe "try decrypt" operations.
 * - Verify that the current SentriX encryption key is available.
 *
 * Actual cryptographic operations are delegated to:
 *
 *      EncryptionEngine
 *
 * Encryption-key management is delegated to:
 *
 *      EncryptionKeyManager
 *
 * Architecture:
 *
 *      Repository / UseCase
 *             │
 *             ▼
 *      SecureDataDecryptor
 *             │
 *             ├──────────────► EncryptionKeyManager
 *             │                      │
 *             │                      ▼
 *             │               Android Keystore
 *             │
 *             ▼
 *      EncryptionEngine
 *             │
 *             ▼
 *         AES-256-GCM
 *
 * Expected encrypted payload:
 *
 *      [Version][IV][Ciphertext + Authentication Tag]
 *
 * Stored representation:
 *
 *      Base64(NO_WRAP)
 *
 * IMPORTANT:
 *
 * Successful AES-GCM decryption also verifies the authentication tag.
 * If the ciphertext has been modified or the wrong key is used,
 * decryption fails.
 */
object SecureDataDecryptor {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /**
     * Base64 decoding flags.
     */
    private const val BASE64_FLAGS =
        Base64.NO_WRAP

    /**
     * Current SentriX encrypted payload format.
     *
     * This must remain synchronized with SecureDataEncryptor.
     */
    private const val PAYLOAD_VERSION = 1

    /**
     * Number of bytes used by the payload version.
     */
    private const val VERSION_SIZE = 1

    /**
     * GCM authentication tag size in bytes.
     */
    private const val AUTH_TAG_SIZE =
        EncryptionEngine.GCM_TAG_LENGTH / Byte.SIZE_BITS

    /**
     * Minimum cryptographic payload:
     *
     * IV + authentication tag + at least one byte ciphertext.
     */
    private const val MIN_CRYPTO_PAYLOAD_SIZE =
        EncryptionEngine.IV_SIZE +
                AUTH_TAG_SIZE +
                1

    /**
     * Minimum complete SentriX payload:
     *
     * Version + IV + authentication tag + ciphertext.
     */
    private const val MINIMUM_PAYLOAD_SIZE =
        VERSION_SIZE +
                MIN_CRYPTO_PAYLOAD_SIZE

    // -------------------------------------------------------------------------
    // String Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypts a Base64 encoded encrypted String.
     *
     * @param encryptedData Base64 encoded SentriX encrypted payload.
     *
     * @return Decrypted UTF-8 String.
     *
     * @throws IllegalArgumentException when the payload format is invalid.
     * @throws SecurityException when authentication/decryption fails.
     */
    suspend fun decrypt(
        encryptedData: String
    ): String = withContext(Dispatchers.Default) {

        require(encryptedData.isNotBlank()) {
            "Encrypted data cannot be blank."
        }

        val encryptedPayload =
            decodeBase64Payload(
                encryptedData
            )

        decryptRawString(
            encryptedPayload
        )
    }

    /**
     * Decrypts a nullable encrypted String.
     *
     * Null remains null.
     */
    suspend fun decryptNullable(
        encryptedData: String?
    ): String? {

        return encryptedData?.let {
            decrypt(it)
        }
    }

    /**
     * Performs decryption and returns null if decryption fails.
     *
     * This is useful for:
     *
     * - Expired cache data
     * - Corrupted cache entries
     * - Data migrated from an older version
     * - Optional encrypted preferences
     */
    suspend fun tryDecrypt(
        encryptedData: String
    ): String? {

        return try {

            decrypt(
                encryptedData
            )

        } catch (_: Exception) {

            null
        }
    }

    // -------------------------------------------------------------------------
    // ByteArray Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypts a Base64 encoded encrypted binary payload.
     *
     * @return Original plaintext bytes.
     */
    suspend fun decryptBytes(
        encryptedData: String
    ): ByteArray = withContext(Dispatchers.Default) {

        require(encryptedData.isNotBlank()) {
            "Encrypted data cannot be blank."
        }

        val encryptedPayload =
            decodeBase64Payload(
                encryptedData
            )

        decryptRawBytes(
            encryptedPayload
        )
    }

    /**
     * Attempts to decrypt Base64 encoded binary data.
     *
     * Returns null when the payload cannot be decrypted.
     */
    suspend fun tryDecryptBytes(
        encryptedData: String
    ): ByteArray? {

        return try {

            decryptBytes(
                encryptedData
            )

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Decrypts an already decoded raw encrypted payload.
     *
     * Useful when encrypted data is stored as binary rather than Base64.
     */
    suspend fun decryptRawBytes(
        encryptedPayload: ByteArray
    ): ByteArray = withContext(Dispatchers.Default) {

        validatePayload(
            encryptedPayload
        )

        val cryptographicPayload =
            extractCryptographicPayload(
                encryptedPayload
            )

        val key =
            EncryptionKeyManager.getMasterKey()

        EncryptionEngine.decrypt(
            encryptedPayload = cryptographicPayload,
            secretKey = key
        )
    }

    /**
     * Decrypts an already decoded payload and converts it to UTF-8.
     */
    private suspend fun decryptRawString(
        encryptedPayload: ByteArray
    ): String {

        val decryptedBytes =
            decryptRawBytes(
                encryptedPayload
            )

        return String(
            decryptedBytes,
            Charsets.UTF_8
        )
    }

    // -------------------------------------------------------------------------
    // Base64 Handling
    // -------------------------------------------------------------------------

    /**
     * Converts a Base64 encrypted String into its binary payload.
     */
    private fun decodeBase64Payload(
        encryptedData: String
    ): ByteArray {

        return try {

            Base64.decode(
                encryptedData,
                BASE64_FLAGS
            )

        } catch (exception: IllegalArgumentException) {

            throw IllegalArgumentException(
                "Invalid SentriX encrypted data format.",
                exception
            )
        }
    }

    /**
     * Encodes raw encrypted data into Base64.
     *
     * This method is exposed for callers that already possess a raw
     * encrypted payload and need a database-safe String representation.
     */
    fun encodePayload(
        encryptedPayload: ByteArray
    ): String {

        validatePayload(
            encryptedPayload
        )

        return Base64.encodeToString(
            encryptedPayload,
            BASE64_FLAGS
        )
    }

    // -------------------------------------------------------------------------
    // Payload Validation
    // -------------------------------------------------------------------------

    /**
     * Performs structural validation before decryption.
     *
     * This does NOT prove authenticity.
     *
     * Authenticity is verified only when AES-GCM successfully validates
     * the authentication tag during EncryptionEngine.decrypt().
     */
    fun isValidPayload(
        encryptedPayload: ByteArray
    ): Boolean {

        if (
            encryptedPayload.size <
            MINIMUM_PAYLOAD_SIZE
        ) {
            return false
        }

        val version =
            encryptedPayload[0].toInt()

        if (version != PAYLOAD_VERSION) {
            return false
        }

        val cryptographicPayload =
            extractCryptographicPayloadUnsafe(
                encryptedPayload
            )

        return EncryptionEngine.isValidPayload(
            cryptographicPayload
        )
    }

    /**
     * Validates a Base64 encrypted String without decrypting it.
     */
    fun isValidEncryptedData(
        encryptedData: String
    ): Boolean {

        if (encryptedData.isBlank()) {
            return false
        }

        return try {

            val payload =
                Base64.decode(
                    encryptedData,
                    BASE64_FLAGS
                )

            isValidPayload(
                payload
            )

        } catch (_: IllegalArgumentException) {

            false
        }
    }

    /**
     * Performs strict payload validation.
     */
    private fun validatePayload(
        encryptedPayload: ByteArray
    ) {

        require(
            encryptedPayload.size >=
                    MINIMUM_PAYLOAD_SIZE
        ) {
            "Invalid SentriX encrypted payload."
        }

        val version =
            encryptedPayload[0].toInt()

        validatePayloadVersion(
            version
        )

        val cryptographicPayload =
            extractCryptographicPayload(
                encryptedPayload
            )

        require(
            EncryptionEngine.isValidPayload(
                cryptographicPayload
            )
        ) {
            "Invalid SentriX cryptographic payload."
        }
    }

    // -------------------------------------------------------------------------
    // Payload Versioning
    // -------------------------------------------------------------------------

    /**
     * Returns the encryption format version stored in a payload.
     */
    fun getPayloadVersion(
        encryptedData: String
    ): Int {

        val payload =
            decodeBase64Payload(
                encryptedData
            )

        require(
            payload.isNotEmpty()
        ) {
            "Encrypted payload is empty."
        }

        return payload[0].toInt()
    }

    /**
     * Validates the supported payload version.
     */
    private fun validatePayloadVersion(
        version: Int
    ) {

        require(version == PAYLOAD_VERSION) {
            "Unsupported SentriX encryption payload version: $version"
        }
    }

    /**
     * Extracts the AES-GCM portion from:
     *
     *      [Version][IV][Ciphertext + Authentication Tag]
     *
     * Result:
     *
     *      [IV][Ciphertext + Authentication Tag]
     */
    private fun extractCryptographicPayload(
        encryptedPayload: ByteArray
    ): ByteArray {

        require(
            encryptedPayload.size >=
                    MINIMUM_PAYLOAD_SIZE
        ) {
            "Encrypted payload is too small."
        }

        return extractCryptographicPayloadUnsafe(
            encryptedPayload
        )
    }

    /**
     * Internal extraction helper.
     *
     * Assumes minimum-size validation has already been performed.
     */
    private fun extractCryptographicPayloadUnsafe(
        encryptedPayload: ByteArray
    ): ByteArray {

        return encryptedPayload.copyOfRange(
            VERSION_SIZE,
            encryptedPayload.size
        )
    }

    // -------------------------------------------------------------------------
    // Encryption-Key Status
    // -------------------------------------------------------------------------

    /**
     * Determines whether the key required for decryption is available.
     *
     * No decryption is performed by this method.
     */
    fun isDecryptionAvailable(): Boolean {

        return try {

            EncryptionKeyManager
                .validateMasterKey() is
                    KeyValidationResult.Valid

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Retrieves the current encryption payload version.
     */
    fun getCurrentPayloadVersion(): Int {
        return PAYLOAD_VERSION
    }

    // -------------------------------------------------------------------------
    // Safe Decryption Helpers
    // -------------------------------------------------------------------------

    /**
     * Decrypts data while distinguishing between:
     *
     * - Invalid payload format.
     * - Missing encryption key.
     * - Cryptographic authentication failure.
     *
     * This gives higher-level SentriX components a typed result instead
     * of requiring them to parse exception types.
     */
    suspend fun decryptSafely(
        encryptedData: String
    ): SecureDecryptionResult {

        return try {

            if (
                encryptedData.isBlank()
            ) {
                return SecureDecryptionResult.InvalidPayload(
                    "Encrypted data is blank."
                )
            }

            val payload =
                try {
                    decodeBase64Payload(
                        encryptedData
                    )
                } catch (exception: Exception) {

                    return SecureDecryptionResult.InvalidPayload(
                        "Encrypted data is not valid Base64."
                    )
                }

            if (
                !isValidPayload(payload)
            ) {
                return SecureDecryptionResult.InvalidPayload(
                    "Encrypted payload structure is invalid."
                )
            }

            if (
                !isDecryptionAvailable()
            ) {
                return SecureDecryptionResult.KeyUnavailable
            }

            val plaintext =
                decryptRawString(
                    payload
                )

            SecureDecryptionResult.Success(
                plaintext
            )

        } catch (exception: SecurityException) {

            SecureDecryptionResult.AuthenticationFailed(
                "Encrypted data authentication failed.",
                exception
            )

        } catch (exception: Exception) {

            SecureDecryptionResult.Failed(
                "Unable to decrypt encrypted data.",
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /**
     * Ensures that the SentriX encryption key exists.
     *
     * Normally initialization should happen through the broader
     * encryption subsystem, but this helper is provided for components
     * that explicitly depend on SecureDataDecryptor.
     */
    fun initialize() {

        EncryptionKeyManager.ensureMasterKey()
    }
}

/**
 * Typed result returned by SecureDataDecryptor.decryptSafely().
 *
 * This prevents higher layers from having to depend directly on
 * cryptographic exception classes.
 */
sealed class SecureDecryptionResult {

    /**
     * Decryption succeeded.
     */
    data class Success(
        val data: String
    ) : SecureDecryptionResult()

    /**
     * Payload structure or Base64 representation is invalid.
     */
    data class InvalidPayload(
        val reason: String
    ) : SecureDecryptionResult()

    /**
     * Required Keystore encryption key is unavailable.
     */
    data object KeyUnavailable : SecureDecryptionResult()

    /**
     * AES-GCM authentication failed.
     *
     * This can indicate:
     *
     * - Modified ciphertext.
     * - Incorrect key.
     * - Corrupted payload.
     * - Incorrect IV.
     */
    data class AuthenticationFailed(
        val message: String,
        val cause: Throwable? = null
    ) : SecureDecryptionResult()

    /**
     * Unexpected decryption failure.
     */
    data class Failed(
        val message: String,
        val cause: Throwable? = null
    ) : SecureDecryptionResult()
}
