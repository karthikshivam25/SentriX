package com.sentrix.security.encryption

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer

/**
 * SentriX Secure Data Encryptor
 *
 * Provides a high-level API for encrypting and decrypting application data.
 *
 * This class is intended for use by:
 *
 * - Repositories
 * - Data sources
 * - Security services
 * - Use cases
 * - Cache protection
 * - Local sensitive-data storage
 *
 * Security responsibilities:
 *
 * - Encrypt String values.
 * - Decrypt String values.
 * - Encrypt ByteArray values.
 * - Decrypt ByteArray values.
 * - Encode encrypted binary payloads as Base64.
 * - Decode Base64 encrypted payloads.
 * - Handle nullable sensitive values.
 * - Validate encrypted payloads.
 *
 * Actual cryptographic execution is delegated to:
 *
 *      EncryptionEngine
 *
 * Key lifecycle is delegated to:
 *
 *      EncryptionKeyManager
 *
 * Architecture:
 *
 *      Repository / UseCase
 *             │
 *             ▼
 *      SecureDataEncryptor
 *             │
 *       ┌─────┴─────┐
 *       ▼           ▼
 * EncryptionEngine  EncryptionKeyManager
 *                       │
 *                       ▼
 *                Android Keystore
 *
 * Algorithm:
 *
 *      AES-256-GCM
 *
 * Encrypted payload:
 *
 *      [IV][Ciphertext + Authentication Tag]
 *
 * Storage representation:
 *
 *      Base64(NO_WRAP)
 */
object SecureDataEncryptor {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /**
     * Base64 encoding flags.
     *
     * NO_WRAP ensures the encrypted value remains a single-line String,
     * making it suitable for:
     *
     * - Room
     * - DataStore
     * - JSON
     * - Cache
     * - Database fields
     */
    private const val BASE64_FLAGS =
        Base64.NO_WRAP

    /**
     * Prefix used to identify the current SentriX encrypted-data format.
     *
     * Versioning allows future encrypted payload formats to be introduced
     * without breaking existing data.
     */
    private const val PAYLOAD_VERSION = 1

    /**
     * Number of bytes used by the payload version.
     */
    private const val VERSION_SIZE = 1

    /**
     * Payload structure:
     *
     *      [Version][IV][Ciphertext + Authentication Tag]
     */
    private const val MINIMUM_PAYLOAD_SIZE =
        VERSION_SIZE +
                EncryptionEngine.IV_SIZE +
                (EncryptionEngine.GCM_TAG_LENGTH / Byte.SIZE_BITS) +
                1

    // -------------------------------------------------------------------------
    // String Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts a String value.
     *
     * The resulting value is Base64 encoded and suitable for persistence.
     *
     * Example:
     *
     *      val encrypted =
     *          SecureDataEncryptor.encrypt("Sensitive token")
     *
     * @param plainText String to encrypt.
     *
     * @return Base64 encoded encrypted data.
     */
    suspend fun encrypt(
        plainText: String
    ): String = withContext(Dispatchers.Default) {

        require(plainText.isNotEmpty()) {
            "Plaintext cannot be empty."
        }

        val encryptedPayload =
            encryptBytesInternal(
                plainText.toByteArray(
                    Charsets.UTF_8
                )
            )

        Base64.encodeToString(
            encryptedPayload,
            BASE64_FLAGS
        )
    }

    /**
     * Encrypts a nullable String.
     *
     * Null remains null.
     */
    suspend fun encryptNullable(
        plainText: String?
    ): String? {

        return plainText?.let {
            encrypt(it)
        }
    }

    // -------------------------------------------------------------------------
    // String Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypts a Base64 encoded encrypted String.
     *
     * @param encryptedData Base64 encoded encrypted payload.
     *
     * @return Original plaintext String.
     */
    suspend fun decrypt(
        encryptedData: String
    ): String = withContext(Dispatchers.Default) {

        require(encryptedData.isNotBlank()) {
            "Encrypted data cannot be blank."
        }

        val encryptedPayload = decodePayload(
            encryptedData
        )

        val decryptedBytes =
            decryptBytesInternal(
                encryptedPayload
            )

        String(
            decryptedBytes,
            Charsets.UTF_8
        )
    }

    /**
     * Decrypts a nullable encrypted String.
     */
    suspend fun decryptNullable(
        encryptedData: String?
    ): String? {

        return encryptedData?.let {
            decrypt(it)
        }
    }

    // -------------------------------------------------------------------------
    // ByteArray Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts arbitrary binary data.
     *
     * Useful for:
     *
     * - Files
     * - Serialized objects
     * - Binary cache entries
     * - Security reports
     * - Exported security metadata
     *
     * @param data Raw data.
     *
     * @return Base64 encoded encrypted payload.
     */
    suspend fun encryptBytes(
        data: ByteArray
    ): String = withContext(Dispatchers.Default) {

        require(data.isNotEmpty()) {
            "Data cannot be empty."
        }

        val encryptedPayload =
            encryptBytesInternal(
                data
            )

        Base64.encodeToString(
            encryptedPayload,
            BASE64_FLAGS
        )
    }

    /**
     * Encrypts raw binary data and returns the binary payload directly.
     *
     * This avoids Base64 overhead when the caller already works with
     * ByteArray storage.
     */
    suspend fun encryptBytesRaw(
        data: ByteArray
    ): ByteArray = withContext(Dispatchers.Default) {

        require(data.isNotEmpty()) {
            "Data cannot be empty."
        }

        encryptBytesInternal(
            data
        )
    }

    // -------------------------------------------------------------------------
    // ByteArray Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypts Base64 encoded binary data.
     */
    suspend fun decryptBytes(
        encryptedData: String
    ): ByteArray = withContext(Dispatchers.Default) {

        require(encryptedData.isNotBlank()) {
            "Encrypted data cannot be blank."
        }

        val encryptedPayload =
            decodePayload(
                encryptedData
            )

        decryptBytesInternal(
            encryptedPayload
        )
    }

    /**
     * Decrypts a raw binary encrypted payload.
     */
    suspend fun decryptBytesRaw(
        encryptedPayload: ByteArray
    ): ByteArray = withContext(Dispatchers.Default) {

        require(encryptedPayload.isNotEmpty()) {
            "Encrypted payload cannot be empty."
        }

        decryptBytesInternal(
            encryptedPayload
        )
    }

    // -------------------------------------------------------------------------
    // Internal Encryption
    // -------------------------------------------------------------------------

    /**
     * Performs the actual encryption workflow.
     *
     * Steps:
     *
     * 1. Obtain the current SentriX encryption key.
     * 2. Pass plaintext to EncryptionEngine.
     * 3. Add the SentriX payload version.
     *
     * EncryptionEngine remains responsible for AES-GCM.
     */
    private fun encryptBytesInternal(
        data: ByteArray
    ): ByteArray {

        val key =
            EncryptionKeyManager.ensureMasterKey()

        val encryptedPayload =
            EncryptionEngine.encrypt(
                plainText = data,
                secretKey = key
            )

        return addPayloadVersion(
            encryptedPayload
        )
    }

    /**
     * Performs the actual decryption workflow.
     *
     * Steps:
     *
     * 1. Validate payload.
     * 2. Read payload version.
     * 3. Remove version metadata.
     * 4. Obtain the SentriX master key.
     * 5. Delegate AES-GCM decryption to EncryptionEngine.
     */
    private fun decryptBytesInternal(
        encryptedPayload: ByteArray
    ): ByteArray {

        validatePayload(
            encryptedPayload
        )

        val payloadVersion =
            encryptedPayload[0].toInt()

        validatePayloadVersion(
            payloadVersion
        )

        val cryptographicPayload =
            encryptedPayload.copyOfRange(
                VERSION_SIZE,
                encryptedPayload.size
            )

        val key =
            EncryptionKeyManager.getMasterKey()

        return EncryptionEngine.decrypt(
            encryptedPayload = cryptographicPayload,
            secretKey = key
        )
    }

    // -------------------------------------------------------------------------
    // Payload Versioning
    // -------------------------------------------------------------------------

    /**
     * Adds a one-byte format version before the cryptographic payload.
     *
     * Final structure:
     *
     *      [Version][IV][Ciphertext + Authentication Tag]
     */
    private fun addPayloadVersion(
        encryptedPayload: ByteArray
    ): ByteArray {

        return ByteBuffer
            .allocate(
                VERSION_SIZE +
                        encryptedPayload.size
            )
            .put(
                PAYLOAD_VERSION.toByte()
            )
            .put(
                encryptedPayload
            )
            .array()
    }

    /**
     * Reads the payload version.
     */
    fun getPayloadVersion(
        encryptedData: String
    ): Int {

        val payload =
            decodePayload(
                encryptedData
            )

        validatePayload(
            payload
        )

        return payload[0].toInt()
    }

    /**
     * Validates the currently supported payload version.
     */
    private fun validatePayloadVersion(
        version: Int
    ) {

        require(version == PAYLOAD_VERSION) {
            "Unsupported SentriX encryption payload version: $version"
        }
    }

    // -------------------------------------------------------------------------
    // Base64 Handling
    // -------------------------------------------------------------------------

    /**
     * Decodes a Base64 encrypted payload.
     */
    private fun decodePayload(
        encryptedData: String
    ): ByteArray {

        return try {

            Base64.decode(
                encryptedData,
                BASE64_FLAGS
            )

        } catch (exception: IllegalArgumentException) {

            throw IllegalArgumentException(
                "Invalid encrypted data format.",
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Payload Validation
    // -------------------------------------------------------------------------

    /**
     * Performs structural validation of an encrypted payload.
     *
     * This does NOT verify authenticity.
     *
     * AES-GCM authentication is performed by EncryptionEngine during
     * decryption.
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
     * Validates a raw encrypted payload.
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
            encryptedPayload.copyOfRange(
                VERSION_SIZE,
                encryptedPayload.size
            )

        return EncryptionEngine.isValidPayload(
            cryptographicPayload
        )
    }

    /**
     * Throws when an encrypted payload is structurally invalid.
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
    }

    // -------------------------------------------------------------------------
    // Secure Data Helpers
    // -------------------------------------------------------------------------

    /**
     * Encrypts a value and returns null instead of throwing when
     * encryption fails.
     *
     * Useful for optional cache/protection workflows where the caller
     * wants to explicitly handle an unavailable encrypted value.
     */
    suspend fun tryEncrypt(
        plainText: String
    ): String? {

        return try {

            encrypt(
                plainText
            )

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Decrypts a value and returns null instead of throwing when
     * decryption fails.
     *
     * This is useful for safely handling corrupted or obsolete
     * encrypted cache entries.
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
    // Key Availability
    // -------------------------------------------------------------------------

    /**
     * Checks whether encryption can currently be performed.
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

    /**
     * Initializes the encryption key if required.
     */
    fun initialize() {

        EncryptionKeyManager.ensureMasterKey()
    }
}
