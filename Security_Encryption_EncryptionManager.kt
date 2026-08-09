package com.sentrix.security.encryption

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * SentriX Encryption Manager
 *
 * Responsible for:
 * - Generating and managing the SentriX master encryption key.
 * - Encrypting sensitive application data.
 * - Decrypting previously encrypted data.
 * - Managing the Android Keystore key lifecycle.
 *
 * Security design:
 *
 * Algorithm:
 *      AES-256-GCM
 *
 * Key storage:
 *      AndroidKeyStore
 *
 * IV:
 *      12 bytes per encryption operation.
 *
 * Authentication tag:
 *      128 bits.
 *
 * Encoded payload:
 *
 *      [IV][Encrypted Data + Authentication Tag]
 *
 * The complete binary payload is finally encoded using
 * Base64.NO_WRAP so it can safely be stored in:
 *
 * - Room
 * - SharedPreferences/DataStore
 * - Files
 * - Cache
 * - Database entities
 * - Network-safe strings
 *
 * IMPORTANT:
 * The encryption key never leaves Android Keystore.
 */
object EncryptionManager {

    // -------------------------------------------------------------------------
    // Android Keystore configuration
    // -------------------------------------------------------------------------

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /**
     * Unique alias used by SentriX to identify its master encryption key.
     *
     * Do not change this alias after production deployment unless
     * a controlled key migration strategy is implemented.
     */
    private const val KEY_ALIAS = "SentriX_Master_Key"

    /**
     * AES transformation used by SentriX.
     *
     * GCM provides:
     * - Confidentiality
     * - Integrity
     * - Authentication
     *
     * NoPadding is required for GCM.
     */
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    /**
     * AES key size.
     */
    private const val KEY_SIZE = 256

    /**
     * GCM initialization vector size.
     *
     * 12 bytes is the recommended IV size for GCM.
     */
    private const val IV_SIZE = 12

    /**
     * Authentication tag size.
     */
    private const val GCM_TAG_LENGTH = 128

    /**
     * KeyStore instance is created lazily so the manager does not
     * perform unnecessary initialization until encryption functionality
     * is actually required.
     */
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }
    }

    // -------------------------------------------------------------------------
    // Public Encryption API
    // -------------------------------------------------------------------------

    /**
     * Encrypts the supplied plaintext.
     *
     * The operation is performed on Dispatchers.Default because
     * cryptographic operations should not execute on the Android main thread.
     *
     * @param plainText Data that needs to be protected.
     *
     * @return EncryptionResult containing either encrypted Base64 data
     *         or a descriptive error.
     */
    suspend fun encrypt(
        plainText: String
    ): EncryptionResult = withContext(Dispatchers.Default) {

        try {

            require(plainText.isNotEmpty()) {
                "Plaintext cannot be empty."
            }

            // Make sure the SentriX master key exists.
            generateKeyIfNeeded()

            val secretKey = getSecretKey()

            val cipher = Cipher.getInstance(TRANSFORMATION)

            /**
             * Calling init() without specifying an IV causes the
             * cryptographic provider to generate a secure random IV.
             *
             * This is preferable to manually reusing IVs.
             */
            cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey
            )

            val iv = cipher.iv

            val encryptedBytes = cipher.doFinal(
                plainText.toByteArray(Charsets.UTF_8)
            )

            /**
             * Store:
             *
             *      IV + encrypted bytes
             *
             * The IV itself is not secret.
             * It only needs to be unique for every encryption operation.
             */
            val combinedPayload = ByteBuffer
                .allocate(iv.size + encryptedBytes.size)
                .put(iv)
                .put(encryptedBytes)
                .array()

            val encodedPayload = Base64.encodeToString(
                combinedPayload,
                Base64.NO_WRAP
            )

            EncryptionResult.Success(encodedPayload)

        } catch (exception: Exception) {

            EncryptionResult.Error(
                message = "Encryption failed.",
                cause = exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Public Decryption API
    // -------------------------------------------------------------------------

    /**
     * Decrypts a previously encrypted Base64 payload.
     *
     * The method extracts:
     *
     *      [IV][Ciphertext + Authentication Tag]
     *
     * and uses the IV to initialize AES-GCM.
     *
     * @param encryptedData Base64 encoded encrypted payload.
     *
     * @return EncryptionResult containing the original plaintext
     *         or an error.
     */
    suspend fun decrypt(
        encryptedData: String
    ): EncryptionResult = withContext(Dispatchers.Default) {

        try {

            require(encryptedData.isNotEmpty()) {
                "Encrypted data cannot be empty."
            }

            val combinedPayload = Base64.decode(
                encryptedData,
                Base64.NO_WRAP
            )

            /**
             * Minimum payload:
             *
             * IV + authentication tag.
             *
             * Actual ciphertext will normally be larger.
             */
            require(combinedPayload.size > IV_SIZE) {
                "Invalid encrypted payload."
            }

            // -----------------------------------------------------------------
            // Extract IV
            // -----------------------------------------------------------------

            val iv = combinedPayload.copyOfRange(
                0,
                IV_SIZE
            )

            // -----------------------------------------------------------------
            // Extract ciphertext + authentication tag
            // -----------------------------------------------------------------

            val encryptedBytes = combinedPayload.copyOfRange(
                IV_SIZE,
                combinedPayload.size
            )

            generateKeyIfNeeded()

            val secretKey = getSecretKey()

            val cipher = Cipher.getInstance(TRANSFORMATION)

            val gcmParameterSpec = GCMParameterSpec(
                GCM_TAG_LENGTH,
                iv
            )

            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                gcmParameterSpec
            )

            /**
             * AES-GCM automatically verifies the authentication tag.
             *
             * If the data has been modified, Cipher.doFinal()
             * will throw an authentication-related exception.
             */
            val decryptedBytes = cipher.doFinal(
                encryptedBytes
            )

            val plainText = String(
                decryptedBytes,
                Charsets.UTF_8
            )

            EncryptionResult.Success(plainText)

        } catch (exception: Exception) {

            EncryptionResult.Error(
                message = "Decryption failed.",
                cause = exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Key Management
    // -------------------------------------------------------------------------

    /**
     * Generates the SentriX master encryption key if it does not already exist.
     *
     * The key is generated inside Android Keystore and marked for:
     *
     * - Encryption
     * - Decryption
     *
     * The raw key material cannot be directly exported from Keystore.
     */
    private fun generateKeyIfNeeded() {

        if (keyStore.containsAlias(KEY_ALIAS)) {
            return
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or
                    KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(KEY_SIZE)
            .setBlockModes(
                KeyProperties.BLOCK_MODE_GCM
            )
            .setEncryptionPaddings(
                KeyProperties.ENCRYPTION_PADDING_NONE
            )
            .setRandomizedEncryptionRequired(true)
            .build()

        keyGenerator.init(keyGenParameterSpec)

        keyGenerator.generateKey()
    }

    /**
     * Retrieves the SentriX master encryption key.
     *
     * The actual AES key material remains protected by Android Keystore.
     *
     * @throws IllegalStateException if the key cannot be retrieved.
     */
    private fun getSecretKey(): SecretKey {

        val entry = keyStore.getEntry(
            KEY_ALIAS,
            null
        )

        require(entry is KeyStore.SecretKeyEntry) {
            "SentriX encryption key is unavailable."
        }

        return entry.secretKey
    }

    // -------------------------------------------------------------------------
    // Key Status
    // -------------------------------------------------------------------------

    /**
     * Checks whether the SentriX encryption key currently exists.
     *
     * Useful for:
     * - Security diagnostics
     * - Device integrity checks
     * - Application startup checks
     * - Security health reports
     */
    fun isEncryptionKeyAvailable(): Boolean {
        return try {
            keyStore.containsAlias(KEY_ALIAS)
        } catch (exception: Exception) {
            false
        }
    }

    /**
     * Ensures that the SentriX encryption key exists.
     *
     * This can be called during application initialization.
     */
    fun initialize() {
        try {
            generateKeyIfNeeded()
        } catch (exception: Exception) {
            throw IllegalStateException(
                "Unable to initialize SentriX encryption.",
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Key Deletion
    // -------------------------------------------------------------------------

    /**
     * Deletes the SentriX master encryption key.
     *
     * WARNING:
     *
     * Any data encrypted with this key becomes permanently
     * undecryptable after the key is deleted.
     *
     * Therefore this method should NOT normally be called during
     * ordinary application execution.
     *
     * It may be useful for:
     *
     * - Secure logout
     * - Application reset
     * - Enterprise device wipe
     * - Security incident response
     */
    fun deleteEncryptionKey() {

        try {

            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }

        } catch (exception: Exception) {

            throw IllegalStateException(
                "Unable to delete SentriX encryption key.",
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Utility Operations
    // -------------------------------------------------------------------------

    /**
     * Encrypts a nullable value.
     *
     * Null remains null.
     *
     * Useful when encryption is applied to optional database fields.
     */
    suspend fun encryptNullable(
        value: String?
    ): EncryptionResult? {

        return value?.let {
            encrypt(it)
        }
    }

    /**
     * Decrypts a nullable value.
     *
     * Null remains null.
     */
    suspend fun decryptNullable(
        value: String?
    ): EncryptionResult? {

        return value?.let {
            decrypt(it)
        }
    }
}

/**
 * Result wrapper for encryption and decryption operations.
 *
 * Keeping encryption failures inside a typed result prevents callers
 * from having to handle cryptographic exceptions directly.
 */
sealed class EncryptionResult {

    /**
     * Successful encryption/decryption operation.
     */
    data class Success(
        val data: String
    ) : EncryptionResult()

    /**
     * Failed encryption/decryption operation.
     *
     * @param message Safe user/developer-facing error description.
     * @param cause Original exception for diagnostics/logging.
     *
     * IMPORTANT:
     * Never expose the raw exception message directly to end users
     * because cryptographic/provider errors may reveal implementation
     * details.
     */
    data class Error(
        val message: String,
        val cause: Throwable? = null
    ) : EncryptionResult()
}
