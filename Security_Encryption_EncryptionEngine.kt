package com.sentrix.security.encryption

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * SentriX Encryption Engine
 *
 * Low-level cryptographic execution engine responsible for:
 *
 * - AES-256-GCM encryption.
 * - AES-256-GCM decryption.
 * - Secure IV generation.
 * - Authentication-tag verification.
 * - Binary payload construction and parsing.
 * - Cryptographic input validation.
 *
 * Architecture:
 *
 *      EncryptionService
 *              │
 *              ▼
 *      EncryptionEngine
 *              │
 *              ▼
 *      EncryptionManager
 *              │
 *              ▼
 *      Android Keystore
 *
 * EncryptionEngine does NOT:
 *
 * - Store encryption keys.
 * - Access databases.
 * - Access SharedPreferences/DataStore.
 * - Perform network operations.
 * - Manage UI state.
 *
 * The SecretKey is supplied by the upper security layer and is used
 * only for the duration of the cryptographic operation.
 *
 * Cryptographic algorithm:
 *
 *      AES-256-GCM
 *
 * Transformation:
 *
 *      AES/GCM/NoPadding
 *
 * IV:
 *
 *      12 bytes
 *
 * Authentication tag:
 *
 *      128 bits
 */
object EncryptionEngine {

    // -------------------------------------------------------------------------
    // Cryptographic Configuration
    // -------------------------------------------------------------------------

    /**
     * AES/GCM transformation.
     *
     * GCM provides authenticated encryption.
     */
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    /**
     * Recommended GCM IV size.
     */
    const val IV_SIZE = 12

    /**
     * Authentication tag size in bits.
     */
    const val GCM_TAG_LENGTH = 128

    /**
     * AES-256 key size in bits.
     *
     * The actual key is managed by Android Keystore through
     * EncryptionManager.
     */
    const val AES_KEY_SIZE = 256

    /**
     * Secure random number generator.
     *
     * Used only when the engine explicitly needs to generate
     * cryptographically secure random values.
     */
    private val secureRandom = SecureRandom()

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts plaintext using AES-GCM.
     *
     * The method generates a fresh cryptographically secure IV
     * for every encryption operation.
     *
     * Payload format:
     *
     *      [IV][Ciphertext + Authentication Tag]
     *
     * The IV is intentionally stored together with the ciphertext.
     * It does not need to be secret.
     *
     * @param plainText Data to encrypt.
     * @param secretKey AES secret key.
     *
     * @return Combined encrypted payload.
     *
     * @throws IllegalArgumentException when input is invalid.
     * @throws IllegalStateException when cryptographic initialization fails.
     */
    fun encrypt(
        plainText: ByteArray,
        secretKey: SecretKey
    ): ByteArray {

        require(plainText.isNotEmpty()) {
            "Plaintext cannot be empty."
        }

        validateSecretKey(secretKey)

        return try {

            val iv = generateIv()

            val cipher = Cipher.getInstance(
                TRANSFORMATION
            )

            val gcmParameterSpec = GCMParameterSpec(
                GCM_TAG_LENGTH,
                iv
            )

            cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                gcmParameterSpec
            )

            val encryptedData = cipher.doFinal(
                plainText
            )

            combineIvAndCiphertext(
                iv = iv,
                encryptedData = encryptedData
            )

        } catch (exception: Exception) {

            throw IllegalStateException(
                "AES-GCM encryption failed.",
                exception
            )
        }
    }

    /**
     * Encrypts a UTF-8 String.
     *
     * Convenience wrapper around the ByteArray encryption method.
     */
    fun encrypt(
        plainText: String,
        secretKey: SecretKey
    ): ByteArray {

        require(plainText.isNotEmpty()) {
            "Plaintext cannot be empty."
        }

        return encrypt(
            plainText = plainText.toByteArray(Charsets.UTF_8),
            secretKey = secretKey
        )
    }

    // -------------------------------------------------------------------------
    // Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypts an AES-GCM payload.
     *
     * The method expects the payload format:
     *
     *      [IV][Ciphertext + Authentication Tag]
     *
     * AES-GCM verifies the authentication tag during doFinal().
     *
     * If the encrypted data has been modified, truncated, or produced
     * using an incorrect key, the operation fails.
     *
     * @param encryptedPayload Combined IV + ciphertext payload.
     * @param secretKey AES secret key.
     *
     * @return Decrypted plaintext.
     */
    fun decrypt(
        encryptedPayload: ByteArray,
        secretKey: SecretKey
    ): ByteArray {

        require(encryptedPayload.isNotEmpty()) {
            "Encrypted payload cannot be empty."
        }

        validateSecretKey(secretKey)

        require(
            encryptedPayload.size >
                    IV_SIZE + authenticationTagSizeInBytes()
        ) {
            "Invalid encrypted payload."
        }

        return try {

            val iv = extractIv(
                encryptedPayload
            )

            val encryptedData = extractCiphertext(
                encryptedPayload
            )

            val cipher = Cipher.getInstance(
                TRANSFORMATION
            )

            val gcmParameterSpec = GCMParameterSpec(
                GCM_TAG_LENGTH,
                iv
            )

            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                gcmParameterSpec
            )

            cipher.doFinal(
                encryptedData
            )

        } catch (exception: Exception) {

            throw SecurityException(
                "AES-GCM decryption or authentication failed.",
                exception
            )
        }
    }

    /**
     * Decrypts a UTF-8 payload and returns a String.
     */
    fun decryptToString(
        encryptedPayload: ByteArray,
        secretKey: SecretKey
    ): String {

        val decryptedBytes = decrypt(
            encryptedPayload = encryptedPayload,
            secretKey = secretKey
        )

        return String(
            decryptedBytes,
            Charsets.UTF_8
        )
    }

    // -------------------------------------------------------------------------
    // IV Generation
    // -------------------------------------------------------------------------

    /**
     * Generates a cryptographically secure AES-GCM IV.
     *
     * GCM security depends heavily on IV uniqueness.
     *
     * NEVER reuse the same IV with the same AES key.
     */
    private fun generateIv(): ByteArray {

        val iv = ByteArray(
            IV_SIZE
        )

        secureRandom.nextBytes(
            iv
        )

        return iv
    }

    // -------------------------------------------------------------------------
    // Payload Construction
    // -------------------------------------------------------------------------

    /**
     * Combines:
     *
     *      IV + ciphertext
     *
     * into one binary payload.
     *
     * The authentication tag is already appended to the ciphertext
     * by the GCM Cipher implementation.
     */
    private fun combineIvAndCiphertext(
        iv: ByteArray,
        encryptedData: ByteArray
    ): ByteArray {

        require(iv.size == IV_SIZE) {
            "Invalid IV size."
        }

        return ByteBuffer
            .allocate(
                iv.size + encryptedData.size
            )
            .put(iv)
            .put(encryptedData)
            .array()
    }

    /**
     * Extracts the IV from an encrypted payload.
     */
    private fun extractIv(
        encryptedPayload: ByteArray
    ): ByteArray {

        require(encryptedPayload.size > IV_SIZE) {
            "Encrypted payload does not contain a valid IV."
        }

        return encryptedPayload.copyOfRange(
            0,
            IV_SIZE
        )
    }

    /**
     * Extracts ciphertext + authentication tag.
     */
    private fun extractCiphertext(
        encryptedPayload: ByteArray
    ): ByteArray {

        require(encryptedPayload.size > IV_SIZE) {
            "Encrypted payload does not contain ciphertext."
        }

        return encryptedPayload.copyOfRange(
            IV_SIZE,
            encryptedPayload.size
        )
    }

    // -------------------------------------------------------------------------
    // Authentication Tag
    // -------------------------------------------------------------------------

    /**
     * Returns authentication tag size in bytes.
     *
     * GCM_TAG_LENGTH is represented in bits by JCA.
     */
    private fun authenticationTagSizeInBytes(): Int {
        return GCM_TAG_LENGTH / Byte.SIZE_BITS
    }

    // -------------------------------------------------------------------------
    // Key Validation
    // -------------------------------------------------------------------------

    /**
     * Validates the supplied SecretKey.
     *
     * The key must:
     *
     * - Exist.
     * - Use AES.
     *
     * Android Keystore-backed keys may intentionally not expose
     * their encoded key material, therefore getEncoded() is NOT
     * used to validate the key.
     */
    private fun validateSecretKey(
        secretKey: SecretKey
    ) {

        require(
            secretKey.algorithm.equals(
                "AES",
                ignoreCase = true
            )
        ) {
            "EncryptionEngine requires an AES SecretKey."
        }
    }

    // -------------------------------------------------------------------------
    // Payload Validation
    // -------------------------------------------------------------------------

    /**
     * Performs structural validation of an encrypted payload.
     *
     * This does NOT prove that the payload is authentic.
     *
     * Authenticity is only established when AES-GCM successfully
     * verifies the authentication tag during decryption.
     */
    fun isValidPayload(
        encryptedPayload: ByteArray
    ): Boolean {

        val minimumSize =
            IV_SIZE + authenticationTagSizeInBytes() + 1

        return encryptedPayload.size >= minimumSize
    }

    /**
     * Validates the IV portion of an encrypted payload.
     */
    fun hasValidIv(
        encryptedPayload: ByteArray
    ): Boolean {

        return encryptedPayload.size >= IV_SIZE &&
                extractIv(encryptedPayload).size == IV_SIZE
    }

    // -------------------------------------------------------------------------
    // Secure Random Data
    // -------------------------------------------------------------------------

    /**
     * Generates cryptographically secure random bytes.
     *
     * Useful for security components that require random values.
     *
     * Examples:
     *
     * - Security challenges
     * - Nonces
     * - Temporary tokens
     * - Random identifiers
     *
     * This method should NOT be used as a replacement for
     * Android Keystore key generation.
     */
    fun generateSecureRandomBytes(
        size: Int
    ): ByteArray {

        require(size > 0) {
            "Random byte size must be greater than zero."
        }

        return ByteArray(size).also {
            secureRandom.nextBytes(it)
        }
    }

    /**
     * Generates a cryptographically secure random Long.
     *
     * This method avoids using java.util.Random for security-sensitive
     * random generation.
     */
    fun generateSecureRandomLong(): Long {

        val bytes = ByteArray(
            Long.SIZE_BYTES
        )

        secureRandom.nextBytes(
            bytes
        )

        return ByteBuffer
            .wrap(bytes)
            .long
    }
}
