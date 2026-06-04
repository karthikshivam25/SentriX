package com.sentrix.core.managers

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * EncryptionManager
 *
 * Responsibilities:
 * - AES-256 encryption/decryption
 * - Android Keystore integration
 * - Secure key generation
 * - String encryption utilities
 * - Secure data protection
 *
 * Encryption Mode:
 * AES/GCM/NoPadding
 */
object EncryptionManager {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "SentriX_Master_Key"

    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128

    init {
        generateKeyIfNeeded()
    }

    /**
     * Encrypt text.
     */
    suspend fun encrypt(
        plainText: String
    ): EncryptionResult = withContext(Dispatchers.Default) {

        try {

            val cipher = Cipher.getInstance(AES_MODE)

            cipher.init(
                Cipher.ENCRYPT_MODE,
                getSecretKey()
            )

            val iv = cipher.iv

            val encryptedBytes = cipher.doFinal(
                plainText.toByteArray(StandardCharsets.UTF_8)
            )

            val combined = iv + encryptedBytes

            EncryptionResult.Success(
                Base64.encodeToString(
                    combined,
                    Base64.NO_WRAP
                )
            )

        } catch (e: Exception) {
            EncryptionResult.Error(
                e.message ?: "Encryption failed"
            )
        }
    }

    /**
     * Decrypt text.
     */
    suspend fun decrypt(
        encryptedText: String
    ): EncryptionResult = withContext(Dispatchers.Default) {

        try {

            val combined = Base64.decode(
                encryptedText,
                Base64.NO_WRAP
            )

            val iv = combined.copyOfRange(0, 12)
            val cipherBytes = combined.copyOfRange(
                12,
                combined.size
            )

            val cipher = Cipher.getInstance(AES_MODE)

            cipher.init(
                Cipher.DECRYPT_MODE,
                getSecretKey(),
                GCMParameterSpec(
                    GCM_TAG_LENGTH,
                    iv
                )
            )

            val decrypted = cipher.doFinal(cipherBytes)

            EncryptionResult.Success(
                String(
                    decrypted,
                    StandardCharsets.UTF_8
                )
            )

        } catch (e: Exception) {
            EncryptionResult.Error(
                e.message ?: "Decryption failed"
            )
        }
    }

    /**
     * Check if encryption key exists.
     */
    fun isKeyAvailable(): Boolean {

        val keyStore = KeyStore.getInstance(
            ANDROID_KEYSTORE
        )

        keyStore.load(null)

        return keyStore.containsAlias(KEY_ALIAS)
    }

    /**
     * Delete existing key.
     */
    fun deleteKey(): Boolean {

        return try {

            val keyStore = KeyStore.getInstance(
                ANDROID_KEYSTORE
            )

            keyStore.load(null)

            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }

            true

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Generate key if missing.
     */
    private fun generateKeyIfNeeded() {

        if (isKeyAvailable()) return

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or
                    KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(
                KeyProperties.BLOCK_MODE_GCM
            )
            .setEncryptionPaddings(
                KeyProperties.ENCRYPTION_PADDING_NONE
            )
            .setKeySize(256)
            .build()

        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }

    /**
     * Retrieve keystore secret key.
     */
    private fun getSecretKey(): SecretKey {

        val keyStore = KeyStore.getInstance(
            ANDROID_KEYSTORE
        )

        keyStore.load(null)

        val secretKeyEntry =
            keyStore.getEntry(
                KEY_ALIAS,
                null
            ) as KeyStore.SecretKeyEntry

        return secretKeyEntry.secretKey
    }

    /**
     * Encryption result wrapper.
     */
    sealed class EncryptionResult {

        data class Success(
            val data: String
        ) : EncryptionResult()

        data class Error(
            val message: String
        ) : EncryptionResult()
    }
}
