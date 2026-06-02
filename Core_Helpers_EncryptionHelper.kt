package com.sentrix.core.helpers

import android.util.Base64
import com.sentrix.core.enums.EncryptionMode
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Helper class for encryption, decryption, hashing,
 * and secure key generation in SentriX
 */
object EncryptionHelper {

    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val AES_KEY_SIZE = 256
    private const val GCM_TAG_LENGTH = 128
    private const val IV_SIZE = 12

    /**
     * Generates secure AES secret key
     */
    fun generateAESKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(AES_KEY_SIZE)
        return keyGenerator.generateKey()
    }

    /**
     * Encrypt text using AES-GCM
     */
    fun encryptAES(
        plainText: String,
        secretKey: SecretKey
    ): Pair<String, String> {

        val cipher = Cipher.getInstance(AES_MODE)

        val iv = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(iv)

        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val encryptedBytes = cipher.doFinal(
            plainText.toByteArray(StandardCharsets.UTF_8)
        )

        return Pair(
            Base64.encodeToString(encryptedBytes, Base64.DEFAULT),
            Base64.encodeToString(iv, Base64.DEFAULT)
        )
    }

    /**
     * Decrypt AES-GCM encrypted text
     */
    fun decryptAES(
        encryptedText: String,
        iv: String,
        secretKey: SecretKey
    ): String {

        val cipher = Cipher.getInstance(AES_MODE)

        val gcmSpec = GCMParameterSpec(
            GCM_TAG_LENGTH,
            Base64.decode(iv, Base64.DEFAULT)
        )

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val decryptedBytes = cipher.doFinal(
            Base64.decode(encryptedText, Base64.DEFAULT)
        )

        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    /**
     * Generate RSA key pair
     */
    fun generateRSAKeyPair(
        keySize: Int = 2048
    ): java.security.KeyPair {

        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)

        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Encrypt data using RSA public key
     */
    fun encryptRSA(
        plainText: String,
        publicKey: PublicKey
    ): String {

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")

        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val encryptedBytes = cipher.doFinal(
            plainText.toByteArray(StandardCharsets.UTF_8)
        )

        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    /**
     * Decrypt RSA encrypted data
     */
    fun decryptRSA(
        encryptedText: String,
        privateKey: PrivateKey
    ): String {

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")

        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        val decryptedBytes = cipher.doFinal(
            Base64.decode(encryptedText, Base64.DEFAULT)
        )

        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    /**
     * Generate SHA-256 hash
     */
    fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(
            input.toByteArray(StandardCharsets.UTF_8)
        )

        return hashBytes.joinToString("") {
            "%02x".format(it)
        }
    }

    /**
     * Generate SHA-512 hash
     */
    fun sha512(input: String): String {
        val digest = MessageDigest.getInstance("SHA-512")
        val hashBytes = digest.digest(
            input.toByteArray(StandardCharsets.UTF_8)
        )

        return hashBytes.joinToString("") {
            "%02x".format(it)
        }
    }

    /**
     * Convert raw bytes into AES SecretKey
     */
    fun secretKeyFromBytes(bytes: ByteArray): SecretKey {
        return SecretKeySpec(bytes, "AES")
    }

    /**
     * Convert Base64 string to PublicKey
     */
    fun publicKeyFromString(key: String): PublicKey {

        val decodedKey = Base64.decode(key, Base64.DEFAULT)

        val spec = X509EncodedKeySpec(decodedKey)

        return KeyFactory.getInstance("RSA")
            .generatePublic(spec)
    }

    /**
     * Convert Base64 string to PrivateKey
     */
    fun privateKeyFromString(key: String): PrivateKey {

        val decodedKey = Base64.decode(key, Base64.DEFAULT)

        val spec = PKCS8EncodedKeySpec(decodedKey)

        return KeyFactory.getInstance("RSA")
            .generatePrivate(spec)
    }

    /**
     * Returns recommended encryption mode
     */
    fun getRecommendedMode(): EncryptionMode {
        return EncryptionMode.AES_256
    }

    /**
     * Checks whether encryption mode is secure
     */
    fun isSecureMode(mode: EncryptionMode): Boolean {
        return mode.isRecommended()
    }
}
