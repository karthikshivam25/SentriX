package com.sentrix.core.extensions

import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encryption Extensions
 * SentriX Core Module
 *
 * NOTE:
 * - Uses AES/GCM/NoPadding for authenticated encryption.
 * - Suitable for local data protection.
 * - For highly sensitive secrets, prefer Android Keystore.
 */

private const val AES_KEY_SIZE = 256
private const val GCM_TAG_LENGTH = 128
private const val GCM_IV_LENGTH = 12
private const val PBKDF2_ITERATIONS = 100_000

/* -------------------------------------------------------------------------
 * Hashing
 * ------------------------------------------------------------------------- */

fun String.sha256(): String {
    val digest = MessageDigest
        .getInstance("SHA-256")
        .digest(toByteArray())

    return digest.joinToString("") {
        "%02x".format(it)
    }
}

fun String.sha512(): String {
    val digest = MessageDigest
        .getInstance("SHA-512")
        .digest(toByteArray())

    return digest.joinToString("") {
        "%02x".format(it)
    }
}

/* -------------------------------------------------------------------------
 * Base64 Helpers
 * ------------------------------------------------------------------------- */

fun String.toBase64(): String {
    return Base64.encodeToString(
        toByteArray(StandardCharsets.UTF_8),
        Base64.NO_WRAP
    )
}

fun String.fromBase64(): String {
    return String(
        Base64.decode(this, Base64.NO_WRAP),
        StandardCharsets.UTF_8
    )
}

/* -------------------------------------------------------------------------
 * AES Key Helpers
 * ------------------------------------------------------------------------- */

fun generateAesKey(): SecretKey {
    val generator = KeyGenerator.getInstance("AES")
    generator.init(AES_KEY_SIZE)
    return generator.generateKey()
}

fun ByteArray.toSecretKey(): SecretKey {
    return SecretKeySpec(this, "AES")
}

fun SecretKey.toBase64Key(): String {
    return Base64.encodeToString(
        encoded,
        Base64.NO_WRAP
    )
}

fun String.toSecretKey(): SecretKey {
    val decoded = Base64.decode(
        this,
        Base64.NO_WRAP
    )
    return SecretKeySpec(decoded, "AES")
}

/* -------------------------------------------------------------------------
 * Password-Based Key Derivation
 * ------------------------------------------------------------------------- */

fun String.deriveAesKey(
    salt: ByteArray,
    iterations: Int = PBKDF2_ITERATIONS
): SecretKey {

    val spec = PBEKeySpec(
        this.toCharArray(),
        salt,
        iterations,
        AES_KEY_SIZE
    )

    val factory = SecretKeyFactory.getInstance(
        "PBKDF2WithHmacSHA256"
    )

    val keyBytes = factory
        .generateSecret(spec)
        .encoded

    return SecretKeySpec(
        keyBytes,
        "AES"
    )
}

/* -------------------------------------------------------------------------
 * Salt & IV Helpers
 * ------------------------------------------------------------------------- */

fun generateSalt(
    size: Int = 16
): ByteArray {
    return ByteArray(size).apply {
        SecureRandom().nextBytes(this)
    }
}

fun generateIv(): ByteArray {
    return ByteArray(GCM_IV_LENGTH).apply {
        SecureRandom().nextBytes(this)
    }
}

/* -------------------------------------------------------------------------
 * AES-GCM Encryption
 * ------------------------------------------------------------------------- */

fun String.encrypt(
    secretKey: SecretKey
): String {

    val iv = generateIv()

    val cipher = Cipher.getInstance(
        "AES/GCM/NoPadding"
    )

    cipher.init(
        Cipher.ENCRYPT_MODE,
        secretKey,
        GCMParameterSpec(
            GCM_TAG_LENGTH,
            iv
        )
    )

    val encrypted = cipher.doFinal(
        toByteArray(StandardCharsets.UTF_8)
    )

    val combined = iv + encrypted

    return Base64.encodeToString(
        combined,
        Base64.NO_WRAP
    )
}

fun String.decrypt(
    secretKey: SecretKey
): String {

    val combined = Base64.decode(
        this,
        Base64.NO_WRAP
    )

    val iv = combined.copyOfRange(
        0,
        GCM_IV_LENGTH
    )

    val encrypted = combined.copyOfRange(
        GCM_IV_LENGTH,
        combined.size
    )

    val cipher = Cipher.getInstance(
        "AES/GCM/NoPadding"
    )

    cipher.init(
        Cipher.DECRYPT_MODE,
        secretKey,
        GCMParameterSpec(
            GCM_TAG_LENGTH,
            iv
        )
    )

    val decrypted = cipher.doFinal(
        encrypted
    )

    return String(
        decrypted,
        StandardCharsets.UTF_8
    )
}

/* -------------------------------------------------------------------------
 * Safe Encryption Helpers
 * ------------------------------------------------------------------------- */

fun String.encryptOrNull(
    secretKey: SecretKey
): String? {
    return runCatching {
        encrypt(secretKey)
    }.getOrNull()
}

fun String.decryptOrNull(
    secretKey: SecretKey
): String? {
    return runCatching {
        decrypt(secretKey)
    }.getOrNull()
}

/* -------------------------------------------------------------------------
 * ByteArray Helpers
 * ------------------------------------------------------------------------- */

fun ByteArray.toHexString(): String {
    return joinToString("") {
        "%02x".format(it)
    }
}

fun String.hexToByteArray(): ByteArray {
    return chunked(2)
        .map {
            it.toInt(16).toByte()
        }
        .toByteArray()
}

/* -------------------------------------------------------------------------
 * Integrity Helpers
 * ------------------------------------------------------------------------- */

fun ByteArray.sha256(): String {
    val digest = MessageDigest
        .getInstance("SHA-256")
        .digest(this)

    return digest.joinToString("") {
        "%02x".format(it)
    }
}

fun ByteArray.sha512(): String {
    val digest = MessageDigest
        .getInstance("SHA-512")
        .digest(this)

    return digest.joinToString("") {
        "%02x".format(it)
    }
}

/* -------------------------------------------------------------------------
 * Security Validation
 * ------------------------------------------------------------------------- */

fun String.isStrongPassword(): Boolean {

    val hasUpper = any { it.isUpperCase() }
    val hasLower = any { it.isLowerCase() }
    val hasDigit = any { it.isDigit() }
    val hasSpecial = any {
        !it.isLetterOrDigit()
    }

    return length >= 12 &&
            hasUpper &&
            hasLower &&
            hasDigit &&
            hasSpecial
}

/* -------------------------------------------------------------------------
 * Secure Comparison
 * ------------------------------------------------------------------------- */

fun String.secureEquals(
    other: String
): Boolean {

    if (length != other.length) {
        return false
    }

    var result = 0

    for (i in indices) {
        result = result or
                (this[i].code xor other[i].code)
    }

    return result == 0
}
