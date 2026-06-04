package com.sentrix.core.extensions

import android.util.Base64
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Security Extensions
 * SentriX Core Module
 *
 * Centralized security utilities for:
 * - Hashing
 * - File Integrity Verification
 * - Certificate Validation
 * - Threat Scoring
 * - Secure Random Generation
 * - Malware Signature Checks
 * - HMAC Verification
 */

/* -------------------------------------------------------------------------
 * Hashing Helpers
 * ------------------------------------------------------------------------- */

fun String.sha1(): String =
    MessageDigest.getInstance("SHA-1")
        .digest(toByteArray())
        .joinToString("") { "%02x".format(it) }

fun String.sha256(): String =
    MessageDigest.getInstance("SHA-256")
        .digest(toByteArray())
        .joinToString("") { "%02x".format(it) }

fun String.sha512(): String =
    MessageDigest.getInstance("SHA-512")
        .digest(toByteArray())
        .joinToString("") { "%02x".format(it) }

fun ByteArray.sha256(): String =
    MessageDigest.getInstance("SHA-256")
        .digest(this)
        .joinToString("") { "%02x".format(it) }

/* -------------------------------------------------------------------------
 * HMAC Helpers
 * ------------------------------------------------------------------------- */

fun String.hmacSha256(
    secret: String
): String {

    val mac = Mac.getInstance("HmacSHA256")

    val keySpec = SecretKeySpec(
        secret.toByteArray(),
        "HmacSHA256"
    )

    mac.init(keySpec)

    return mac.doFinal(
        toByteArray()
    ).joinToString("") {
        "%02x".format(it)
    }
}

fun String.verifyHmacSha256(
    secret: String,
    expectedHash: String
): Boolean {

    return hmacSha256(secret)
        .equals(expectedHash, ignoreCase = true)
}

/* -------------------------------------------------------------------------
 * Base64 Security Helpers
 * ------------------------------------------------------------------------- */

fun String.toBase64Safe(): String {
    return Base64.encodeToString(
        toByteArray(),
        Base64.NO_WRAP
    )
}

fun String.fromBase64Safe(): String {
    return String(
        Base64.decode(this, Base64.NO_WRAP)
    )
}

/* -------------------------------------------------------------------------
 * Secure Random Helpers
 * ------------------------------------------------------------------------- */

fun generateSecureToken(
    length: Int = 32
): String {

    val bytes = ByteArray(length)

    SecureRandom().nextBytes(bytes)

    return bytes.joinToString("") {
        "%02x".format(it)
    }
}

fun generateNonce(
    length: Int = 16
): ByteArray {

    return ByteArray(length).apply {
        SecureRandom().nextBytes(this)
    }
}

/* -------------------------------------------------------------------------
 * Password Strength Validation
 * ------------------------------------------------------------------------- */

fun String.passwordStrengthScore(): Int {

    var score = 0

    if (length >= 8) score += 20
    if (length >= 12) score += 20
    if (any { it.isUpperCase() }) score += 20
    if (any { it.isLowerCase() }) score += 20
    if (any { it.isDigit() }) score += 10
    if (any { !it.isLetterOrDigit() }) score += 10

    return score.coerceAtMost(100)
}

fun String.passwordStrengthLabel(): String {
    return when (passwordStrengthScore()) {
        in 90..100 -> "Excellent"
        in 75..89 -> "Strong"
        in 50..74 -> "Moderate"
        in 25..49 -> "Weak"
        else -> "Very Weak"
    }
}

fun String.isStrongPassword(): Boolean {
    return passwordStrengthScore() >= 75
}

/* -------------------------------------------------------------------------
 * Threat Scoring Helpers
 * ------------------------------------------------------------------------- */

fun Int.toThreatLevel(): String {
    return when {
        this >= 90 -> "Critical"
        this >= 75 -> "High"
        this >= 50 -> "Medium"
        this >= 25 -> "Low"
        else -> "Safe"
    }
}

fun Int.isCriticalThreat(): Boolean {
    return this >= 90
}

/* -------------------------------------------------------------------------
 * Malware Signature Helpers
 * ------------------------------------------------------------------------- */

fun String.matchesMalwareSignature(
    signatures: Collection<String>
): Boolean {

    val hash = sha256()

    return signatures.any {
        it.equals(hash, true)
    }
}

fun File.matchesMalwareSignature(
    signatures: Collection<String>
): Boolean {

    val hash = MessageDigest
        .getInstance("SHA-256")
        .digest(readBytes())
        .joinToString("") {
            "%02x".format(it)
        }

    return signatures.any {
        it.equals(hash, true)
    }
}

/* -------------------------------------------------------------------------
 * File Integrity Verification
 * ------------------------------------------------------------------------- */

fun File.verifySha256(
    expectedHash: String
): Boolean {

    val actualHash =
        MessageDigest
            .getInstance("SHA-256")
            .digest(readBytes())
            .joinToString("") {
                "%02x".format(it)
            }

    return actualHash.equals(
        expectedHash,
        ignoreCase = true
    )
}

fun File.verifyMd5(
    expectedHash: String
): Boolean {

    val actualHash =
        MessageDigest
            .getInstance("MD5")
            .digest(readBytes())
            .joinToString("") {
                "%02x".format(it)
            }

    return actualHash.equals(
        expectedHash,
        ignoreCase = true
    )
}

/* -------------------------------------------------------------------------
 * Certificate Helpers
 * ------------------------------------------------------------------------- */

fun ByteArray.toX509Certificate(): X509Certificate? {
    return try {

        val factory =
            CertificateFactory.getInstance("X.509")

        factory.generateCertificate(
            inputStream()
        ) as X509Certificate

    } catch (_: Exception) {
        null
    }
}

fun X509Certificate.isExpired(): Boolean {
    return try {
        checkValidity()
        false
    } catch (_: Exception) {
        true
    }
}

fun X509Certificate.daysUntilExpiry(): Long {

    val diff =
        notAfter.time - System.currentTimeMillis()

    return diff / (1000L * 60 * 60 * 24)
}

/* -------------------------------------------------------------------------
 * Security Score Helpers
 * ------------------------------------------------------------------------- */

fun calculateSecurityScore(
    permissionsRisk: Int,
    malwareRisk: Int,
    networkRisk: Int,
    rootRisk: Int
): Int {

    val score =
        100 -
                permissionsRisk -
                malwareRisk -
                networkRisk -
                rootRisk

    return score.coerceIn(0, 100)
}

fun Int.securityStatus(): String {
    return when {
        this >= 90 -> "Protected"
        this >= 75 -> "Secure"
        this >= 50 -> "Moderate Risk"
        this >= 25 -> "High Risk"
        else -> "Critical Risk"
    }
}

/* -------------------------------------------------------------------------
 * Security Event Helpers
 * ------------------------------------------------------------------------- */

fun String.containsSuspiciousKeyword(): Boolean {

    val keywords = setOf(
        "trojan",
        "malware",
        "spyware",
        "ransomware",
        "rootkit",
        "keylogger",
        "payload",
        "backdoor",
        "exploit",
        "inject"
    )

    return keywords.any {
        contains(it, ignoreCase = true)
    }
}

fun Collection<String>.countSuspiciousEntries(): Int {
    return count {
        it.containsSuspiciousKeyword()
    }
}

/* -------------------------------------------------------------------------
 * Secure Comparison
 * ------------------------------------------------------------------------- */

fun String.secureCompare(
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

/* -------------------------------------------------------------------------
 * Security Reporting
 * ------------------------------------------------------------------------- */

fun Int.toSecurityReportSummary(): String {

    return when {
        this >= 90 ->
            "Device security status is excellent."

        this >= 75 ->
            "Device security status is good."

        this >= 50 ->
            "Some security improvements are recommended."

        this >= 25 ->
            "Security risks detected."

        else ->
            "Critical security threats detected."
    }
}
