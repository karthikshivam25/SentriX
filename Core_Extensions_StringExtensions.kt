package com.sentrix.core.extensions

import android.util.Patterns
import java.security.MessageDigest
import java.text.DecimalFormat
import java.util.Locale

/**
 * String Extensions
 * SentriX Core Module
 */

/**
 * Null or Empty Checks
 */
fun String?.isNullOrEmptySafe(): Boolean {
    return this == null || this.trim().isEmpty()
}

fun String?.isNotNullOrEmptySafe(): Boolean {
    return !this.isNullOrEmptySafe()
}

/**
 * Capitalization
 */
fun String.capitalizeFirst(): String {
    return replaceFirstChar {
        if (it.isLowerCase()) {
            it.titlecase(Locale.getDefault())
        } else {
            it.toString()
        }
    }
}

fun String.capitalizeWords(): String {
    return split(" ")
        .joinToString(" ") { word ->
            word.lowercase()
                .replaceFirstChar { char ->
                    char.titlecase(Locale.getDefault())
                }
        }
}

/**
 * Validation
 */
fun String.isValidEmail(): Boolean {
    return Patterns.EMAIL_ADDRESS.matcher(this).matches()
}

fun String.isValidUrl(): Boolean {
    return Patterns.WEB_URL.matcher(this).matches()
}

fun String.isNumeric(): Boolean {
    return matches(Regex("^\\d+$"))
}

fun String.isAlphaNumeric(): Boolean {
    return matches(Regex("^[a-zA-Z0-9]+$"))
}

fun String.containsSpecialCharacter(): Boolean {
    return matches(Regex(".*[^a-zA-Z0-9 ].*"))
}

/**
 * Security Helpers
 */
fun String.toMD5(): String {
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest(toByteArray())

    return digest.joinToString("") {
        "%02x".format(it)
    }
}

fun String.toSHA256(): String {
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(toByteArray())

    return digest.joinToString("") {
        "%02x".format(it)
    }
}

/**
 * Masking
 */
fun String.maskEmail(): String {
    val parts = split("@")

    if (parts.size != 2) return this

    val username = parts[0]
    val domain = parts[1]

    val maskedUser = when {
        username.length <= 2 -> "*".repeat(username.length)
        else -> username.take(2) + "*".repeat(username.length - 2)
    }

    return "$maskedUser@$domain"
}

fun String.maskPhone(): String {
    return if (length >= 4) {
        "*".repeat(length - 4) + takeLast(4)
    } else {
        this
    }
}

/**
 * Formatting
 */
fun String.removeSpaces(): String {
    return replace(" ", "")
}

fun String.removeNewLines(): String {
    return replace("\n", "")
        .replace("\r", "")
}

fun String.truncate(maxLength: Int): String {
    return if (length > maxLength) {
        take(maxLength) + "..."
    } else {
        this
    }
}

fun String.toTitleCase(): String {
    return lowercase()
        .split(" ")
        .joinToString(" ") {
            it.replaceFirstChar { char ->
                char.titlecase(Locale.getDefault())
            }
        }
}

/**
 * Conversion Helpers
 */
fun String.toIntOrZero(): Int {
    return toIntOrNull() ?: 0
}

fun String.toLongOrZero(): Long {
    return toLongOrNull() ?: 0L
}

fun String.toDoubleOrZero(): Double {
    return toDoubleOrNull() ?: 0.0
}

fun String.toFloatOrZero(): Float {
    return toFloatOrNull() ?: 0f
}

/**
 * Byte Size Formatting
 */
fun Long.toReadableFileSize(): String {
    if (this <= 0) return "0 B"

    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var size = this.toDouble()
    var index = 0

    while (size >= 1024 && index < units.lastIndex) {
        size /= 1024
        index++
    }

    return "${DecimalFormat("#,##0.#").format(size)} ${units[index]}"
}

/**
 * String Utilities
 */
fun String.reverseText(): String {
    return reversed()
}

fun String.onlyDigits(): String {
    return filter { it.isDigit() }
}

fun String.onlyLetters(): String {
    return filter { it.isLetter() }
}

fun String.wordCount(): Int {
    return trim()
        .split("\\s+".toRegex())
        .filter { it.isNotBlank() }
        .size
}

fun String.isPalindrome(): Boolean {
    val cleaned = lowercase()
        .replace("\\s".toRegex(), "")

    return cleaned == cleaned.reversed()
}

/**
 * Malware / Threat Analysis Helpers
 */
fun String.containsSuspiciousKeywords(): Boolean {

    val suspiciousKeywords = listOf(
        "hack",
        "exploit",
        "payload",
        "trojan",
        "malware",
        "ransomware",
        "spyware",
        "keylogger",
        "phishing",
        "backdoor"
    )

    return suspiciousKeywords.any {
        lowercase().contains(it)
    }
}

/**
 * Hex Helpers
 */
fun String.isHexString(): Boolean {
    return matches(Regex("^[0-9A-Fa-f]+$"))
}

/**
 * UUID Validation
 */
fun String.isUUID(): Boolean {
    return matches(
        Regex(
            "^[0-9a-fA-F]{8}-" +
                    "[0-9a-fA-F]{4}-" +
                    "[0-9a-fA-F]{4}-" +
                    "[0-9a-fA-F]{4}-" +
                    "[0-9a-fA-F]{12}$"
        )
    )
}
