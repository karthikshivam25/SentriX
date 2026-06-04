package com.sentrix.core.validators

import com.sentrix.core.exceptions.InvalidPasswordException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * PasswordValidator
 *
 * Responsibilities:
 * - Password strength validation
 * - Minimum/maximum length checks
 * - Complexity requirements
 * - Password scoring
 * - Secure password analysis
 */
object PasswordValidator {

    private const val MIN_LENGTH = 8
    private const val MAX_LENGTH = 128

    /**
     * Validate password.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidPasswordException::class
    )
    fun validate(
        password: String?
    ): Boolean {

        if (password.isNullOrBlank()) {
            throw RequiredFieldException(
                "Password"
            )
        }

        if (
            password.length <
            MIN_LENGTH
        ) {
            throw InvalidPasswordException(
                "Password must contain at least $MIN_LENGTH characters."
            )
        }

        if (
            password.length >
            MAX_LENGTH
        ) {
            throw InvalidPasswordException(
                "Password exceeds maximum length."
            )
        }

        if (
            !password.any { it.isUpperCase() }
        ) {
            throw InvalidPasswordException(
                "Password must contain at least one uppercase letter."
            )
        }

        if (
            !password.any { it.isLowerCase() }
        ) {
            throw InvalidPasswordException(
                "Password must contain at least one lowercase letter."
            )
        }

        if (
            !password.any { it.isDigit() }
        ) {
            throw InvalidPasswordException(
                "Password must contain at least one number."
            )
        }

        if (
            !password.any {
                !it.isLetterOrDigit()
            }
        ) {
            throw InvalidPasswordException(
                "Password must contain at least one special character."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        password: String?
    ): Boolean {

        return try {

            validate(password)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Password strength score.
     */
    fun calculateStrength(
        password: String
    ): Int {

        var score = 0

        if (password.length >= 8) score += 20
        if (password.length >= 12) score += 20
        if (password.any { it.isUpperCase() }) score += 20
        if (password.any { it.isLowerCase() }) score += 10
        if (password.any { it.isDigit() }) score += 15
        if (password.any {
                !it.isLetterOrDigit()
            }
        ) score += 15

        return score.coerceAtMost(100)
    }

    /**
     * Strength label.
     */
    fun getStrengthLabel(
        password: String
    ): String {

        return when (
            calculateStrength(password)
        ) {
            in 0..39 -> "Weak"
            in 40..69 -> "Moderate"
            in 70..89 -> "Strong"
            else -> "Very Strong"
        }
    }

    /**
     * Check common weak passwords.
     */
    fun isCommonPassword(
        password: String
    ): Boolean {

        val commonPasswords = setOf(
            "password",
            "123456",
            "123456789",
            "qwerty",
            "admin",
            "welcome",
            "letmein",
            "password123"
        )

        return commonPasswords.contains(
            password.lowercase()
        )
    }

    /**
     * Check repeated characters.
     */
    fun hasRepeatedCharacters(
        password: String,
        limit: Int = 4
    ): Boolean {

        var count = 1

        for (
            i in 1 until password.length
        ) {

            if (
                password[i] ==
                password[i - 1]
            ) {

                count++

                if (count >= limit) {
                    return true
                }

            } else {
                count = 1
            }
        }

        return false
    }

    /**
     * Mask password length.
     */
    fun maskPassword(
        password: String
    ): String {

        return "*".repeat(
            password.length
        )
    }
}
