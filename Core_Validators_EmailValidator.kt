package com.sentrix.core.validators

import android.util.Patterns
import com.sentrix.core.exceptions.InvalidEmailException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * EmailValidator
 *
 * Responsibilities:
 * - Email format validation
 * - Null/empty checks
 * - Length validation
 * - Domain validation
 * - Normalization
 */
object EmailValidator {

    private const val MIN_EMAIL_LENGTH = 5
    private const val MAX_EMAIL_LENGTH = 254

    /**
     * Validate email.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidEmailException::class
    )
    fun validate(
        email: String?
    ): Boolean {

        if (email.isNullOrBlank()) {
            throw RequiredFieldException("Email")
        }

        val normalizedEmail =
            email.trim()

        if (
            normalizedEmail.length <
            MIN_EMAIL_LENGTH
        ) {
            throw InvalidEmailException(
                "Email is too short."
            )
        }

        if (
            normalizedEmail.length >
            MAX_EMAIL_LENGTH
        ) {
            throw InvalidEmailException(
                "Email exceeds maximum length."
            )
        }

        if (
            !Patterns.EMAIL_ADDRESS.matcher(
                normalizedEmail
            ).matches()
        ) {
            throw InvalidEmailException(
                "Invalid email format."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        email: String?
    ): Boolean {

        return try {

            validate(email)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Normalize email.
     */
    fun normalize(
        email: String
    ): String {

        return email
            .trim()
            .lowercase()
    }

    /**
     * Extract domain.
     */
    fun getDomain(
        email: String
    ): String? {

        return if (
            email.contains("@")
        ) {
            email.substringAfter("@")
        } else {
            null
        }
    }

    /**
     * Check corporate email.
     */
    fun isCorporateEmail(
        email: String
    ): Boolean {

        val domain =
            getDomain(email)
                ?: return false

        val publicDomains = setOf(
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "icloud.com",
            "proton.me",
            "protonmail.com"
        )

        return !publicDomains.contains(
            domain.lowercase()
        )
    }

    /**
     * Check disposable email.
     */
    fun isDisposableEmail(
        email: String
    ): Boolean {

        val domain =
            getDomain(email)
                ?: return false

        val disposableDomains = setOf(
            "mailinator.com",
            "10minutemail.com",
            "temp-mail.org",
            "guerrillamail.com",
            "yopmail.com"
        )

        return disposableDomains.contains(
            domain.lowercase()
        )
    }

    /**
     * Mask email for display.
     */
    fun maskEmail(
        email: String
    ): String {

        val parts =
            email.split("@")

        if (parts.size != 2) {
            return email
        }

        val username =
            parts[0]

        val domain =
            parts[1]

        val maskedUser =
            when {

                username.length <= 2 ->
                    "*".repeat(username.length)

                else ->
                    username.first() +
                            "*".repeat(
                                username.length - 2
                            ) +
                            username.last()
            }

        return "$maskedUser@$domain"
    }
}
