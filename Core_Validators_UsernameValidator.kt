package com.sentrix.core.validators

import com.sentrix.core.exceptions.InvalidUsernameException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * UsernameValidator
 *
 * Responsibilities:
 * - Username validation
 * - Length verification
 * - Character restrictions
 * - Username normalization
 * - Reserved username checks
 */
object UsernameValidator {

    private const val MIN_USERNAME_LENGTH = 3
    private const val MAX_USERNAME_LENGTH = 30

    private val RESERVED_USERNAMES = setOf(
        "admin",
        "administrator",
        "root",
        "system",
        "support",
        "security",
        "sentrix",
        "owner",
        "superuser",
        "guest"
    )

    /**
     * Validate username.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidUsernameException::class
    )
    fun validate(
        username: String?
    ): Boolean {

        if (username.isNullOrBlank()) {
            throw RequiredFieldException(
                "Username"
            )
        }

        val normalizedUsername =
            username.trim()

        if (
            normalizedUsername.length <
            MIN_USERNAME_LENGTH
        ) {
            throw InvalidUsernameException(
                "Username is too short."
            )
        }

        if (
            normalizedUsername.length >
            MAX_USERNAME_LENGTH
        ) {
            throw InvalidUsernameException(
                "Username exceeds maximum length."
            )
        }

        if (
            !normalizedUsername.matches(
                Regex(
                    "^[a-zA-Z0-9_.]+$"
                )
            )
        ) {
            throw InvalidUsernameException(
                "Username contains invalid characters."
            )
        }

        if (
            RESERVED_USERNAMES.contains(
                normalizedUsername.lowercase()
            )
        ) {
            throw InvalidUsernameException(
                "Username is reserved."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        username: String?
    ): Boolean {

        return try {

            validate(username)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Normalize username.
     */
    fun normalize(
        username: String
    ): String {

        return username
            .trim()
            .lowercase()
    }

    /**
     * Check if username is reserved.
     */
    fun isReserved(
        username: String
    ): Boolean {

        return RESERVED_USERNAMES.contains(
            username.lowercase()
        )
    }

    /**
     * Check if username is numeric only.
     */
    fun isNumericOnly(
        username: String
    ): Boolean {

        return username.matches(
            Regex("^\\d+$")
        )
    }

    /**
     * Check if username contains special characters.
     */
    fun containsSpecialCharacters(
        username: String
    ): Boolean {

        return username.any {
            !it.isLetterOrDigit() &&
                    it != '_' &&
                    it != '.'
        }
    }

    /**
     * Generate suggested username.
     */
    fun generateSuggestion(
        username: String
    ): String {

        val base =
            normalize(username)
                .replace(
                    Regex("[^a-z0-9_.]"),
                    ""
                )

        return "$base${(1000..9999).random()}"
    }

    /**
     * Mask username.
     */
    fun maskUsername(
        username: String
    ): String {

        if (
            username.length <= 2
        ) {
            return "*".repeat(
                username.length
            )
        }

        return username.first() +
                "*".repeat(
                    username.length - 2
                ) +
                username.last()
    }
}
