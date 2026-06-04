package com.sentrix.core.validators

import com.sentrix.core.exceptions.InvalidInputException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * InputValidator
 *
 * Responsibilities:
 * - Generic input validation
 * - Null/empty checks
 * - Length validation
 * - Character validation
 * - Sanitization support
 */
object InputValidator {

    private const val DEFAULT_MIN_LENGTH = 1
    private const val DEFAULT_MAX_LENGTH = 255

    /**
     * Validate input.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidInputException::class
    )
    fun validate(
        input: String?,
        fieldName: String = "Input",
        minLength: Int = DEFAULT_MIN_LENGTH,
        maxLength: Int = DEFAULT_MAX_LENGTH
    ): Boolean {

        if (input.isNullOrBlank()) {
            throw RequiredFieldException(
                fieldName
            )
        }

        val normalizedInput =
            input.trim()

        if (
            normalizedInput.length <
            minLength
        ) {
            throw InvalidInputException(
                "$fieldName is too short."
            )
        }

        if (
            normalizedInput.length >
            maxLength
        ) {
            throw InvalidInputException(
                "$fieldName exceeds maximum length."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        input: String?,
        fieldName: String = "Input"
    ): Boolean {

        return try {

            validate(
                input = input,
                fieldName = fieldName
            )

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Sanitize input.
     */
    fun sanitize(
        input: String
    ): String {

        return input
            .trim()
            .replace(
                Regex("\\s+"),
                " "
            )
    }

    /**
     * Check alphanumeric.
     */
    fun isAlphaNumeric(
        input: String
    ): Boolean {

        return input.matches(
            Regex("^[a-zA-Z0-9]+$")
        )
    }

    /**
     * Check alphabetic.
     */
    fun isAlphabetic(
        input: String
    ): Boolean {

        return input.matches(
            Regex("^[a-zA-Z ]+$")
        )
    }

    /**
     * Check numeric.
     */
    fun isNumeric(
        input: String
    ): Boolean {

        return input.matches(
            Regex("^\\d+$")
        )
    }

    /**
     * Check if contains special characters.
     */
    fun containsSpecialCharacters(
        input: String
    ): Boolean {

        return input.matches(
            Regex(".*[^a-zA-Z0-9 ].*")
        )
    }

    /**
     * Remove special characters.
     */
    fun removeSpecialCharacters(
        input: String
    ): String {

        return input.replace(
            Regex("[^a-zA-Z0-9 ]"),
            ""
        )
    }

    /**
     * Mask sensitive input.
     */
    fun mask(
        input: String,
        visibleChars: Int = 2
    ): String {

        if (
            input.length <= visibleChars
        ) {
            return "*".repeat(
                input.length
            )
        }

        return input.take(
            visibleChars
        ) + "*".repeat(
            input.length - visibleChars
        )
    }
}
