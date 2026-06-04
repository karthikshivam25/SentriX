package com.sentrix.core.validators

import android.util.Patterns
import com.sentrix.core.exceptions.InvalidPhoneException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * PhoneValidator
 *
 * Responsibilities:
 * - Phone number validation
 * - International format support
 * - Length validation
 * - Normalization
 * - Masking and formatting
 */
object PhoneValidator {

    private const val MIN_PHONE_LENGTH = 7
    private const val MAX_PHONE_LENGTH = 15

    /**
     * Validate phone number.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidPhoneException::class
    )
    fun validate(
        phone: String?
    ): Boolean {

        if (phone.isNullOrBlank()) {
            throw RequiredFieldException(
                "Phone Number"
            )
        }

        val normalizedPhone =
            phone.trim()
                .replace(" ", "")
                .replace("-", "")

        if (
            normalizedPhone.length <
            MIN_PHONE_LENGTH
        ) {
            throw InvalidPhoneException(
                "Phone number is too short."
            )
        }

        if (
            normalizedPhone.length >
            MAX_PHONE_LENGTH + 1
        ) {
            throw InvalidPhoneException(
                "Phone number exceeds maximum length."
            )
        }

        if (
            !Patterns.PHONE.matcher(
                normalizedPhone
            ).matches()
        ) {
            throw InvalidPhoneException(
                "Invalid phone number format."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        phone: String?
    ): Boolean {

        return try {

            validate(phone)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Normalize phone number.
     */
    fun normalize(
        phone: String
    ): String {

        return phone
            .trim()
            .replace(" ", "")
            .replace("-", "")
            .replace("(", "")
            .replace(")", "")
    }

    /**
     * Check international number.
     */
    fun isInternational(
        phone: String
    ): Boolean {

        return normalize(phone)
            .startsWith("+")
    }

    /**
     * Extract country code.
     */
    fun getCountryCode(
        phone: String
    ): String? {

        val normalized =
            normalize(phone)

        return if (
            normalized.startsWith("+")
        ) {
            normalized.takeWhile {
                it == '+' || it.isDigit()
            }.take(4)
        } else {
            null
        }
    }

    /**
     * Format phone number.
     */
    fun format(
        phone: String
    ): String {

        return normalize(phone)
    }

    /**
     * Mask phone number.
     */
    fun maskPhone(
        phone: String
    ): String {

        val normalized =
            normalize(phone)

        if (
            normalized.length <= 4
        ) {
            return "*".repeat(
                normalized.length
            )
        }

        return "*".repeat(
            normalized.length - 4
        ) + normalized.takeLast(4)
    }
}
