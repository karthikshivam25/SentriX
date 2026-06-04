package com.sentrix.core.validators

import com.sentrix.core.exceptions.InvalidTokenException
import com.sentrix.core.exceptions.RequiredFieldException
import java.util.Base64

/**
 * TokenValidator
 *
 * Responsibilities:
 * - Access token validation
 * - JWT structure verification
 * - Length validation
 * - Expiration checks
 * - Token masking and analysis
 */
object TokenValidator {

    private const val MIN_TOKEN_LENGTH = 16
    private const val MAX_TOKEN_LENGTH = 4096

    /**
     * Validate token.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidTokenException::class
    )
    fun validate(
        token: String?
    ): Boolean {

        if (token.isNullOrBlank()) {
            throw RequiredFieldException(
                "Token"
            )
        }

        val normalizedToken =
            token.trim()

        if (
            normalizedToken.length <
            MIN_TOKEN_LENGTH
        ) {
            throw InvalidTokenException(
                "Token is too short."
            )
        }

        if (
            normalizedToken.length >
            MAX_TOKEN_LENGTH
        ) {
            throw InvalidTokenException(
                "Token exceeds maximum length."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        token: String?
    ): Boolean {

        return try {

            validate(token)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check JWT format.
     */
    fun isJwt(
        token: String
    ): Boolean {

        return token.split(".")
            .size == 3
    }

    /**
     * Decode JWT payload.
     */
    fun decodeJwtPayload(
        token: String
    ): String? {

        return try {

            if (!isJwt(token)) {
                return null
            }

            val payload =
                token.split(".")[1]

            String(
                Base64.getUrlDecoder()
                    .decode(payload)
            )

        } catch (_: Exception) {
            null
        }
    }

    /**
     * Check Bearer token.
     */
    fun isBearerToken(
        token: String
    ): Boolean {

        return token.startsWith(
            "Bearer ",
            ignoreCase = true
        )
    }

    /**
     * Extract Bearer token value.
     */
    fun extractBearerToken(
        token: String
    ): String {

        return token.removePrefix(
            "Bearer "
        ).trim()
    }

    /**
     * Get token type.
     */
    fun getTokenType(
        token: String
    ): String {

        return when {

            isJwt(token) ->
                "JWT"

            isBearerToken(token) ->
                "Bearer"

            else ->
                "Generic"
        }
    }

    /**
     * Mask token.
     */
    fun maskToken(
        token: String
    ): String {

        if (
            token.length <= 8
        ) {
            return "*".repeat(
                token.length
            )
        }

        return token.take(4) +
                "*".repeat(
                    token.length - 8
                ) +
                token.takeLast(4)
    }
}
