package com.sentrix.core.validators

import android.util.Patterns
import com.sentrix.core.exceptions.InvalidURLException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * URLValidator
 *
 * Responsibilities:
 * - URL format validation
 * - HTTP/HTTPS verification
 * - Domain extraction
 * - URL normalization
 * - Security checks
 */
object URLValidator {

    private const val MAX_URL_LENGTH = 2048

    /**
     * Validate URL.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidURLException::class
    )
    fun validate(
        url: String?
    ): Boolean {

        if (url.isNullOrBlank()) {
            throw RequiredFieldException(
                "URL"
            )
        }

        val normalizedUrl =
            url.trim()

        if (
            normalizedUrl.length >
            MAX_URL_LENGTH
        ) {
            throw InvalidURLException(
                "URL exceeds maximum length."
            )
        }

        if (
            !Patterns.WEB_URL.matcher(
                normalizedUrl
            ).matches()
        ) {
            throw InvalidURLException(
                "Invalid URL format."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        url: String?
    ): Boolean {

        return try {

            validate(url)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Normalize URL.
     */
    fun normalize(
        url: String
    ): String {

        return url.trim()
    }

    /**
     * Check HTTPS.
     */
    fun isSecure(
        url: String
    ): Boolean {

        return url.lowercase()
            .startsWith("https://")
    }

    /**
     * Extract domain.
     */
    fun getDomain(
        url: String
    ): String? {

        return try {

            val cleanUrl =
                if (
                    url.startsWith(
                        "http://"
                    ) ||
                    url.startsWith(
                        "https://"
                    )
                ) {
                    url
                } else {
                    "https://$url"
                }

            java.net.URI(
                cleanUrl
            ).host
                ?.removePrefix("www.")

        } catch (_: Exception) {
            null
        }
    }

    /**
     * Check IP-based URL.
     */
    fun isIPAddressUrl(
        url: String
    ): Boolean {

        val domain =
            getDomain(url)
                ?: return false

        return domain.matches(
            Regex(
                "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$)){4}$"
            )
        )
    }

    /**
     * Check localhost URL.
     */
    fun isLocalhost(
        url: String
    ): Boolean {

        val domain =
            getDomain(url)
                ?: return false

        return domain.equals(
            "localhost",
            ignoreCase = true
        )
    }

    /**
     * Mask URL for display.
     */
    fun maskUrl(
        url: String
    ): String {

        val domain =
            getDomain(url)
                ?: return url

        return "***.$domain"
    }
}
