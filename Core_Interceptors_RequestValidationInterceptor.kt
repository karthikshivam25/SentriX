package com.sentrix.core.interceptors

import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for validating outgoing requests
 * before they are sent to remote servers.
 *
 * Validation includes:
 * - URL validation
 * - HTTP method validation
 * - Header validation
 * - Request body validation
 */
@Singleton
class RequestValidationInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        validateRequest(request)

        return chain.proceed(request)
    }

    /**
     * Performs request validation.
     */
    private fun validateRequest(
        request: okhttp3.Request
    ) {

        validateUrl(request)

        validateMethod(request)

        validateHeaders(request)

        validateBody(request)
    }

    /**
     * Validates request URL.
     */
    private fun validateUrl(
        request: okhttp3.Request
    ) {

        val url = request.url.toString()

        require(url.isNotBlank()) {
            "Request URL cannot be empty."
        }

        require(
            url.startsWith("https://")
        ) {
            "Only HTTPS endpoints are allowed."
        }
    }

    /**
     * Validates HTTP method.
     */
    private fun validateMethod(
        request: okhttp3.Request
    ) {

        val allowedMethods = setOf(
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "HEAD",
            "OPTIONS"
        )

        require(
            request.method.uppercase() in allowedMethods
        ) {
            "Unsupported HTTP method: ${request.method}"
        }
    }

    /**
     * Validates mandatory headers.
     */
    private fun validateHeaders(
        request: okhttp3.Request
    ) {

        val userAgent =
            request.header("User-Agent")

        require(
            !userAgent.isNullOrBlank()
        ) {
            "Missing User-Agent header."
        }
    }

    /**
     * Validates request body when required.
     */
    private fun validateBody(
        request: okhttp3.Request
    ) {

        val methodsRequiringBody = setOf(
            "POST",
            "PUT",
            "PATCH"
        )

        if (
            request.method.uppercase() in methodsRequiringBody &&
            request.body == null
        ) {
            throw IllegalArgumentException(
                "Request body required for ${request.method}."
            )
        }
    }
}

/**
 * Exception thrown when request validation fails.
 */
class RequestValidationException(
    message: String,
    cause: Throwable? = null
) : IllegalArgumentException(message, cause)
