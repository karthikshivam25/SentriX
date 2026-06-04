package com.sentrix.core.interceptors

import android.util.Log
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for processing and validating
 * incoming HTTP responses.
 */
@Singleton
class ResponseInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        val response = chain.proceed(request)

        validateResponse(response)

        logResponse(response)

        return response
    }

    /**
     * Validates server response.
     */
    private fun validateResponse(
        response: Response
    ) {

        when (response.code) {

            200,
            201,
            202,
            204 -> {
                // Successful responses
            }

            400 -> throw ResponseException(
                "Bad Request (400)"
            )

            401 -> throw ResponseException(
                "Unauthorized (401)"
            )

            403 -> throw ResponseException(
                "Forbidden (403)"
            )

            404 -> throw ResponseException(
                "Resource Not Found (404)"
            )

            408 -> throw ResponseException(
                "Request Timeout (408)"
            )

            429 -> throw ResponseException(
                "Too Many Requests (429)"
            )

            in 500..599 -> throw ResponseException(
                "Server Error (${response.code})"
            )

            else -> {
                if (!response.isSuccessful) {
                    throw ResponseException(
                        "Unexpected Response (${response.code})"
                    )
                }
            }
        }
    }

    /**
     * Logs response metadata.
     */
    private fun logResponse(
        response: Response
    ) {

        Log.d(
            TAG,
            """
            Response Received
            -------------------------
            URL       : ${response.request.url}
            Code      : ${response.code}
            Message   : ${response.message}
            Success   : ${response.isSuccessful}
            Protocol  : ${response.protocol}
            """.trimIndent()
        )
    }

    companion object {
        private const val TAG = "SentriX-Response"
    }
}

/**
 * Exception thrown when a response fails validation.
 */
class ResponseException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)
