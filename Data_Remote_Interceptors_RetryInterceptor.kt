package com.sentrix.data.remote.interceptors

import kotlinx.coroutines.delay
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import timber.log.Timber
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.pow

/**
 * -----------------------------------------------------------------------------
 * RetryInterceptor
 * -----------------------------------------------------------------------------
 *
 * Enterprise-grade interceptor responsible for automatically retrying failed
 * network requests.
 *
 * In real-world mobile applications, requests may fail because of:
 *
 * • Temporary network interruptions
 * • Slow internet connectivity
 * • Server overload
 * • Gateway timeout errors
 * • Rate limiting
 * • DNS failures
 * • Connection reset exceptions
 *
 * This interceptor improves reliability by retrying requests using an
 * exponential backoff strategy.
 *
 * Example retry sequence:
 *
 * Attempt 1 -> Immediate
 * Attempt 2 -> Wait 2 seconds
 * Attempt 3 -> Wait 4 seconds
 * Attempt 4 -> Wait 8 seconds
 *
 * Features:
 * • Configurable retry count
 * • Exponential backoff
 * • Selective retry based on HTTP status codes
 * • Network exception retry support
 * • Detailed logging
 *
 * NOTE:
 * Retry should generally be applied only to idempotent requests
 * such as GET, HEAD and OPTIONS.
 *
 * @property maxRetryCount Maximum retry attempts.
 * @property initialDelayMillis Initial backoff delay.
 */
@Singleton
class RetryInterceptor @Inject constructor() : Interceptor {

    /**
     * Intercepts requests and retries them when appropriate.
     *
     * @param chain Current interceptor chain.
     *
     * @return Successful response or final failure response.
     */
    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        /*
         * Avoid retrying non-idempotent requests unless explicitly allowed.
         */
        if (!isRetryAllowed(request)) {
            return chain.proceed(request)
        }

        var currentAttempt = 0
        var response: Response? = null
        var lastException: IOException? = null

        while (currentAttempt <= MAX_RETRY_COUNT) {

            try {

                response?.close()

                Timber.d(
                    "RetryInterceptor -> Attempt ${currentAttempt + 1} " +
                            "for ${request.method} ${request.url}"
                )

                response = chain.proceed(request)

                /*
                 * Success response received.
                 */
                if (response.isSuccessful) {

                    Timber.d(
                        "RetryInterceptor -> Request succeeded on " +
                                "attempt ${currentAttempt + 1}"
                    )

                    return response
                }

                /*
                 * Retry only retryable status codes.
                 */
                if (!shouldRetry(response.code)) {

                    Timber.d(
                        "RetryInterceptor -> No retry required " +
                                "for HTTP ${response.code}"
                    )

                    return response
                }

                Timber.w(
                    "RetryInterceptor -> HTTP ${response.code}. " +
                            "Retrying..."
                )

            } catch (exception: IOException) {

                lastException = exception

                Timber.e(
                    exception,
                    "RetryInterceptor -> Network error on " +
                            "attempt ${currentAttempt + 1}"
                )
            }

            /*
             * No more retries left.
             */
            if (currentAttempt == MAX_RETRY_COUNT) {
                break
            }

            performBackoff(currentAttempt)

            currentAttempt++
        }

        Timber.e(
            "RetryInterceptor -> Exhausted all retries."
        )

        response?.let { return it }

        throw lastException ?: IOException(
            "Network request failed after retries."
        )
    }

    /**
     * Determines whether retry logic should be applied.
     *
     * Generally only safe HTTP methods are retried.
     */
    private fun isRetryAllowed(request: Request): Boolean {

        return request.method.uppercase() in SAFE_HTTP_METHODS
    }

    /**
     * Determines whether the given HTTP status code
     * is eligible for retry.
     *
     * Retryable responses:
     * - 408 Request Timeout
     * - 429 Too Many Requests
     * - 500 Internal Server Error
     * - 502 Bad Gateway
     * - 503 Service Unavailable
     * - 504 Gateway Timeout
     */
    private fun shouldRetry(code: Int): Boolean {

        return code in RETRYABLE_HTTP_CODES
    }

    /**
     * Performs exponential backoff.
     *
     * Formula:
     *
     * delay = baseDelay * 2 ^ attempt
     */
    private fun performBackoff(attempt: Int) {

        val delayMillis =
            (INITIAL_BACKOFF_DELAY_MS *
                    BACKOFF_MULTIPLIER.pow(attempt.toDouble()))
                .toLong()

        Timber.d(
            "RetryInterceptor -> Waiting ${delayMillis}ms " +
                    "before retry."
        )

        try {
            Thread.sleep(delayMillis)
        } catch (exception: InterruptedException) {

            Timber.e(
                exception,
                "RetryInterceptor -> Backoff interrupted."
            )

            Thread.currentThread().interrupt()
        }
    }

    companion object {

        /**
         * Maximum retry attempts.
         *
         * Example:
         * MAX_RETRY_COUNT = 3
         *
         * Total executions:
         * Initial request + 3 retries = 4 attempts.
         */
        private const val MAX_RETRY_COUNT = 3

        /**
         * Initial delay before first retry.
         */
        private const val INITIAL_BACKOFF_DELAY_MS = 2_000L

        /**
         * Exponential multiplier.
         */
        private const val BACKOFF_MULTIPLIER = 2.0

        /**
         * Safe methods that can be retried.
         */
        private val SAFE_HTTP_METHODS = setOf(
            "GET",
            "HEAD",
            "OPTIONS"
        )

        /**
         * Retryable HTTP status codes.
         */
        private val RETRYABLE_HTTP_CODES = setOf(
            408, // Request Timeout
            429, // Too Many Requests
            500, // Internal Server Error
            502, // Bad Gateway
            503, // Service Unavailable
            504  // Gateway Timeout
        )
    }
}
