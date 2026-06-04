package com.sentrix.core.interceptors

import android.util.Log
import okhttp3.Interceptor
import okhttp3.Response
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.min

/**
 * Interceptor responsible for automatically retrying
 * failed network requests using exponential backoff.
 */
@Singleton
class RetryInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        var retryCount = 0
        var lastException: IOException? = null

        while (retryCount <= MAX_RETRIES) {

            try {

                val response = chain.proceed(request)

                if (shouldRetry(response.code) &&
                    retryCount < MAX_RETRIES
                ) {

                    response.close()

                    retryCount++

                    val delayMillis = calculateBackoffDelay(retryCount)

                    Log.w(
                        TAG,
                        "Retrying request (${retryCount}/$MAX_RETRIES) " +
                                "after HTTP ${response.code}"
                    )

                    Thread.sleep(delayMillis)

                    continue
                }

                return response

            } catch (exception: IOException) {

                lastException = exception

                if (retryCount >= MAX_RETRIES) {
                    break
                }

                retryCount++

                val delayMillis = calculateBackoffDelay(retryCount)

                Log.w(
                    TAG,
                    "Network failure. Retrying request " +
                            "(${retryCount}/$MAX_RETRIES)",
                    exception
                )

                Thread.sleep(delayMillis)
            }
        }

        throw RetryException(
            message = "Request failed after $MAX_RETRIES retry attempts.",
            cause = lastException
        )
    }

    /**
     * Determines whether the response code
     * is eligible for retry.
     */
    private fun shouldRetry(
        responseCode: Int
    ): Boolean {
        return responseCode == 408 || // Request Timeout
                responseCode == 429 || // Too Many Requests
                responseCode in 500..599 // Server Errors
    }

    /**
     * Calculates exponential backoff delay.
     */
    private fun calculateBackoffDelay(
        retryCount: Int
    ): Long {

        val delay =
            INITIAL_BACKOFF_MS * (1L shl (retryCount - 1))

        return min(delay, MAX_BACKOFF_MS)
    }

    companion object {

        private const val TAG = "SentriX-Retry"

        /**
         * Maximum retry attempts.
         */
        private const val MAX_RETRIES = 3

        /**
         * Initial retry delay.
         */
        private const val INITIAL_BACKOFF_MS = 1_000L

        /**
         * Maximum retry delay.
         */
        private const val MAX_BACKOFF_MS = 10_000L
    }
}

/**
 * Exception thrown when all retry attempts fail.
 */
class RetryException(
    message: String,
    cause: Throwable? = null
) : IOException(message, cause)
