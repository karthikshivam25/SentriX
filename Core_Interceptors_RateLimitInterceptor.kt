package com.sentrix.core.interceptors

import okhttp3.Interceptor
import okhttp3.Response
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for basic client-side rate limiting.
 *
 * Helps prevent excessive API calls and reduces the risk
 * of accidental request flooding.
 */
@Singleton
class RateLimitInterceptor @Inject constructor() : Interceptor {

    private val requestCounter = AtomicInteger(0)

    @Volatile
    private var windowStartTime: Long = System.currentTimeMillis()

    override fun intercept(chain: Interceptor.Chain): Response {

        synchronized(this) {

            val currentTime = System.currentTimeMillis()

            // Reset window if expired
            if (currentTime - windowStartTime >= WINDOW_DURATION_MS) {
                windowStartTime = currentTime
                requestCounter.set(0)
            }

            val currentCount = requestCounter.incrementAndGet()

            if (currentCount > MAX_REQUESTS_PER_WINDOW) {
                throw RateLimitExceededException(
                    "Rate limit exceeded. Maximum $MAX_REQUESTS_PER_WINDOW requests allowed every ${WINDOW_DURATION_MS / 1000} seconds."
                )
            }
        }

        return chain.proceed(chain.request())
    }

    companion object {

        /**
         * Maximum requests allowed during a time window.
         */
        private const val MAX_REQUESTS_PER_WINDOW = 100

        /**
         * Window duration in milliseconds.
         */
        private const val WINDOW_DURATION_MS = 60_000L // 1 minute
    }
}

/**
 * Exception thrown when rate limits are exceeded.
 */
class RateLimitExceededException(
    message: String
) : RuntimeException(message)
