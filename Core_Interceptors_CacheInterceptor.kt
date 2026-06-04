package com.sentrix.core.interceptors

import okhttp3.CacheControl
import okhttp3.Interceptor
import okhttp3.Response
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for applying cache policies
 * to network requests and responses.
 *
 * Features:
 * - Offline cache support
 * - Configurable cache duration
 * - Reduced network usage
 * - Improved response times
 */
@Singleton
class CacheInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        val response = chain.proceed(request)

        val cacheControl = CacheControl.Builder()
            .maxAge(CACHE_DURATION_MINUTES, TimeUnit.MINUTES)
            .build()

        return response.newBuilder()
            .header(
                HEADER_CACHE_CONTROL,
                cacheControl.toString()
            )
            .removeHeader(HEADER_PRAGMA)
            .build()
    }

    companion object {

        /**
         * Cache duration for successful responses.
         */
        private const val CACHE_DURATION_MINUTES = 10

        private const val HEADER_CACHE_CONTROL = "Cache-Control"

        private const val HEADER_PRAGMA = "Pragma"
    }
}
