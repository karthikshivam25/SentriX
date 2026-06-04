package com.sentrix.core.interceptors

import okhttp3.Interceptor
import okhttp3.Response
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for attaching security-related headers
 * and validating outgoing requests.
 */
@Singleton
class SecurityInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()

        val securedRequest = originalRequest.newBuilder()
            .addHeader("X-Request-ID", generateRequestId())
            .addHeader("X-Client-Type", "Android")
            .addHeader("X-App-Name", "SentriX")
            .addHeader("X-Security-Version", SECURITY_VERSION)
            .addHeader("X-Timestamp", System.currentTimeMillis().toString())
            .build()

        return chain.proceed(securedRequest)
    }

    /**
     * Generates a unique request identifier.
     */
    private fun generateRequestId(): String {
        return UUID.randomUUID().toString()
    }

    companion object {
        private const val SECURITY_VERSION = "1.0"
    }
}
