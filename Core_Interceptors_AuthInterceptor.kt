package com.sentrix.core.interceptors

import com.sentrix.core.managers.SessionManager
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for attaching authentication headers
 * to all outgoing API requests.
 */
@Singleton
class AuthInterceptor @Inject constructor(
    private val sessionManager: SessionManager
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()

        val token = sessionManager.getAccessToken()

        val requestBuilder = originalRequest.newBuilder()
            .addHeader("Accept", "application/json")
            .addHeader("Content-Type", "application/json")

        if (!token.isNullOrBlank()) {
            requestBuilder.addHeader(
                "Authorization",
                "Bearer $token"
            )
        }

        val authenticatedRequest = requestBuilder.build()

        return chain.proceed(authenticatedRequest)
    }
}
