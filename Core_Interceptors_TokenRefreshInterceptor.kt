package com.sentrix.core.interceptors

import com.sentrix.core.managers.SessionManager
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for automatically refreshing
 * expired access tokens when a 401 Unauthorized response is received.
 */
@Singleton
class TokenRefreshInterceptor @Inject constructor(
    private val sessionManager: SessionManager
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()

        var response = chain.proceed(originalRequest)

        if (response.code != HTTP_UNAUTHORIZED) {
            return response
        }

        synchronized(this) {

            val currentToken = sessionManager.getAccessToken()

            val requestToken = extractToken(originalRequest)

            // Another request may have already refreshed the token
            if (!currentToken.isNullOrBlank() &&
                currentToken != requestToken
            ) {
                response.close()

                return chain.proceed(
                    originalRequest.withAccessToken(currentToken)
                )
            }

            val refreshedToken = try {
                sessionManager.refreshAccessToken()
            } catch (exception: Exception) {
                null
            }

            if (refreshedToken.isNullOrBlank()) {
                sessionManager.clearSession()
                return response
            }

            sessionManager.saveAccessToken(refreshedToken)

            response.close()

            return chain.proceed(
                originalRequest.withAccessToken(refreshedToken)
            )
        }
    }

    /**
     * Extracts bearer token from request headers.
     */
    private fun extractToken(
        request: Request
    ): String? {
        return request.header(AUTHORIZATION_HEADER)
            ?.removePrefix(BEARER_PREFIX)
            ?.trim()
    }

    /**
     * Creates a copy of request with updated token.
     */
    private fun Request.withAccessToken(
        token: String
    ): Request {
        return newBuilder()
            .header(
                AUTHORIZATION_HEADER,
                "$BEARER_PREFIX$token"
            )
            .build()
    }

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val AUTHORIZATION_HEADER = "Authorization"
        private const val BEARER_PREFIX = "Bearer "
    }
}
