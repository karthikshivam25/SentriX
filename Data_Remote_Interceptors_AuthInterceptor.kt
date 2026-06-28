package com.sentrix.data.remote.interceptors

import com.sentrix.core.constants.NetworkConstants
import com.sentrix.core.managers.SessionManager
import okhttp3.Interceptor
import okhttp3.Response
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * -----------------------------------------------------------------------------
 * AuthInterceptor
 * -----------------------------------------------------------------------------
 *
 * OkHttp interceptor responsible for attaching authentication credentials
 * to every outgoing network request.
 *
 * Responsibilities:
 * - Attach JWT/Bearer token to API requests.
 * - Attach common security headers required by SentriX backend.
 * - Ensure all requests contain mandatory metadata.
 * - Centralize authentication header management.
 *
 * Benefits:
 * - Avoids duplicating authorization logic in repositories.
 * - Ensures consistency across all API calls.
 * - Simplifies token rotation and maintenance.
 *
 * Example:
 *
 * Authorization: Bearer eyJhbGciOi...
 * X-Platform: Android
 * X-App-Version: 1.0.0
 *
 * Registered inside OkHttp:
 *
 * ```
 * OkHttpClient.Builder()
 *      .addInterceptor(authInterceptor)
 * ```
 *
 * @property sessionManager Manages authentication and user session data.
 */
@Singleton
class AuthInterceptor @Inject constructor(
    private val sessionManager: SessionManager
) : Interceptor {

    /**
     * Intercepts outgoing requests and injects authentication headers.
     *
     * @param chain Current interceptor chain.
     *
     * @return Modified network response.
     */
    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()

        /*
         * Retrieve latest access token from secure session storage.
         *
         * Token may be stored in:
         * - EncryptedSharedPreferences
         * - DataStore
         * - Keystore-backed storage
         */
        val accessToken = sessionManager.getAccessToken()

        val requestBuilder = originalRequest.newBuilder()

        // ---------------------------------------------------------------------
        // Common Headers
        // ---------------------------------------------------------------------

        requestBuilder.addHeader(
            NetworkConstants.Headers.ACCEPT,
            NetworkConstants.APPLICATION_JSON
        )

        requestBuilder.addHeader(
            NetworkConstants.Headers.CONTENT_TYPE,
            NetworkConstants.APPLICATION_JSON
        )

        requestBuilder.addHeader(
            NetworkConstants.Headers.PLATFORM,
            "Android"
        )

        requestBuilder.addHeader(
            NetworkConstants.Headers.APP_VERSION,
            sessionManager.getAppVersion()
        )

        requestBuilder.addHeader(
            NetworkConstants.Headers.DEVICE_ID,
            sessionManager.getDeviceId()
        )

        // ---------------------------------------------------------------------
        // Authentication Header
        // ---------------------------------------------------------------------

        if (!accessToken.isNullOrBlank()) {

            requestBuilder.addHeader(
                NetworkConstants.Headers.AUTHORIZATION,
                "${NetworkConstants.BEARER_PREFIX}$accessToken"
            )

            Timber.d("AuthInterceptor: Authorization header attached.")
        } else {
            Timber.w("AuthInterceptor: No access token found.")
        }

        // ---------------------------------------------------------------------
        // Additional Security Headers
        // ---------------------------------------------------------------------

        sessionManager.getUserId()?.let { userId ->
            requestBuilder.addHeader(
                NetworkConstants.Headers.USER_ID,
                userId
            )
        }

        sessionManager.getSessionId()?.let { sessionId ->
            requestBuilder.addHeader(
                NetworkConstants.Headers.SESSION_ID,
                sessionId
            )
        }

        /*
         * Build the final secured request.
         */
        val securedRequest = requestBuilder.build()

        Timber.v(
            "Request -> ${securedRequest.method} ${securedRequest.url}"
        )

        return chain.proceed(securedRequest)
    }
}
