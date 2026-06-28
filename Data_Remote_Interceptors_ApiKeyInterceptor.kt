package com.sentrix.data.remote.interceptors

import com.sentrix.core.constants.NetworkConstants
import com.sentrix.core.managers.ApiKeyManager
import okhttp3.Interceptor
import okhttp3.Response
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * -----------------------------------------------------------------------------
 * ApiKeyInterceptor
 * -----------------------------------------------------------------------------
 *
 * OkHttp interceptor responsible for attaching API keys and additional
 * service-specific authentication headers to outgoing requests.
 *
 * In SentriX Enterprise Architecture, some backend services or third-party
 * providers may require dedicated API keys instead of user authentication.
 *
 * Examples:
 * - Threat Intelligence APIs
 * - URL Reputation Services
 * - Malware Analysis Providers
 * - Cloud AI Scanning Engines
 * - Device Trust Services
 *
 * Responsibilities:
 * - Add API key headers to requests.
 * - Support multiple API providers.
 * - Skip API key injection for excluded endpoints.
 * - Centralize API key management.
 * - Prevent duplication across repositories.
 *
 * Security Notes:
 * - API keys should NEVER be hardcoded.
 * - Keys should be retrieved securely from:
 *      • Encrypted local storage
 *      • Remote configuration
 *      • Secure backend provisioning
 *      • Android Keystore-backed storage
 *
 * Registration:
 *
 * ```
 * OkHttpClient.Builder()
 *      .addInterceptor(apiKeyInterceptor)
 * ```
 *
 * @property apiKeyManager Provides secure access to API credentials.
 */
@Singleton
class ApiKeyInterceptor @Inject constructor(
    private val apiKeyManager: ApiKeyManager
) : Interceptor {

    /**
     * Intercepts outgoing requests and injects API key headers when required.
     *
     * @param chain Current interceptor chain.
     *
     * @return Network response.
     */
    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()
        val requestUrl = originalRequest.url.toString()

        /*
         * Some endpoints such as login, health-check,
         * or public configuration endpoints may not require
         * API key authentication.
         */
        if (shouldSkipApiKey(requestUrl)) {
            Timber.d("ApiKeyInterceptor: Skipping API key injection.")
            return chain.proceed(originalRequest)
        }

        val requestBuilder = originalRequest.newBuilder()

        // ---------------------------------------------------------------------
        // SentriX Internal API Key
        // ---------------------------------------------------------------------

        apiKeyManager.getPrimaryApiKey()?.let { apiKey ->

            requestBuilder.addHeader(
                NetworkConstants.Headers.API_KEY,
                apiKey
            )

            Timber.d("ApiKeyInterceptor: Primary API key attached.")
        }

        // ---------------------------------------------------------------------
        // Threat Intelligence Provider Key
        // ---------------------------------------------------------------------

        apiKeyManager.getThreatIntelApiKey()?.let { apiKey ->

            requestBuilder.addHeader(
                NetworkConstants.Headers.THREAT_API_KEY,
                apiKey
            )

            Timber.d("ApiKeyInterceptor: Threat Intelligence API key attached.")
        }

        // ---------------------------------------------------------------------
        // AI Analysis Engine Key
        // ---------------------------------------------------------------------

        apiKeyManager.getAiEngineApiKey()?.let { apiKey ->

            requestBuilder.addHeader(
                NetworkConstants.Headers.AI_ENGINE_API_KEY,
                apiKey
            )

            Timber.d("ApiKeyInterceptor: AI Engine API key attached.")
        }

        // ---------------------------------------------------------------------
        // Malware Intelligence Service Key
        // ---------------------------------------------------------------------

        apiKeyManager.getMalwareApiKey()?.let { apiKey ->

            requestBuilder.addHeader(
                NetworkConstants.Headers.MALWARE_API_KEY,
                apiKey
            )

            Timber.d("ApiKeyInterceptor: Malware API key attached.")
        }

        // ---------------------------------------------------------------------
        // Optional Request Metadata
        // ---------------------------------------------------------------------

        requestBuilder.addHeader(
            NetworkConstants.Headers.CLIENT_NAME,
            "SentriX-Android"
        )

        requestBuilder.addHeader(
            NetworkConstants.Headers.CLIENT_VERSION,
            apiKeyManager.getClientVersion()
        )

        val securedRequest = requestBuilder.build()

        Timber.v(
            "ApiKeyInterceptor -> ${securedRequest.method} ${securedRequest.url}"
        )

        return chain.proceed(securedRequest)
    }

    /**
     * Determines whether the current endpoint should bypass
     * API key injection.
     *
     * Typical examples:
     * - Login endpoints
     * - Registration endpoints
     * - Public configuration APIs
     * - Health-check endpoints
     *
     * @param url Full request URL.
     *
     * @return True if API key injection should be skipped.
     */
    private fun shouldSkipApiKey(url: String): Boolean {

        return EXCLUDED_ENDPOINTS.any { endpoint ->
            url.contains(endpoint, ignoreCase = true)
        }
    }

    companion object {

        /**
         * Public endpoints that do not require API keys.
         */
        private val EXCLUDED_ENDPOINTS = listOf(
            "/auth/login",
            "/auth/register",
            "/health",
            "/status",
            "/public",
            "/config"
        )
    }
}
