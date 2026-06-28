package com.sentrix.data.remote.interceptors

import com.sentrix.core.constants.NetworkConstants
import com.sentrix.core.managers.DeviceInfoManager
import com.sentrix.core.managers.SessionManager
import okhttp3.Interceptor
import okhttp3.Response
import timber.log.Timber
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * -----------------------------------------------------------------------------
 * SecurityHeaderInterceptor
 * -----------------------------------------------------------------------------
 *
 * Enterprise-grade interceptor responsible for attaching security-related
 * headers to every outgoing network request.
 *
 * In SentriX, additional metadata is sent to the backend to:
 *
 * • Strengthen API security
 * • Improve threat detection accuracy
 * • Enable device trust validation
 * • Correlate requests for auditing
 * • Support zero-trust architecture
 * • Detect replay attacks
 * • Assist incident investigation
 *
 * Typical headers added:
 *
 * - Device identifier
 * - Session identifier
 * - Request identifier
 * - Application version
 * - Operating system version
 * - Device model
 * - Platform information
 * - Timestamp
 * - Request nonce
 *
 * Security Benefits:
 *
 * • Backend can validate device legitimacy.
 * • Every request becomes traceable.
 * • Duplicate/replayed requests can be detected.
 * • Security analytics gain additional context.
 *
 * Example:
 *
 * X-Request-Id: 95d47eec-8f2e-43b6-aaf5-64f1c71d4e5d
 * X-Request-Timestamp: 1719589000000
 * X-Nonce: f8d1b2e9f24b41f4
 * X-Device-Id: android-123456
 * X-Platform: Android
 *
 * @property sessionManager Provides session-related information.
 * @property deviceInfoManager Provides device metadata.
 */
@Singleton
class SecurityHeaderInterceptor @Inject constructor(
    private val sessionManager: SessionManager,
    private val deviceInfoManager: DeviceInfoManager
) : Interceptor {

    /**
     * Intercepts requests and appends security metadata headers.
     *
     * @param chain Current interceptor chain.
     *
     * @return Network response.
     */
    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()

        // Unique identifier for tracing a single request.
        val requestId = UUID.randomUUID().toString()

        // Current UTC timestamp in milliseconds.
        val timestamp = System.currentTimeMillis().toString()

        // Random nonce used to mitigate replay attacks.
        val nonce = generateNonce()

        val securedRequest = originalRequest.newBuilder()

            // -----------------------------------------------------------------
            // Request Correlation Headers
            // -----------------------------------------------------------------
            .addHeader(
                NetworkConstants.Headers.REQUEST_ID,
                requestId
            )
            .addHeader(
                NetworkConstants.Headers.REQUEST_TIMESTAMP,
                timestamp
            )
            .addHeader(
                NetworkConstants.Headers.REQUEST_NONCE,
                nonce
            )

            // -----------------------------------------------------------------
            // Device Trust Headers
            // -----------------------------------------------------------------
            .addHeader(
                NetworkConstants.Headers.DEVICE_ID,
                deviceInfoManager.getDeviceId()
            )
            .addHeader(
                NetworkConstants.Headers.DEVICE_MODEL,
                deviceInfoManager.getDeviceModel()
            )
            .addHeader(
                NetworkConstants.Headers.DEVICE_BRAND,
                deviceInfoManager.getDeviceBrand()
            )
            .addHeader(
                NetworkConstants.Headers.OS_VERSION,
                deviceInfoManager.getOsVersion()
            )
            .addHeader(
                NetworkConstants.Headers.APP_VERSION,
                deviceInfoManager.getAppVersion()
            )

            // -----------------------------------------------------------------
            // Platform Headers
            // -----------------------------------------------------------------
            .addHeader(
                NetworkConstants.Headers.PLATFORM,
                PLATFORM_ANDROID
            )
            .addHeader(
                NetworkConstants.Headers.APP_BUILD_NUMBER,
                deviceInfoManager.getBuildNumber()
            )

            .apply {

                // Optional session headers.
                sessionManager.getSessionId()?.let {
                    addHeader(
                        NetworkConstants.Headers.SESSION_ID,
                        it
                    )
                }

                sessionManager.getUserId()?.let {
                    addHeader(
                        NetworkConstants.Headers.USER_ID,
                        it
                    )
                }
            }

            .build()

        Timber.v(
            """
            SecurityHeaderInterceptor:
            Request ID  : $requestId
            Timestamp   : $timestamp
            Device ID   : ${deviceInfoManager.getDeviceId()}
            URL         : ${securedRequest.url}
            """.trimIndent()
        )

        return chain.proceed(securedRequest)
    }

    /**
     * Generates a random nonce value.
     *
     * A nonce is a one-time-use random token that helps
     * backend systems identify replayed requests.
     *
     * @return Random nonce string.
     */
    private fun generateNonce(): String {
        return UUID.randomUUID()
            .toString()
            .replace("-", "")
    }

    companion object {

        /**
         * Platform identifier used by SentriX backend.
         */
        private const val PLATFORM_ANDROID = "Android"
    }
}
