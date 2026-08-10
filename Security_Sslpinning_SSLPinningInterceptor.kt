package com.sentrix.security.sslpinning

import okhttp3.Interceptor
import okhttp3.Response
import java.io.IOException

/**
 * SSLPinningInterceptor
 *
 * OkHttp interceptor used by SentriX to enforce application-level
 * SSL pinning policy and provide consistent pinning failure
 * reporting.
 *
 * IMPORTANT:
 *
 * The interceptor does NOT manually validate certificates.
 *
 * Actual certificate/public-key pin verification is performed by
 * OkHttp's CertificatePinner during the TLS handshake.
 *
 * This interceptor is responsible for:
 *
 * - Enforcing SentriX pinning policy before network execution.
 * - Detecting whether the destination hostname is configured.
 * - Preventing accidental unpinned requests when pinning is mandatory.
 * - Recording request-level pinning metadata.
 * - Converting pinning failures into SentriX exceptions.
 *
 * Architecture:
 *
 * SentriX Repository
 *        ↓
 * OkHttpClient
 *        ↓
 * SSLPinningInterceptor
 *        ↓
 * TLS / CertificatePinner
 *        ↓
 * HTTPS Server
 *
 * DO NOT use this interceptor to implement custom TrustManager
 * logic or to disable normal TLS validation.
 */
class SSLPinningInterceptor(
    private val pinningManager: SSLPinningManager,
    private val configuration:
        SSLPinningInterceptorConfiguration =
        SSLPinningInterceptorConfiguration()
) : Interceptor {

    /**
     * Intercepts an outgoing HTTP request.
     */
    override fun intercept(
        chain: Interceptor.Chain
    ): Response {

        val request =
            chain.request()

        val hostname =
            request.url
                .host
                .trim()
                .lowercase()

        /**
         * ---------------------------------------------------------
         * Validate manager state
         * ---------------------------------------------------------
         */
        if (
            configuration.requireInitializedManager &&
            !pinningManager.isEnabled()
        ) {

            throw SSLPinningPolicyException(
                message =
                    "SentriX SSL pinning manager is not initialized."
            )
        }

        /**
         * ---------------------------------------------------------
         * Check hostname configuration
         * ---------------------------------------------------------
         */
        val hostStatus =
            pinningManager
                .checkHostConfiguration(
                    hostname
                )

        /**
         * Host is not explicitly pinned.
         */
        if (!hostStatus.pinned) {

            if (
                configuration
                    .requirePinningForConfiguredHostsOnly
            ) {

                /**
                 * Allow requests to hosts that are not part of the
                 * application's pinning policy.
                 *
                 * This is useful when the application communicates
                 * with multiple external services.
                 */
                return executeRequest(
                    chain = chain,
                    hostname = hostname,
                    pinningConfigured = false
                )
            }

            /**
             * Global pinning mode.
             */
            if (
                pinningManager.isPinningRequired()
            ) {

                throw SSLPinningPolicyException(
                    message =
                        "HTTPS request targets an unpinned host " +
                                "while mandatory global pinning is enabled: " +
                                hostname
                )
            }
        }

        /**
         * ---------------------------------------------------------
         * Execute request
         * ---------------------------------------------------------
         *
         * CertificatePinner performs the actual certificate pin
         * verification during the TLS handshake.
         */
        return try {

            executeRequest(
                chain = chain,
                hostname = hostname,
                pinningConfigured =
                    hostStatus.pinned
            )

        } catch (exception: SSLPinningException) {

            throw exception

        } catch (exception: IOException) {

            /**
             * OkHttp CertificatePinner failures are surfaced through
             * IOException. We preserve the original exception as the
             * cause while providing a SentriX-specific classification.
             */
            if (
                looksLikePinningFailure(
                    exception
                )
            ) {

                throw SSLPinningException(
                    hostname = hostname,
                    message =
                        "SSL certificate pinning validation failed " +
                                "for host: $hostname",
                    cause = exception
                )
            }

            throw exception
        }
    }

    /**
     * Executes the request and optionally attaches SentriX metadata
     * to the response.
     */
    private fun executeRequest(
        chain: Interceptor.Chain,
        hostname: String,
        pinningConfigured: Boolean
    ): Response {

        val request =
            chain
                .request()
                .newBuilder()
                .apply {

                    /**
                     * These headers are internal telemetry markers.
                     *
                     * They are disabled by default because security
                     * state should generally not be sent to remote
                     * servers unless explicitly required.
                     */
                    if (
                        configuration
                            .addInternalPinningHeader
                    ) {

                        header(
                            configuration
                                .pinningHeaderName,
                            if (pinningConfigured) {
                                configuration
                                    .pinnedHeaderValue
                            } else {
                                configuration
                                    .unpinnedHeaderValue
                            }
                        )
                    }
                }
                .build()

        val response =
            chain.proceed(
                request
            )

        /**
         * Response itself does not prove certificate validity.
         *
         * Successful TLS connection already passed OkHttp's TLS
         * and CertificatePinner validation before the response
         * could be received.
         */
        return response
    }

    /**
     * Attempts to classify an IOException as a certificate-pinning
     * failure without depending on a particular OkHttp internal
     * exception implementation.
     */
    private fun looksLikePinningFailure(
        exception: IOException
    ): Boolean {

        var current:
                Throwable? =
            exception

        while (current != null) {

            val message =
                current.message
                    ?.lowercase()
                    ?: ""

            val className =
                current
                    .javaClass
                    .name
                    .lowercase()

            if (
                message.contains(
                    "certificate pinning"
                ) ||
                message.contains(
                    "pinning failure"
                ) ||
                message.contains(
                    "pinning"
                ) ||
                className.contains(
                    "certificatepinner"
                )
            ) {

                return true
            }

            current =
                current.cause
        }

        return false
    }
}

/**
 * SSL pinning interceptor configuration.
 */
data class SSLPinningInterceptorConfiguration(

    /**
     * Require the SSLPinningManager to be initialized before
     * requests are executed.
     */
    val requireInitializedManager: Boolean = true,

    /**
     * When true, only explicitly configured hosts require pinning.
     *
     * When false and global pinning is mandatory, requests to
     * unconfigured hosts are rejected.
     */
    val requirePinningForConfiguredHostsOnly: Boolean = true,

    /**
     * Whether an internal pinning-state header should be attached
     * to outgoing requests.
     *
     * Disabled by default.
     */
    val addInternalPinningHeader: Boolean = false,

    /**
     * Internal telemetry header name.
     */
    val pinningHeaderName: String =
        "X-SentriX-Pinning",

    /**
     * Value used when pinning is configured.
     */
    val pinnedHeaderValue: String =
        "configured",

    /**
     * Value used when pinning is not configured.
     */
    val unpinnedHeaderValue: String =
        "not-configured"
)

/**
 * General SentriX SSL pinning exception.
 */
open class SSLPinningException(
    val hostname: String,
    message: String,
    cause: Throwable? = null
) : IOException(
    message,
    cause
)

/**
 * Indicates that an application-level SentriX pinning policy
 * prevented a request from being executed.
 */
class SSLPinningPolicyException(
    message: String
) : SSLPinningException(
    hostname = "",
    message = message
)
