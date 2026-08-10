package com.sentrix.security.sslpinning

import android.content.Context
import android.os.Build
import java.net.SocketTimeoutException
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLException

/**
 * SSLPinningFailureHandler
 *
 * Centralized failure-handling component for SentriX SSL/TLS
 * certificate-pinning failures.
 *
 * Responsibilities:
 *
 * - Classify SSL/TLS failures.
 * - Identify certificate pinning failures.
 * - Identify certificate-chain failures.
 * - Identify hostname verification failures.
 * - Identify TLS protocol/cipher failures.
 * - Determine the security action that should be taken.
 * - Produce structured failure reports.
 * - Prevent accidental fail-open behavior.
 *
 * SECURITY PRINCIPLE:
 *
 * SSL pinning failure MUST default to blocking the connection.
 *
 * This class must NEVER:
 *
 * - disable SSL pinning.
 * - install a trust-all TrustManager.
 * - retry using an insecure connection.
 * - downgrade TLS to an insecure protocol.
 * - bypass hostname verification.
 * - silently ignore certificate errors.
 *
 * Architecture:
 *
 * TLS Failure
 *      ↓
 * SSLPinningFailureHandler
 *      ↓
 * Failure Classification
 *      ↓
 * Security Policy
 *      ↓
 * BLOCK / REPORT / ALERT
 */
class SSLPinningFailureHandler(
    private val context: Context,
    private val configuration:
        SSLPinningFailureHandlerConfiguration =
        SSLPinningFailureHandlerConfiguration()
) {

    /**
     * Handles an SSL/TLS security failure.
     *
     * The returned action determines how the SentriX networking
     * layer should react.
     */
    fun handleFailure(
        exception: Throwable,
        hostname: String? = null,
        requestUrl: String? = null,
        calculatedPin: String? = null,
        expectedPins: Set<String> = emptySet()
    ): SSLPinningFailureHandlingResult {

        val classification =
            classifyFailure(
                exception
            )

        val action =
            determineAction(
                classification
            )

        val severity =
            determineSeverity(
                classification
            )

        val safeHost =
            sanitizeHostname(
                hostname
            )

        val safeUrl =
            sanitizeUrl(
                requestUrl
            )

        val report =
            SSLPinningFailureReport(
                failureId =
                    generateFailureId(),
                failureType =
                    classification.type,
                severity =
                    severity,
                action =
                    action,
                hostname =
                    safeHost,
                requestUrl =
                    safeUrl,
                calculatedPin =
                    maskPin(
                        calculatedPin
                    ),
                expectedPinCount =
                    expectedPins.size,
                exceptionType =
                    exception.javaClass.simpleName,
                message =
                    safeFailureMessage(
                        classification
                    ),
                timestamp =
                    System.currentTimeMillis(),
                androidApiLevel =
                    Build.VERSION.SDK_INT,
                applicationPackage =
                    context.packageName
            )

        return SSLPinningFailureHandlingResult(
            handled = true,
            shouldBlockConnection =
                action ==
                        SSLPinningFailureAction.BLOCK_CONNECTION ||
                action ==
                        SSLPinningFailureAction.BLOCK_AND_ALERT,
            classification =
                classification,
            action =
                action,
            report =
                report
        )
    }

    /**
     * Handles a direct public-key pin mismatch.
     */
    fun handlePinMismatch(
        hostname: String?,
        requestUrl: String? = null,
        calculatedPin: String? = null,
        expectedPins: Set<String> = emptySet()
    ): SSLPinningFailureHandlingResult {

        val exception =
            SSLPeerUnverifiedException(
                "TLS certificate public-key pin mismatch."
            )

        return handleFailure(
            exception =
                exception,
            hostname =
                hostname,
            requestUrl =
                requestUrl,
            calculatedPin =
                calculatedPin,
            expectedPins =
                expectedPins
        ).copy(
            classification =
                SSLPinningFailureClassification(
                    type =
                        SSLPinningFailureType.PIN_MISMATCH,
                    confidence =
                        SSLPinningFailureConfidence.HIGH,
                    message =
                        "The peer certificate did not match the configured public-key pins."
                )
        )
    }

    /**
     * Handles a certificate-chain failure.
     */
    fun handleCertificateFailure(
        exception: CertificateException,
        hostname: String? = null,
        requestUrl: String? = null
    ): SSLPinningFailureHandlingResult {

        return handleFailure(
            exception =
                exception,
            hostname =
                hostname,
            requestUrl =
                requestUrl
        )
    }

    /**
     * Handles a hostname verification failure.
     */
    fun handleHostnameFailure(
        hostname: String?,
        requestUrl: String? = null,
        cause: Throwable? = null
    ): SSLPinningFailureHandlingResult {

        val exception =
            cause
                ?: SSLPeerUnverifiedException(
                    "TLS hostname verification failed."
                )

        return handleFailure(
            exception =
                exception,
            hostname =
                hostname,
            requestUrl =
                requestUrl
        ).copy(
            classification =
                SSLPinningFailureClassification(
                    type =
                        SSLPinningFailureType.HOSTNAME_VERIFICATION_FAILURE,
                    confidence =
                        SSLPinningFailureConfidence.HIGH,
                    message =
                        "The TLS peer hostname could not be verified."
                )
        )
    }

    /**
     * Handles a generic TLS handshake failure.
     */
    fun handleHandshakeFailure(
        exception: SSLHandshakeException,
        hostname: String? = null,
        requestUrl: String? = null
    ): SSLPinningFailureHandlingResult {

        return handleFailure(
            exception =
                exception,
            hostname =
                hostname,
            requestUrl =
                requestUrl
        )
    }

    /**
     * Classifies an SSL/TLS exception.
     */
    fun classifyFailure(
        exception: Throwable
    ): SSLPinningFailureClassification {

        /**
         * Most specific checks should happen first.
         */

        if (
            exception is SSLPeerUnverifiedException
        ) {

            return SSLPinningFailureClassification(
                type =
                    SSLPinningFailureType.PIN_MISMATCH,
                confidence =
                    SSLPinningFailureConfidence.MEDIUM,
                message =
                    "The TLS peer could not be verified."
            )
        }

        if (
            exception is SSLHandshakeException
        ) {

            val message =
                exception
                    .message
                    ?.lowercase()
                    ?: ""

            return when {

                message.contains(
                    "pin"
                ) ||
                        message.contains(
                            "certificate pin"
                        ) ||
                        message.contains(
                            "pinned"
                        ) -> {

                    SSLPinningFailureClassification(
                        type =
                            SSLPinningFailureType.PIN_MISMATCH,
                        confidence =
                            SSLPinningFailureConfidence.HIGH,
                        message =
                            "The TLS handshake appears to have failed because of certificate pinning."
                    )
                }

                message.contains(
                    "hostname"
                ) -> {

                    SSLPinningFailureClassification(
                        type =
                            SSLPinningFailureType.HOSTNAME_VERIFICATION_FAILURE,
                        confidence =
                            SSLPinningFailureConfidence.HIGH,
                        message =
                            "TLS hostname verification failed."
                    )
                }

                message.contains(
                    "protocol"
                ) -> {

                    SSLPinningFailureClassification(
                        type =
                            SSLPinningFailureType.TLS_PROTOCOL_FAILURE,
                        confidence =
                            SSLPinningFailureConfidence.HIGH,
                        message =
                            "The TLS protocol negotiation failed."
                    )
                }

                message.contains(
                    "cipher"
                ) -> {

                    SSLPinningFailureClassification(
                        type =
                            SSLPinningFailureType.CIPHER_SUITE_FAILURE,
                        confidence =
                            SSLPinningFailureConfidence.MEDIUM,
                        message =
                            "The TLS cipher-suite negotiation failed."
                    )
                }

                message.contains(
                    "certificate"
                ) ||
                        message.contains(
                            "trust anchor"
                        ) ||
                        message.contains(
                            "certpath"
                        ) -> {

                    SSLPinningFailureClassification(
                        type =
                            SSLPinningFailureType.CERTIFICATE_CHAIN_FAILURE,
                        confidence =
                            SSLPinningFailureConfidence.HIGH,
                        message =
                            "TLS certificate-chain validation failed."
                    )
                }

                else -> {

                    SSLPinningFailureClassification(
                        type =
                            SSLPinningFailureType.HANDSHAKE_FAILURE,
                        confidence =
                            SSLPinningFailureConfidence.MEDIUM,
                        message =
                            "The TLS handshake failed."
                    )
                }
            }
        }

        if (
            exception is SSLProtocolException
        ) {

            return SSLPinningFailureClassification(
                type =
                    SSLPinningFailureType.TLS_PROTOCOL_FAILURE,
                confidence =
                    SSLPinningFailureConfidence.HIGH,
                message =
                    "TLS protocol negotiation failed."
            )
        }

        if (
            exception is CertificateException
        ) {

            return SSLPinningFailureClassification(
                type =
                    SSLPinningFailureType.CERTIFICATE_CHAIN_FAILURE,
                confidence =
                    SSLPinningFailureConfidence.HIGH,
                message =
                    "Certificate validation failed."
            )
        }

        if (
            exception is SocketTimeoutException
        ) {

            return SSLPinningFailureClassification(
                type =
                    SSLPinningFailureType.NETWORK_TIMEOUT,
                confidence =
                    SSLPinningFailureConfidence.HIGH,
                message =
                    "The TLS/network operation timed out."
            )
        }

        if (
            exception is SSLException
        ) {

            return SSLPinningFailureClassification(
                type =
                    SSLPinningFailureType.GENERIC_SSL_FAILURE,
                confidence =
                    SSLPinningFailureConfidence.MEDIUM,
                message =
                    "A generic TLS/SSL failure occurred."
            )
        }

        return SSLPinningFailureClassification(
            type =
                SSLPinningFailureType.UNKNOWN_FAILURE,
            confidence =
                SSLPinningFailureConfidence.LOW,
            message =
                "An unknown security-related network failure occurred."
        )
    }

    /**
     * Determines the security action from the failure class.
     *
     * Security-sensitive failures default to BLOCK_CONNECTION.
     */
    private fun determineAction(
        classification:
            SSLPinningFailureClassification
    ): SSLPinningFailureAction {

        return when (
            classification.type
        ) {

            SSLPinningFailureType.PIN_MISMATCH,
            SSLPinningFailureType.CERTIFICATE_CHAIN_FAILURE,
            SSLPinningFailureType.HOSTNAME_VERIFICATION_FAILURE,
            SSLPinningFailureType.TLS_PROTOCOL_FAILURE,
            SSLPinningFailureType.CIPHER_SUITE_FAILURE -> {

                if (
                    configuration.alertOnSecurityFailure
                ) {
                    SSLPinningFailureAction.BLOCK_AND_ALERT
                } else {
                    SSLPinningFailureAction.BLOCK_CONNECTION
                }
            }

            SSLPinningFailureType.HANDSHAKE_FAILURE,
            SSLPinningFailureType.GENERIC_SSL_FAILURE -> {

                if (
                    configuration.alertOnSecurityFailure
                ) {
                    SSLPinningFailureAction.BLOCK_AND_ALERT
                } else {
                    SSLPinningFailureAction.BLOCK_CONNECTION
                }
            }

            SSLPinningFailureType.NETWORK_TIMEOUT -> {

                SSLPinningFailureAction.BLOCK_CONNECTION
            }

            SSLPinningFailureType.UNKNOWN_FAILURE -> {

                /**
                 * Fail closed by default.
                 */
                SSLPinningFailureAction.BLOCK_CONNECTION
            }
        }
    }

    /**
     * Determines security severity.
     */
    private fun determineSeverity(
        classification:
            SSLPinningFailureClassification
    ): SSLPinningFailureSeverity {

        return when (
            classification.type
        ) {

            SSLPinningFailureType.PIN_MISMATCH ->
                SSLPinningFailureSeverity.CRITICAL

            SSLPinningFailureType.CERTIFICATE_CHAIN_FAILURE ->
                SSLPinningFailureSeverity.CRITICAL

            SSLPinningFailureType.HOSTNAME_VERIFICATION_FAILURE ->
                SSLPinningFailureSeverity.CRITICAL

            SSLPinningFailureType.TLS_PROTOCOL_FAILURE ->
                SSLPinningFailureSeverity.HIGH

            SSLPinningFailureType.CIPHER_SUITE_FAILURE ->
                SSLPinningFailureSeverity.HIGH

            SSLPinningFailureType.HANDSHAKE_FAILURE ->
                SSLPinningFailureSeverity.HIGH

            SSLPinningFailureType.GENERIC_SSL_FAILURE ->
                SSLPinningFailureSeverity.HIGH

            SSLPinningFailureType.NETWORK_TIMEOUT ->
                SSLPinningFailureSeverity.MEDIUM

            SSLPinningFailureType.UNKNOWN_FAILURE ->
                SSLPinningFailureSeverity.HIGH
        }
    }

    /**
     * Sanitizes a hostname before placing it into a security report.
     */
    private fun sanitizeHostname(
        hostname: String?
    ): String? {

        if (
            hostname.isNullOrBlank()
        ) {
            return null
        }

        return hostname
            .trim()
            .lowercase()
            .take(
                configuration.maxHostnameLength
            )
    }

    /**
     * Sanitizes a URL before reporting.
     *
     * Query parameters and fragments are intentionally removed
     * to reduce the possibility of leaking credentials, tokens,
     * identifiers, or other sensitive values into logs.
     */
    private fun sanitizeUrl(
        url: String?
    ): String? {

        if (
            url.isNullOrBlank()
        ) {
            return null
        }

        return try {

            val uri =
                android.net.Uri.parse(
                    url
                )

            buildString {

                if (
                    !uri.scheme.isNullOrBlank()
                ) {

                    append(
                        uri.scheme
                    )

                    append(
                        "://"
                    )
                }

                if (
                    !uri.host.isNullOrBlank()
                ) {

                    append(
                        uri.host
                    )
                }

                if (
                    uri.port != -1
                ) {

                    append(
                        ":"
                    )

                    append(
                        uri.port
                    )
                }

                uri.path?.let {

                    append(
                        it
                    )
                }
            }.take(
                configuration.maxUrlLength
            )

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Masks certificate pin data.
     */
    private fun maskPin(
        pin: String?
    ): String? {

        if (
            pin.isNullOrBlank()
        ) {
            return null
        }

        if (
            pin.length <= 16
        ) {

            return "***"
        }

        return pin.take(12) +
                "..." +
                pin.takeLast(6)
    }

    /**
     * Returns a safe failure message.
     *
     * Raw exception messages may contain certificate details,
     * URLs, or other sensitive information, so they are not
     * exposed directly.
     */
    private fun safeFailureMessage(
        classification:
            SSLPinningFailureClassification
    ): String {

        return classification.message
    }

    /**
     * Generates a local failure identifier.
     */
    private fun generateFailureId(): String {

        return "SSL-" +
                System.currentTimeMillis()
                    .toString(36)
                    .uppercase()
    }

    companion object {

        /**
         * Creates a default SentriX failure handler.
         */
        fun create(
            context: Context
        ): SSLPinningFailureHandler {

            return SSLPinningFailureHandler(
                context =
                    context.applicationContext
            )
        }
    }
}

/**
 * SSL pinning failure-handler configuration.
 */
data class SSLPinningFailureHandlerConfiguration(

    /**
     * Whether security failures should produce an alert.
     */
    val alertOnSecurityFailure: Boolean = true,

    /**
     * Maximum hostname length stored in reports.
     */
    val maxHostnameLength: Int = 255,

    /**
     * Maximum sanitized URL length.
     */
    val maxUrlLength: Int = 2048,

    /**
     * Whether diagnostic reports should be generated.
     */
    val generateSecurityReport: Boolean = true
)

/**
 * Result returned after handling an SSL failure.
 */
data class SSLPinningFailureHandlingResult(

    /**
     * Whether the failure was successfully classified/handled.
     */
    val handled: Boolean,

    /**
     * Whether the network connection must be blocked.
     */
    val shouldBlockConnection: Boolean,

    /**
     * Failure classification.
     */
    val classification:
        SSLPinningFailureClassification,

    /**
     * Recommended security action.
     */
    val action:
        SSLPinningFailureAction,

    /**
     * Structured failure report.
     */
    val report:
        SSLPinningFailureReport
)

/**
 * SSL/TLS failure classification.
 */
data class SSLPinningFailureClassification(

    /**
     * Failure type.
     */
    val type:
        SSLPinningFailureType,

    /**
     * Classification confidence.
     */
    val confidence:
        SSLPinningFailureConfidence,

    /**
     * Safe human-readable description.
     */
    val message: String
)

/**
 * SSL pinning failure report.
 */
data class SSLPinningFailureReport(

    /**
     * Locally generated failure identifier.
     */
    val failureId: String,

    /**
     * Failure category.
     */
    val failureType:
        SSLPinningFailureType,

    /**
     * Security severity.
     */
    val severity:
        SSLPinningFailureSeverity,

    /**
     * Recommended security action.
     */
    val action:
        SSLPinningFailureAction,

    /**
     * Sanitized hostname.
     */
    val hostname: String?,

    /**
     * Sanitized URL.
     */
    val requestUrl: String?,

    /**
     * Masked calculated pin.
     */
    val calculatedPin: String?,

    /**
     * Number of expected pins.
     */
    val expectedPinCount: Int,

    /**
     * Exception class.
     */
    val exceptionType: String,

    /**
     * Safe error description.
     */
    val message: String,

    /**
     * Failure timestamp.
     */
    val timestamp: Long,

    /**
     * Android API level.
     */
    val androidApiLevel: Int,

    /**
     * Application package.
     */
    val applicationPackage: String
)

/**
 * SSL/TLS failure types.
 */
enum class SSLPinningFailureType {

    /**
     * Public-key/certificate pin mismatch.
     */
    PIN_MISMATCH,

    /**
     * Certificate-chain validation failure.
     */
    CERTIFICATE_CHAIN_FAILURE,

    /**
     * Hostname verification failure.
     */
    HOSTNAME_VERIFICATION_FAILURE,

    /**
     * TLS protocol negotiation failure.
     */
    TLS_PROTOCOL_FAILURE,

    /**
     * Cipher-suite negotiation failure.
     */
    CIPHER_SUITE_FAILURE,

    /**
     * Generic handshake failure.
     */
    HANDSHAKE_FAILURE,

    /**
     * Generic SSL failure.
     */
    GENERIC_SSL_FAILURE,

    /**
     * Network timeout.
     */
    NETWORK_TIMEOUT,

    /**
     * Unknown failure.
     */
    UNKNOWN_FAILURE
}

/**
 * Confidence of failure classification.
 */
enum class SSLPinningFailureConfidence {

    /**
     * Low confidence.
     */
    LOW,

    /**
     * Medium confidence.
     */
    MEDIUM,

    /**
     * High confidence.
     */
    HIGH
}

/**
 * Security severity.
 */
enum class SSLPinningFailureSeverity {

    /**
     * Informational.
     */
    INFO,

    /**
     * Low severity.
     */
    LOW,

    /**
     * Medium severity.
     */
    MEDIUM,

    /**
     * High severity.
     */
    HIGH,

    /**
     * Critical security failure.
     */
    CRITICAL
}

/**
 * Action recommended by the failure handler.
 */
enum class SSLPinningFailureAction {

    /**
     * Block the network connection.
     */
    BLOCK_CONNECTION,

    /**
     * Block and generate a security alert.
     */
    BLOCK_AND_ALERT
}
