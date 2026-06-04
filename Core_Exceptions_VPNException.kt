package com.sentrix.core.exceptions

/**
 * VPNException
 *
 * Base exception for all VPN-related failures
 * within the SentriX security platform.
 */
open class VPNException : Exception {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * VPN service unavailable.
 */
class VPNServiceUnavailableException(
    message: String = "VPN service is unavailable."
) : VPNException(message)

/**
 * VPN connection failed.
 */
class VPNConnectionException(
    message: String = "Failed to establish VPN connection.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN disconnected unexpectedly.
 */
class VPNDisconnectedException(
    message: String = "VPN connection was unexpectedly disconnected."
) : VPNException(message)

/**
 * VPN authentication failed.
 */
class VPNAuthenticationException(
    message: String = "VPN authentication failed."
) : VPNException(message)

/**
 * VPN authorization failed.
 */
class VPNAuthorizationException(
    message: String = "VPN authorization failed."
) : VPNException(message)

/**
 * VPN configuration invalid.
 */
class VPNConfigurationException(
    message: String = "Invalid VPN configuration."
) : VPNException(message)

/**
 * VPN tunnel creation failed.
 */
class VPNTunnelException(
    message: String = "Failed to create VPN tunnel.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN handshake failed.
 */
class VPNHandshakeException(
    message: String = "VPN handshake failed.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN protocol unsupported.
 */
class UnsupportedVPNProtocolException(
    message: String = "Unsupported VPN protocol."
) : VPNException(message)

/**
 * VPN server unreachable.
 */
class VPNServerUnreachableException(
    message: String = "VPN server is unreachable."
) : VPNException(message)

/**
 * VPN timeout occurred.
 */
class VPNTimeoutException(
    message: String = "VPN connection timed out."
) : VPNException(message)

/**
 * VPN DNS leak detected.
 */
class DNSLeakException(
    message: String = "Potential DNS leak detected."
) : VPNException(message)

/**
 * VPN WebRTC leak detected.
 */
class WebRTCLeakException(
    message: String = "Potential WebRTC leak detected."
) : VPNException(message)

/**
 * VPN kill switch failure.
 */
class KillSwitchException(
    message: String = "VPN kill switch failure detected."
) : VPNException(message)

/**
 * VPN certificate validation failed.
 */
class VPNCertificateException(
    message: String = "VPN certificate validation failed.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN encryption failure.
 */
class VPNEncryptionException(
    message: String = "VPN encryption failure.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN provider not trusted.
 */
class UntrustedVPNProviderException(
    message: String = "VPN provider is not trusted."
) : VPNException(message)

/**
 * VPN provider blacklisted.
 */
class BlacklistedVPNProviderException(
    message: String = "VPN provider is blacklisted."
) : VPNException(message)

/**
 * VPN reputation lookup failed.
 */
class VPNReputationException(
    message: String = "VPN reputation check failed.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN policy violation.
 */
class VPNPolicyViolationException(
    message: String = "VPN policy violation detected."
) : VPNException(message)

/**
 * VPN traffic inspection failure.
 */
class VPNTrafficInspectionException(
    message: String = "VPN traffic inspection failed.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN monitoring failure.
 */
class VPNMonitoringException(
    message: String = "VPN monitoring failure.",
    cause: Throwable? = null
) : VPNException(message, cause)

/**
 * VPN state detection failure.
 */
class VPNStateException(
    message: String = "Unable to determine VPN state."
) : VPNException(message)

/**
 * VPN permission denied.
 */
class VPNPermissionException(
    message: String = "VPN permission denied."
) : VPNException(message)

/**
 * Split tunneling configuration error.
 */
class SplitTunnelException(
    message: String = "Split tunneling configuration failed."
) : VPNException(message)

/**
 * VPN route configuration failure.
 */
class VPNRoutingException(
    message: String = "VPN routing configuration failed."
) : VPNException(message)

/**
 * Critical VPN security failure.
 */
class CriticalVPNException(
    message: String = "Critical VPN security failure detected."
) : VPNException(message)
