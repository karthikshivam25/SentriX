package com.sentrix.core.exceptions

import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * NetworkException
 *
 * Base exception for all network-related failures
 * within the SentriX platform.
 */
open class NetworkException : IOException {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * No internet connection available.
 */
class NoInternetException(
    message: String = "No internet connection available."
) : NetworkException(message)

/**
 * Unable to resolve host.
 */
class HostUnreachableException(
    message: String = "Host could not be reached.",
    cause: Throwable? = null
) : NetworkException(message, cause)

/**
 * Request timeout.
 */
class RequestTimeoutException(
    message: String = "Network request timed out.",
    cause: Throwable? = null
) : NetworkException(message, cause)

/**
 * Connection refused by server.
 */
class ConnectionRefusedException(
    message: String = "Connection refused by remote server."
) : NetworkException(message)

/**
 * SSL/TLS validation failure.
 */
class SSLValidationException(
    message: String = "SSL certificate validation failed.",
    cause: Throwable? = null
) : NetworkException(message, cause)

/**
 * Certificate pinning validation failure.
 */
class CertificatePinningException(
    message: String = "Certificate pinning verification failed."
) : NetworkException(message)

/**
 * DNS lookup failure.
 */
class DNSResolutionException(
    message: String = "DNS resolution failed.",
    cause: Throwable? = null
) : NetworkException(message, cause)

/**
 * API response error.
 */
class ApiException(
    val code: Int,
    message: String = "API request failed."
) : NetworkException(
    "$message (HTTP $code)"
)

/**
 * Unauthorized API request.
 */
class UnauthorizedException(
    message: String = "Unauthorized request."
) : ApiException(
    code = 401,
    message = message
)

/**
 * Forbidden API request.
 */
class ForbiddenException(
    message: String = "Access forbidden."
) : ApiException(
    code = 403,
    message = message
)

/**
 * Resource not found.
 */
class NotFoundException(
    message: String = "Requested resource not found."
) : ApiException(
    code = 404,
    message = message
)

/**
 * Too many requests.
 */
class RateLimitException(
    message: String = "Too many requests."
) : ApiException(
    code = 429,
    message = message
)

/**
 * Internal server error.
 */
class ServerException(
    code: Int = 500,
    message: String = "Server error occurred."
) : ApiException(
    code = code,
    message = message
)

/**
 * VPN tunnel failure.
 */
class VPNConnectionException(
    message: String = "VPN connection failed."
) : NetworkException(message)

/**
 * Firewall policy violation.
 */
class FirewallBlockedException(
    message: String = "Connection blocked by firewall policy."
) : NetworkException(message)

/**
 * Suspicious network activity detected.
 */
class SuspiciousTrafficException(
    message: String = "Suspicious network activity detected."
) : NetworkException(message)

/**
 * Network scan failure.
 */
class NetworkScanException(
    message: String = "Network scan failed."
) : NetworkException(message)

/**
 * Packet inspection failure.
 */
class PacketInspectionException(
    message: String = "Packet inspection failed."
) : NetworkException(message)

/**
 * Threat intelligence lookup failure.
 */
class ThreatLookupException(
    message: String = "Threat intelligence lookup failed."
) : NetworkException(message)

/**
 * Convert common Java exceptions into SentriX exceptions.
 */
object NetworkExceptionMapper {

    fun map(
        throwable: Throwable
    ): NetworkException {

        return when (throwable) {

            is SocketTimeoutException ->
                RequestTimeoutException(
                    cause = throwable
                )

            is UnknownHostException ->
                DNSResolutionException(
                    cause = throwable
                )

            is NetworkException ->
                throwable

            else ->
                NetworkException(
                    throwable.message
                        ?: "Unknown network error.",
                    throwable
                )
        }
    }
}
