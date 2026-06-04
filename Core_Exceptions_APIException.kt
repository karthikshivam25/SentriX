package com.sentrix.core.exceptions

/**
 * APIException
 *
 * Base exception for all API, backend,
 * web service, cloud synchronization,
 * and remote communication failures
 * within SentriX.
 */
open class APIException : Exception {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Generic API request failure.
 */
class APIRequestException(
    message: String = "API request failed.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Invalid API response.
 */
class InvalidAPIResponseException(
    message: String = "Invalid API response received."
) : APIException(message)

/**
 * API timeout.
 */
class APITimeoutException(
    message: String = "API request timed out."
) : APIException(message)

/**
 * API unavailable.
 */
class APIUnavailableException(
    message: String = "API service unavailable."
) : APIException(message)

/**
 * Unauthorized request.
 */
class APIUnauthorizedException(
    message: String = "Unauthorized API request."
) : APIException(message)

/**
 * Forbidden request.
 */
class APIForbiddenException(
    message: String = "Access to API resource forbidden."
) : APIException(message)

/**
 * Resource not found.
 */
class APINotFoundException(
    message: String = "Requested API resource not found."
) : APIException(message)

/**
 * Rate limit exceeded.
 */
class APIRateLimitException(
    message: String = "API rate limit exceeded."
) : APIException(message)

/**
 * Internal server error.
 */
class APIServerException(
    val statusCode: Int = 500,
    message: String = "Internal server error."
) : APIException("$message (HTTP $statusCode)")

/**
 * Bad request.
 */
class APIBadRequestException(
    message: String = "Invalid API request."
) : APIException(message)

/**
 * Conflict error.
 */
class APIConflictException(
    message: String = "API resource conflict."
) : APIException(message)

/**
 * Validation error.
 */
class APIValidationException(
    message: String = "API validation failed."
) : APIException(message)

/**
 * Serialization failure.
 */
class APISerializationException(
    message: String = "Failed to serialize API request.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Deserialization failure.
 */
class APIDeserializationException(
    message: String = "Failed to parse API response.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Authentication token invalid.
 */
class APITokenException(
    message: String = "Invalid or expired API token."
) : APIException(message)

/**
 * API key invalid.
 */
class APIKeyException(
    message: String = "Invalid API key."
) : APIException(message)

/**
 * Cloud synchronization failure.
 */
class CloudSyncException(
    message: String = "Cloud synchronization failed.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Threat intelligence API failure.
 */
class ThreatIntelligenceAPIException(
    message: String = "Threat intelligence API unavailable.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Malware reputation API failure.
 */
class ReputationAPIException(
    message: String = "Reputation service API failure.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Update API failure.
 */
class UpdateAPIException(
    message: String = "Update service API failure.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * AI service API failure.
 */
class AIServiceException(
    message: String = "AI service unavailable.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Remote configuration failure.
 */
class RemoteConfigException(
    message: String = "Failed to retrieve remote configuration."
) : APIException(message)

/**
 * WebSocket connection failure.
 */
class WebSocketException(
    message: String = "WebSocket connection failed.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * API version mismatch.
 */
class APIVersionMismatchException(
    message: String = "Unsupported API version."
) : APIException(message)

/**
 * Maintenance mode.
 */
class MaintenanceModeException(
    message: String = "Service temporarily unavailable due to maintenance."
) : APIException(message)

/**
 * Service dependency failure.
 */
class ServiceDependencyException(
    message: String = "Dependent service failure.",
    cause: Throwable? = null
) : APIException(message, cause)

/**
 * Critical API failure.
 */
class CriticalAPIException(
    message: String = "Critical API infrastructure failure."
) : APIException(message)

/**
 * Maps HTTP status codes to SentriX API exceptions.
 */
object APIExceptionMapper {

    fun fromStatusCode(
        statusCode: Int,
        message: String? = null
    ): APIException {

        return when (statusCode) {

            400 -> APIBadRequestException(
                message ?: "Bad request."
            )

            401 -> APIUnauthorizedException(
                message ?: "Unauthorized."
            )

            403 -> APIForbiddenException(
                message ?: "Forbidden."
            )

            404 -> APINotFoundException(
                message ?: "Not found."
            )

            409 -> APIConflictException(
                message ?: "Conflict."
            )

            422 -> APIValidationException(
                message ?: "Validation failed."
            )

            429 -> APIRateLimitException(
                message ?: "Rate limit exceeded."
            )

            in 500..599 -> APIServerException(
                statusCode,
                message ?: "Server error."
            )

            else -> APIRequestException(
                message ?: "Unknown API error."
            )
        }
    }
}
