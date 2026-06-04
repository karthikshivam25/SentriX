package com.sentrix.core.exceptions

/**
 * ValidationException
 *
 * Base exception for all validation-related
 * failures within the SentriX platform.
 *
 * Used for:
 * - User input validation
 * - Security policy validation
 * - Configuration validation
 * - API request validation
 * - File and URL validation
 * - Authentication data validation
 */
open class ValidationException : IllegalArgumentException {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Generic validation failure.
 */
class InvalidInputException(
    message: String = "Invalid input provided."
) : ValidationException(message)

/**
 * Required field missing.
 */
class RequiredFieldException(
    fieldName: String
) : ValidationException(
    "$fieldName is required."
)

/**
 * Invalid email format.
 */
class InvalidEmailException(
    message: String = "Invalid email address."
) : ValidationException(message)

/**
 * Invalid phone number.
 */
class InvalidPhoneNumberException(
    message: String = "Invalid phone number."
) : ValidationException(message)

/**
 * Invalid username.
 */
class InvalidUsernameException(
    message: String = "Invalid username."
) : ValidationException(message)

/**
 * Invalid password.
 */
class InvalidPasswordException(
    message: String =
        "Password does not meet security requirements."
) : ValidationException(message)

/**
 * Password confirmation mismatch.
 */
class PasswordMismatchException(
    message: String =
        "Passwords do not match."
) : ValidationException(message)

/**
 * Invalid PIN.
 */
class InvalidPinException(
    message: String =
        "Invalid PIN format."
) : ValidationException(message)

/**
 * Invalid OTP.
 */
class InvalidOtpException(
    message: String =
        "Invalid one-time password."
) : ValidationException(message)

/**
 * Invalid authentication token.
 */
class InvalidTokenFormatException(
    message: String =
        "Invalid authentication token format."
) : ValidationException(message)

/**
 * Invalid URL.
 */
class InvalidURLException(
    message: String = "Invalid URL."
) : ValidationException(message)

/**
 * Invalid domain.
 */
class InvalidDomainException(
    message: String = "Invalid domain."
) : ValidationException(message)

/**
 * Invalid IP address.
 */
class InvalidIPAddressException(
    message: String = "Invalid IP address."
) : ValidationException(message)

/**
 * Invalid package name.
 */
class InvalidPackageNameException(
    message: String = "Invalid package name."
) : ValidationException(message)

/**
 * Invalid file.
 */
class InvalidFileException(
    message: String = "Invalid file."
) : ValidationException(message)

/**
 * Unsupported file type.
 */
class UnsupportedFileTypeException(
    message: String = "Unsupported file type."
) : ValidationException(message)

/**
 * File size exceeds allowed limit.
 */
class FileSizeLimitException(
    message: String = "File exceeds size limit."
) : ValidationException(message)

/**
 * Invalid APK file.
 */
class InvalidAPKException(
    message: String = "Invalid APK file."
) : ValidationException(message)

/**
 * Invalid configuration.
 */
class InvalidConfigurationException(
    message: String =
        "Invalid configuration."
) : ValidationException(message)

/**
 * Missing configuration.
 */
class MissingConfigurationException(
    configKey: String
) : ValidationException(
    "Missing configuration: $configKey"
)

/**
 * Invalid JSON payload.
 */
class InvalidJsonException(
    message: String =
        "Invalid JSON payload."
) : ValidationException(message)

/**
 * Invalid request parameters.
 */
class InvalidRequestException(
    message: String =
        "Invalid request parameters."
) : ValidationException(message)

/**
 * Invalid API response.
 */
class InvalidResponseException(
    message: String =
        "Invalid response received."
) : ValidationException(message)

/**
 * Security policy validation failure.
 */
class SecurityPolicyValidationException(
    message: String =
        "Security policy validation failed."
) : ValidationException(message)

/**
 * Invalid permission configuration.
 */
class InvalidPermissionException(
    message: String =
        "Invalid permission configuration."
) : ValidationException(message)

/**
 * Invalid scan configuration.
 */
class InvalidScanConfigurationException(
    message: String =
        "Invalid scan configuration."
) : ValidationException(message)

/**
 * Invalid VPN configuration.
 */
class InvalidVPNConfigurationException(
    message: String =
        "Invalid VPN configuration."
) : ValidationException(message)

/**
 * Invalid firewall rule.
 */
class InvalidFirewallRuleException(
    message: String =
        "Invalid firewall rule."
) : ValidationException(message)

/**
 * Invalid encryption configuration.
 */
class InvalidEncryptionConfigurationException(
    message: String =
        "Invalid encryption configuration."
) : ValidationException(message)

/**
 * Validation rule violation.
 */
class ValidationRuleException(
    message: String =
        "Validation rule violated."
) : ValidationException(message)

/**
 * Data integrity validation failure.
 */
class DataIntegrityValidationException(
    message: String =
        "Data integrity validation failed."
) : ValidationException(message)
