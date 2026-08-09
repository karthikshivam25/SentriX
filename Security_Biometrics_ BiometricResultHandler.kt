package com.sentrix.security.biometrics

/**
 * SentriX Biometric Result Handler
 *
 * Final normalization layer for biometric authentication results.
 *
 * Responsibilities:
 *
 * - Process BiometricAuthenticationResult.
 * - Normalize success/failure states.
 * - Classify security significance.
 * - Determine whether retry is appropriate.
 * - Determine whether user action is required.
 * - Determine whether enrollment/configuration is required.
 * - Produce a stable SentriX-level result.
 * - Provide safe user-facing messages.
 * - Provide security audit classification.
 *
 * This class DOES NOT:
 *
 * - Display BiometricPrompt.
 * - Perform biometric authentication.
 * - Access biometric templates.
 * - Store fingerprints or facial data.
 * - Modify device biometric configuration.
 * - Authorize business operations.
 *
 * Android authentication details have already been abstracted by
 * BiometricAuthenticator / BiometricAuthenticationHandler.
 *
 * Architecture:
 *
 *      BiometricAuthenticator
 *                │
 *                ▼
 *      BiometricAuthenticationHandler
 *                │
 *                ▼
 *        BiometricResultHandler
 *                │
 *                ▼
 *      SentriXBiometricResult
 *                │
 *                ▼
 *       Security / Domain Layer
 */
class BiometricResultHandler {

    // -------------------------------------------------------------------------
    // Runtime State
    // -------------------------------------------------------------------------

    /**
     * Last normalized result.
     *
     * This is kept in memory only.
     */
    private var lastResult:
            SentriXBiometricResult? = null

    /**
     * Number of failed attempts observed during the current
     * result-processing session.
     */
    private var failedAttemptCount: Int = 0

    // -------------------------------------------------------------------------
    // Main Result Processing
    // -------------------------------------------------------------------------

    /**
     * Processes a biometric authentication result.
     *
     * This is the primary entry point for result normalization.
     */
    fun handle(
        result: BiometricAuthenticationResult
    ): SentriXBiometricResult {

        val normalizedResult =
            when (result) {

                BiometricAuthenticationResult.Success -> {

                    failedAttemptCount = 0

                    SentriXBiometricResult.Authenticated(
                        securityLevel =
                            BiometricSecurityLevel.BIOMETRIC,
                        auditSeverity =
                            BiometricAuditSeverity.INFO
                    )
                }

                BiometricAuthenticationResult.FailedAttempt -> {

                    failedAttemptCount++

                    SentriXBiometricResult.RetryableFailure(
                        reason =
                            BiometricFailureReason
                                .AuthenticationMismatch,
                        failedAttempts =
                            failedAttemptCount,
                        auditSeverity =
                            BiometricAuditSeverity.LOW
                    )
                }

                is BiometricAuthenticationResult.Cancelled -> {

                    SentriXBiometricResult.Cancelled(
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.INFO
                    )
                }

                is BiometricAuthenticationResult.LockedOut -> {

                    SentriXBiometricResult.LockedOut(
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        permanent = false,
                        auditSeverity =
                            BiometricAuditSeverity.HIGH
                    )
                }

                is BiometricAuthenticationResult.PermanentlyLockedOut -> {

                    SentriXBiometricResult.LockedOut(
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        permanent = true,
                        auditSeverity =
                            BiometricAuditSeverity.CRITICAL
                    )
                }

                is BiometricAuthenticationResult.HardwareUnavailable -> {

                    SentriXBiometricResult.TemporaryFailure(
                        reason =
                            BiometricFailureReason
                                .HardwareUnavailable,
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.MEDIUM
                    )
                }

                is BiometricAuthenticationResult.NotEnrolled -> {

                    SentriXBiometricResult.ConfigurationRequired(
                        requirement =
                            BiometricConfigurationRequirement
                                .BiometricEnrollment,
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.MEDIUM
                    )
                }

                is BiometricAuthenticationResult.NoDeviceCredential -> {

                    SentriXBiometricResult.ConfigurationRequired(
                        requirement =
                            BiometricConfigurationRequirement
                                .DeviceCredential,
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.MEDIUM
                    )
                }

                is BiometricAuthenticationResult.Timeout -> {

                    SentriXBiometricResult.RetryableFailure(
                        reason =
                            BiometricFailureReason
                                .AuthenticationTimeout,
                        failedAttempts =
                            failedAttemptCount,
                        auditSeverity =
                            BiometricAuditSeverity.LOW
                    )
                }

                is BiometricAuthenticationResult.ProcessingError -> {

                    SentriXBiometricResult.TemporaryFailure(
                        reason =
                            BiometricFailureReason
                                .ProcessingError,
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.MEDIUM
                    )
                }

                is BiometricAuthenticationResult.VendorError -> {

                    SentriXBiometricResult.TemporaryFailure(
                        reason =
                            BiometricFailureReason
                                .VendorError,
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.MEDIUM
                    )
                }

                BiometricAuthenticationResult.SecurityUpdateRequired -> {

                    SentriXBiometricResult.ConfigurationRequired(
                        requirement =
                            BiometricConfigurationRequirement
                                .SecurityUpdate,
                        message =
                            "A device security update is required.",
                        auditSeverity =
                            BiometricAuditSeverity.HIGH
                    )
                }

                is BiometricAuthenticationResult.NotSupported -> {

                    SentriXBiometricResult.Unsupported(
                        reason =
                            sanitizeMessage(
                                result.reason
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.MEDIUM
                    )
                }

                is BiometricAuthenticationResult.UnknownError -> {

                    SentriXBiometricResult.Failure(
                        reason =
                            BiometricFailureReason
                                .Unknown,
                        message =
                            sanitizeMessage(
                                result.message
                            ),
                        auditSeverity =
                            BiometricAuditSeverity.MEDIUM
                    )
                }

                is BiometricAuthenticationResult.Error -> {

                    SentriXBiometricResult.Failure(
                        reason =
                            BiometricFailureReason
                                .SystemError,
                        message =
                            "Biometric authentication could not be completed.",
                        auditSeverity =
                            BiometricAuditSeverity.HIGH
                    )
                }
            }

        lastResult =
            normalizedResult

        return normalizedResult
    }

    // -------------------------------------------------------------------------
    // Authentication Result Handling
    // -------------------------------------------------------------------------

    /**
     * Handles a successful authentication result with an explicitly
     * known security level.
     *
     * This is useful when BiometricSecurityManager has already determined
     * whether strong biometric or another authentication level was used.
     */
    fun handleAuthenticated(
        securityLevel: BiometricSecurityLevel
    ): SentriXBiometricResult {

        failedAttemptCount = 0

        val result =
            SentriXBiometricResult.Authenticated(
                securityLevel =
                    securityLevel,
                auditSeverity =
                    BiometricAuditSeverity.INFO
            )

        lastResult =
            result

        return result
    }

    /**
     * Handles an individual failed biometric attempt.
     *
     * The authentication prompt may remain active.
     */
    fun handleFailedAttempt():
            SentriXBiometricResult {

        failedAttemptCount++

        val result =
            SentriXBiometricResult.RetryableFailure(
                reason =
                    BiometricFailureReason
                        .AuthenticationMismatch,
                failedAttempts =
                    failedAttemptCount,
                auditSeverity =
                    BiometricAuditSeverity.LOW
            )

        lastResult =
            result

        return result
    }

    // -------------------------------------------------------------------------
    // Classification
    // -------------------------------------------------------------------------

    /**
     * Determines whether the result represents successful
     * authentication.
     */
    fun isAuthenticated(
        result: SentriXBiometricResult
    ): Boolean {

        return result is
                SentriXBiometricResult.Authenticated
    }

    /**
     * Determines whether another authentication attempt can
     * reasonably be made.
     */
    fun isRetryable(
        result: SentriXBiometricResult
    ): Boolean {

        return result is
                SentriXBiometricResult.RetryableFailure ||
                result is
                SentriXBiometricResult.TemporaryFailure
    }

    /**
     * Determines whether user/device configuration action is required.
     */
    fun requiresConfiguration(
        result: SentriXBiometricResult
    ): Boolean {

        return result is
                SentriXBiometricResult.ConfigurationRequired
    }

    /**
     * Determines whether the result indicates biometric lockout.
     */
    fun isLockedOut(
        result: SentriXBiometricResult
    ): Boolean {

        return result is
                SentriXBiometricResult.LockedOut
    }

    /**
     * Determines whether the lockout is permanent.
     */
    fun isPermanentlyLockedOut(
        result: SentriXBiometricResult
    ): Boolean {

        return result is
                SentriXBiometricResult.LockedOut &&
                result.permanent
    }

    /**
     * Determines whether the authentication operation was cancelled.
     */
    fun isCancelled(
        result: SentriXBiometricResult
    ): Boolean {

        return result is
                SentriXBiometricResult.Cancelled
    }

    /**
     * Determines whether the result should terminate the current
     * protected operation.
     */
    fun shouldTerminateOperation(
        result: SentriXBiometricResult
    ): Boolean {

        return when (result) {

            is SentriXBiometricResult.Authenticated ->
                false

            is SentriXBiometricResult.RetryableFailure ->
                false

            is SentriXBiometricResult.TemporaryFailure ->
                true

            is SentriXBiometricResult.Cancelled ->
                true

            is SentriXBiometricResult.LockedOut ->
                true

            is SentriXBiometricResult.ConfigurationRequired ->
                true

            is SentriXBiometricResult.Unsupported ->
                true

            is SentriXBiometricResult.Failure ->
                true
        }
    }

    // -------------------------------------------------------------------------
    // Security Classification
    // -------------------------------------------------------------------------

    /**
     * Returns the security significance of a result.
     */
    fun getSecuritySeverity(
        result: SentriXBiometricResult
    ): BiometricAuditSeverity {

        return when (result) {

            is SentriXBiometricResult.Authenticated ->
                result.auditSeverity

            is SentriXBiometricResult.RetryableFailure ->
                result.auditSeverity

            is SentriXBiometricResult.TemporaryFailure ->
                result.auditSeverity

            is SentriXBiometricResult.Cancelled ->
                result.auditSeverity

            is SentriXBiometricResult.LockedOut ->
                result.auditSeverity

            is SentriXBiometricResult.ConfigurationRequired ->
                result.auditSeverity

            is SentriXBiometricResult.Unsupported ->
                result.auditSeverity

            is SentriXBiometricResult.Failure ->
                result.auditSeverity
        }
    }

    /**
     * Determines whether an event should be considered security
     * relevant for SentriX audit logging.
     */
    fun isSecurityRelevant(
        result: SentriXBiometricResult
    ): Boolean {

        return when (result) {

            is SentriXBiometricResult.Authenticated ->
                true

            is SentriXBiometricResult.RetryableFailure ->
                true

            is SentriXBiometricResult.TemporaryFailure ->
                true

            is SentriXBiometricResult.Cancelled ->
                false

            is SentriXBiometricResult.LockedOut ->
                true

            is SentriXBiometricResult.ConfigurationRequired ->
                true

            is SentriXBiometricResult.Unsupported ->
                true

            is SentriXBiometricResult.Failure ->
                true
        }
    }

    // -------------------------------------------------------------------------
    // User Guidance
    // -------------------------------------------------------------------------

    /**
     * Returns a safe, generic user-facing message.
     *
     * Raw Android error strings should generally not be exposed
     * directly to security-sensitive UI.
     */
    fun getUserMessage(
        result: SentriXBiometricResult
    ): String {

        return when (result) {

            is SentriXBiometricResult.Authenticated -> {

                "Identity verified successfully."
            }

            is SentriXBiometricResult.RetryableFailure -> {

                "Authentication was not recognized. Please try again."
            }

            is SentriXBiometricResult.TemporaryFailure -> {

                "Biometric authentication is temporarily unavailable."
            }

            is SentriXBiometricResult.Cancelled -> {

                "Authentication was cancelled."
            }

            is SentriXBiometricResult.LockedOut -> {

                if (result.permanent) {
                    "Biometric authentication is locked. Use the device security settings."
                } else {
                    "Biometric authentication is temporarily locked. Try again later."
                }
            }

            is SentriXBiometricResult.ConfigurationRequired -> {

                when (result.requirement) {

                    BiometricConfigurationRequirement.BiometricEnrollment ->
                        "Enroll a biometric on this device to use biometric protection."

                    BiometricConfigurationRequirement.DeviceCredential ->
                        "Configure a device PIN, password, or pattern."

                    BiometricConfigurationRequirement.SecurityUpdate ->
                        "Update the device security software before continuing."
                }
            }

            is SentriXBiometricResult.Unsupported -> {

                "This authentication method is not supported on this device."
            }

            is SentriXBiometricResult.Failure -> {

                "Authentication could not be completed."
            }
        }
    }

    // -------------------------------------------------------------------------
    // Failed Attempt Information
    // -------------------------------------------------------------------------

    /**
     * Returns the number of biometric failures observed by this
     * result handler.
     */
    fun getFailedAttemptCount(): Int {
        return failedAttemptCount
    }

    /**
     * Determines whether the handler has observed repeated failures.
     *
     * This is an application-level signal only and must not be used
     * to replace Android's own biometric lockout mechanism.
     */
    fun hasRepeatedFailures(): Boolean {

        return failedAttemptCount >=
                REPEATED_FAILURE_THRESHOLD
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /**
     * Returns the most recently normalized result.
     */
    fun getLastResult():
            SentriXBiometricResult? {

        return lastResult
    }

    /**
     * Clears transient result state.
     */
    fun reset() {

        lastResult = null

        failedAttemptCount = 0
    }

    // -------------------------------------------------------------------------
    // Message Sanitization
    // -------------------------------------------------------------------------

    /**
     * Sanitizes framework/vendor messages before exposing them
     * through SentriX.
     *
     * The original framework message should not become part of
     * security decisions.
     */
    private fun sanitizeMessage(
        message: String
    ): String {

        if (message.isBlank()) {

            return "Biometric authentication could not be completed."
        }

        /**
         * Limit message length to avoid unexpectedly large framework
         * or vendor-generated strings entering application logs/UI.
         */
        return message
            .trim()
            .take(MAX_MESSAGE_LENGTH)
    }

    companion object {

        /**
         * Number of failures considered a repeated-failure pattern
         * for SentriX application-level telemetry.
         */
        private const val REPEATED_FAILURE_THRESHOLD = 3

        /**
         * Maximum framework/vendor message length retained.
         */
        private const val MAX_MESSAGE_LENGTH = 256
    }
}

/**
 * Normalized SentriX biometric authentication result.
 *
 * Higher-level SentriX components should consume this abstraction
 * instead of Android BiometricPrompt error codes.
 */
sealed class SentriXBiometricResult {

    /**
     * Authentication completed successfully.
     */
    data class Authenticated(
        val securityLevel: BiometricSecurityLevel,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()

    /**
     * Authentication failed for a retryable reason.
     */
    data class RetryableFailure(
        val reason: BiometricFailureReason,
        val failedAttempts: Int,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()

    /**
     * Authentication was temporarily unavailable.
     */
    data class TemporaryFailure(
        val reason: BiometricFailureReason,
        val message: String,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()

    /**
     * User explicitly cancelled authentication.
     */
    data class Cancelled(
        val message: String,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()

    /**
     * Authentication is locked out.
     */
    data class LockedOut(
        val message: String,
        val permanent: Boolean,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()

    /**
     * Device/user configuration must be changed before authentication
     * can be used.
     */
    data class ConfigurationRequired(
        val requirement: BiometricConfigurationRequirement,
        val message: String,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()

    /**
     * Requested authentication mechanism is unsupported.
     */
    data class Unsupported(
        val reason: String,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()

    /**
     * Unexpected authentication failure.
     */
    data class Failure(
        val reason: BiometricFailureReason,
        val message: String,
        val auditSeverity: BiometricAuditSeverity
    ) : SentriXBiometricResult()
}

/**
 * Reason associated with a normalized biometric failure.
 */
enum class BiometricFailureReason {

    /**
     * Biometric did not match the enrolled biometric.
     */
    AuthenticationMismatch,

    /**
     * Authentication prompt timed out.
     */
    AuthenticationTimeout,

    /**
     * Biometric hardware is unavailable.
     */
    HardwareUnavailable,

    /**
     * Android could not process the biometric request.
     */
    ProcessingError,

    /**
     * Device/vendor-specific biometric failure.
     */
    VendorError,

    /**
     * Unknown authentication problem.
     */
    Unknown,

    /**
     * Unexpected application/system error.
     */
    SystemError
}

/**
 * Configuration required before biometric authentication can work.
 */
enum class BiometricConfigurationRequirement {

    /**
     * User needs to enroll a biometric.
     */
    BiometricEnrollment,

    /**
     * User needs to configure device credentials.
     */
    DeviceCredential,

    /**
     * Device security software requires an update.
     */
    SecurityUpdate
}

/**
 * Security significance assigned to biometric events.
 *
 * These values are intended for SentriX security telemetry and
 * audit classification.
 */
enum class BiometricAuditSeverity {

    /**
     * Normal informational event.
     */
    INFO,

    /**
     * Minor security event.
     */
    LOW,

    /**
     * Security-relevant operational issue.
     */
    MEDIUM,

    /**
     * Significant security event.
     */
    HIGH,

    /**
     * Critical security event such as permanent biometric lockout.
     */
    CRITICAL
}
