package com.sentrix.security.biometrics

import androidx.biometric.BiometricPrompt

/**
 * SentriX Biometric Authentication Handler
 *
 * Centralizes the handling of biometric authentication events.
 *
 * Responsibilities:
 *
 * - Handle successful authentication.
 * - Handle failed biometric attempts.
 * - Handle user cancellation.
 * - Handle biometric lockout.
 * - Handle hardware failures.
 * - Handle enrollment problems.
 * - Normalize Android BiometricPrompt errors.
 * - Convert authentication events into SentriX-specific results.
 * - Provide retry/security-state information to callers.
 *
 * This class DOES NOT:
 *
 * - Display BiometricPrompt.
 * - Perform biometric recognition.
 * - Store biometric templates.
 * - Store fingerprints.
 * - Store facial data.
 * - Manage Android biometric hardware.
 * - Decide whether a business operation should be authorized.
 *
 * Android performs the actual biometric authentication.
 *
 * Architecture:
 *
 *      BiometricAuthenticator
 *              │
 *              ▼
 *      AuthenticationHandler
 *              │
 *       ┌──────┼──────┐
 *       ▼      ▼      ▼
 *    Success  Failed  Error
 *       │      │      │
 *       └──────┼──────┘
 *              ▼
 *    SentriX Authentication Result
 */
class BiometricAuthenticationHandler {

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    /**
     * Maximum number of application-level failed attempts that SentriX
     * will track during a single authentication session.
     *
     * Android remains responsible for the actual biometric lockout policy.
     *
     * This value is only an application-level observation limit and
     * does not override Android security controls.
     */
    private val maxTrackedFailedAttempts: Int =
        DEFAULT_MAX_TRACKED_FAILED_ATTEMPTS

    // -------------------------------------------------------------------------
    // Runtime State
    // -------------------------------------------------------------------------

    /**
     * Number of failed biometric attempts observed during the current
     * authentication session.
     */
    private var failedAttemptCount: Int = 0

    /**
     * Indicates whether the current authentication session has completed.
     */
    private var authenticationCompleted: Boolean = false

    /**
     * Last processed authentication result.
     */
    private var lastResult:
            BiometricAuthenticationResult? = null

    /**
     * Current authentication state.
     */
    private var state:
            BiometricHandlerState =
        BiometricHandlerState.Idle

    // -------------------------------------------------------------------------
    // Success Handling
    // -------------------------------------------------------------------------

    /**
     * Handles successful Android biometric authentication.
     *
     * A successful authentication resets the application-level
     * failed-attempt counter.
     */
    fun handleSuccess(
        result: BiometricPrompt.AuthenticationResult
    ): BiometricAuthenticationResult {

        failedAttemptCount = 0

        authenticationCompleted = true

        state =
            BiometricHandlerState.Authenticated

        val authenticationResult =
            BiometricAuthenticationResult.Success

        lastResult =
            authenticationResult

        return authenticationResult
    }

    // -------------------------------------------------------------------------
    // Failed Attempt Handling
    // -------------------------------------------------------------------------

    /**
     * Handles an individual biometric mismatch.
     *
     * IMPORTANT:
     *
     * Android may continue displaying the prompt after this callback.
     * Therefore this method does not mark the complete authentication
     * session as finished.
     */
    fun handleFailedAttempt():
            BiometricAuthenticationResult {

        if (
            authenticationCompleted
        ) {

            return lastResult
                ?: BiometricAuthenticationResult
                    .UnknownError(
                        "Authentication session has already completed."
                    )
        }

        failedAttemptCount++

        state =
            BiometricHandlerState.FailedAttempt

        val result =
            BiometricAuthenticationResult.FailedAttempt

        /**
         * SentriX does not attempt to replace Android's own biometric
         * lockout policy.
         *
         * Once Android reports a lockout error, that error is handled
         * separately.
         */
        if (
            failedAttemptCount >=
            maxTrackedFailedAttempts
        ) {

            state =
                BiometricHandlerState.HighFailureRate
        }

        lastResult =
            result

        return result
    }

    // -------------------------------------------------------------------------
    // Error Handling
    // -------------------------------------------------------------------------

    /**
     * Handles an Android BiometricPrompt error.
     */
    fun handleError(
        errorCode: Int,
        message: String
    ): BiometricAuthenticationResult {

        authenticationCompleted = true

        val result =
            mapAndroidError(
                errorCode = errorCode,
                message = message
            )

        state =
            when (result) {

                is BiometricAuthenticationResult.Cancelled ->
                    BiometricHandlerState.Cancelled

                is BiometricAuthenticationResult.LockedOut ->
                    BiometricHandlerState.LockedOut

                is BiometricAuthenticationResult.PermanentlyLockedOut ->
                    BiometricHandlerState.PermanentlyLockedOut

                is BiometricAuthenticationResult.HardwareUnavailable ->
                    BiometricHandlerState.HardwareUnavailable

                is BiometricAuthenticationResult.NotEnrolled ->
                    BiometricHandlerState.NotEnrolled

                is BiometricAuthenticationResult.NoDeviceCredential ->
                    BiometricHandlerState.NoDeviceCredential

                is BiometricAuthenticationResult.Timeout ->
                    BiometricHandlerState.Timeout

                is BiometricAuthenticationResult.ProcessingError ->
                    BiometricHandlerState.ProcessingError

                is BiometricAuthenticationResult.VendorError ->
                    BiometricHandlerState.VendorError

                BiometricAuthenticationResult.SecurityUpdateRequired ->
                    BiometricHandlerState.SecurityUpdateRequired

                is BiometricAuthenticationResult.NotSupported ->
                    BiometricHandlerState.Unsupported

                is BiometricAuthenticationResult.UnknownError ->
                    BiometricHandlerState.UnknownError

                is BiometricAuthenticationResult.Error ->
                    BiometricHandlerState.SystemError

                BiometricAuthenticationResult.Success ->
                    BiometricHandlerState.Authenticated

                BiometricAuthenticationResult.FailedAttempt ->
                    BiometricHandlerState.FailedAttempt
            }

        lastResult =
            result

        return result
    }

    // -------------------------------------------------------------------------
    // Android Error Mapping
    // -------------------------------------------------------------------------

    /**
     * Converts Android BiometricPrompt error codes into the
     * SentriX authentication abstraction.
     */
    private fun mapAndroidError(
        errorCode: Int,
        message: String
    ): BiometricAuthenticationResult {

        return when (errorCode) {

            BiometricPrompt.ERROR_CANCELED -> {

                BiometricAuthenticationResult.Cancelled(
                    message
                )
            }

            BiometricPrompt.ERROR_USER_CANCELED -> {

                BiometricAuthenticationResult.Cancelled(
                    message
                )
            }

            BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {

                BiometricAuthenticationResult.Cancelled(
                    message
                )
            }

            BiometricPrompt.ERROR_LOCKOUT -> {

                BiometricAuthenticationResult.LockedOut(
                    message
                )
            }

            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {

                BiometricAuthenticationResult.PermanentlyLockedOut(
                    message
                )
            }

            BiometricPrompt.ERROR_HW_UNAVAILABLE -> {

                BiometricAuthenticationResult.HardwareUnavailable(
                    message
                )
            }

            BiometricPrompt.ERROR_NO_BIOMETRICS -> {

                BiometricAuthenticationResult.NotEnrolled(
                    message
                )
            }

            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> {

                BiometricAuthenticationResult.NoDeviceCredential(
                    message
                )
            }

            BiometricPrompt.ERROR_NO_SPACE -> {

                BiometricAuthenticationResult.HardwareUnavailable(
                    message
                )
            }

            BiometricPrompt.ERROR_TIMEOUT -> {

                BiometricAuthenticationResult.Timeout(
                    message
                )
            }

            BiometricPrompt.ERROR_UNABLE_TO_PROCESS -> {

                BiometricAuthenticationResult.ProcessingError(
                    message
                )
            }

            BiometricPrompt.ERROR_VENDOR -> {

                BiometricAuthenticationResult.VendorError(
                    message
                )
            }

            BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED -> {

                BiometricAuthenticationResult.SecurityUpdateRequired
            }

            else -> {

                BiometricAuthenticationResult.UnknownError(
                    message
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // Result Classification
    // -------------------------------------------------------------------------

    /**
     * Determines whether authentication was successful.
     */
    fun isSuccess(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.Success
    }

    /**
     * Determines whether the event represents an individual failed
     * biometric attempt.
     */
    fun isFailedAttempt(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.FailedAttempt
    }

    /**
     * Determines whether the user cancelled authentication.
     */
    fun isCancelled(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.Cancelled
    }

    /**
     * Determines whether Android has locked biometric authentication.
     */
    fun isLockedOut(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.LockedOut ||
                result is
                BiometricAuthenticationResult.PermanentlyLockedOut
    }

    /**
     * Determines whether the authentication process can reasonably
     * be retried.
     */
    fun canRetry(
        result: BiometricAuthenticationResult
    ): Boolean {

        return when (result) {

            BiometricAuthenticationResult.Success ->
                false

            BiometricAuthenticationResult.FailedAttempt ->
                true

            is BiometricAuthenticationResult.Cancelled ->
                false

            is BiometricAuthenticationResult.LockedOut ->
                false

            is BiometricAuthenticationResult.PermanentlyLockedOut ->
                false

            is BiometricAuthenticationResult.HardwareUnavailable ->
                true

            is BiometricAuthenticationResult.NotEnrolled ->
                false

            is BiometricAuthenticationResult.NoDeviceCredential ->
                false

            is BiometricAuthenticationResult.Timeout ->
                true

            is BiometricAuthenticationResult.ProcessingError ->
                true

            is BiometricAuthenticationResult.VendorError ->
                true

            BiometricAuthenticationResult.SecurityUpdateRequired ->
                false

            is BiometricAuthenticationResult.NotSupported ->
                false

            is BiometricAuthenticationResult.UnknownError ->
                false

            is BiometricAuthenticationResult.Error ->
                false
        }
    }

    // -------------------------------------------------------------------------
    // Security Classification
    // -------------------------------------------------------------------------

    /**
     * Determines whether an authentication result should be treated
     * as a terminal event.
     *
     * FailedAttempt is intentionally non-terminal because Android can
     * allow another biometric attempt.
     */
    fun isTerminal(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result !is
                BiometricAuthenticationResult.FailedAttempt
    }

    /**
     * Determines whether the result represents a device security
     * configuration problem rather than an authentication mismatch.
     */
    fun isSecurityConfigurationProblem(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.NotEnrolled ||
                result is
                BiometricAuthenticationResult.NoDeviceCredential ||
                result is
                BiometricAuthenticationResult.NotSupported ||
                result is
                BiometricAuthenticationResult.SecurityUpdateRequired
    }

    /**
     * Determines whether the result indicates a temporary system
     * availability problem.
     */
    fun isTemporaryFailure(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.HardwareUnavailable ||
                result is
                BiometricAuthenticationResult.Timeout ||
                result is
                BiometricAuthenticationResult.ProcessingError ||
                result is
                BiometricAuthenticationResult.VendorError
    }

    /**
     * Determines whether the result indicates a user decision.
     */
    fun isUserAction(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.Cancelled ||
                result is
                BiometricAuthenticationResult.FailedAttempt
    }

    // -------------------------------------------------------------------------
    // Session Information
    // -------------------------------------------------------------------------

    /**
     * Returns the current handler state.
     */
    fun getState(): BiometricHandlerState {
        return state
    }

    /**
     * Returns the number of failed biometric attempts observed
     * during the current handler session.
     */
    fun getFailedAttemptCount(): Int {
        return failedAttemptCount
    }

    /**
     * Returns the last processed authentication result.
     */
    fun getLastResult():
            BiometricAuthenticationResult? {

        return lastResult
    }

    /**
     * Determines whether the current handler session has completed.
     */
    fun isCompleted(): Boolean {
        return authenticationCompleted
    }

    /**
     * Determines whether the current session is still capable of
     * accepting biometric attempts.
     */
    fun isSessionActive(): Boolean {

        return !authenticationCompleted &&
                state !=
                BiometricHandlerState.Idle
    }

    // -------------------------------------------------------------------------
    // Session Management
    // -------------------------------------------------------------------------

    /**
     * Starts a new authentication handling session.
     *
     * The handler itself does not launch BiometricPrompt.
     */
    fun startSession() {

        failedAttemptCount = 0

        authenticationCompleted = false

        lastResult = null

        state =
            BiometricHandlerState.Authenticating
    }

    /**
     * Resets the handler into an idle state.
     */
    fun reset() {

        failedAttemptCount = 0

        authenticationCompleted = false

        lastResult = null

        state =
            BiometricHandlerState.Idle
    }

    // -------------------------------------------------------------------------
    // Result Conversion
    // -------------------------------------------------------------------------

    /**
     * Converts an authentication result into a simplified
     * SentriX authentication outcome.
     */
    fun getOutcome(
        result: BiometricAuthenticationResult
    ): BiometricAuthenticationOutcome {

        return when (result) {

            BiometricAuthenticationResult.Success -> {

                BiometricAuthenticationOutcome.Authenticated
            }

            BiometricAuthenticationResult.FailedAttempt -> {

                BiometricAuthenticationOutcome.RetryPossible
            }

            is BiometricAuthenticationResult.Cancelled -> {

                BiometricAuthenticationOutcome.Cancelled
            }

            is BiometricAuthenticationResult.LockedOut -> {

                BiometricAuthenticationOutcome.LockedOut
            }

            is BiometricAuthenticationResult.PermanentlyLockedOut -> {

                BiometricAuthenticationOutcome.PermanentlyLockedOut
            }

            is BiometricAuthenticationResult.NotEnrolled -> {

                BiometricAuthenticationOutcome.EnrollmentRequired
            }

            is BiometricAuthenticationResult.NoDeviceCredential -> {

                BiometricAuthenticationOutcome.CredentialRequired
            }

            is BiometricAuthenticationResult.HardwareUnavailable -> {

                BiometricAuthenticationOutcome.TemporaryFailure
            }

            is BiometricAuthenticationResult.Timeout -> {

                BiometricAuthenticationOutcome.TemporaryFailure
            }

            is BiometricAuthenticationResult.ProcessingError -> {

                BiometricAuthenticationOutcome.TemporaryFailure
            }

            is BiometricAuthenticationResult.VendorError -> {

                BiometricAuthenticationOutcome.TemporaryFailure
            }

            BiometricAuthenticationResult.SecurityUpdateRequired -> {

                BiometricAuthenticationOutcome.SecurityUpdateRequired
            }

            is BiometricAuthenticationResult.NotSupported -> {

                BiometricAuthenticationOutcome.Unsupported
            }

            is BiometricAuthenticationResult.UnknownError -> {

                BiometricAuthenticationOutcome.Failure
            }

            is BiometricAuthenticationResult.Error -> {

                BiometricAuthenticationOutcome.Failure
            }
        }
    }

    companion object {

        /**
         * Default number of application-level failed attempts tracked.
         *
         * This does not override Android's lockout mechanism.
         */
        private const val DEFAULT_MAX_TRACKED_FAILED_ATTEMPTS = 5
    }
}

/**
 * Internal state of the authentication handler.
 */
enum class BiometricHandlerState {

    /**
     * Handler has not started processing an authentication session.
     */
    Idle,

    /**
     * Authentication is currently being processed.
     */
    Authenticating,

    /**
     * One biometric attempt failed.
     */
    FailedAttempt,

    /**
     * A high number of failures has been observed.
     */
    HighFailureRate,

    /**
     * Authentication succeeded.
     */
    Authenticated,

    /**
     * User cancelled authentication.
     */
    Cancelled,

    /**
     * Android biometric hardware is unavailable.
     */
    HardwareUnavailable,

    /**
     * Required biometric is not enrolled.
     */
    NotEnrolled,

    /**
     * Device credential is unavailable.
     */
    NoDeviceCredential,

    /**
     * Authentication timed out.
     */
    Timeout,

    /**
     * Android could not process the authentication request.
     */
    ProcessingError,

    /**
     * Vendor-specific biometric failure.
     */
    VendorError,

    /**
     * Android requires a security update.
     */
    SecurityUpdateRequired,

    /**
     * Requested authentication mechanism is unsupported.
     */
    Unsupported,

    /**
     * Unknown authentication error.
     */
    UnknownError,

    /**
     * Unexpected system exception.
     */
    SystemError
}

/**
 * Simplified authentication outcome for higher-level SentriX
 * security components.
 */
enum class BiometricAuthenticationOutcome {

    /**
     * Authentication succeeded.
     */
    Authenticated,

    /**
     * Individual biometric attempt failed but another attempt
     * may be possible.
     */
    RetryPossible,

    /**
     * User cancelled authentication.
     */
    Cancelled,

    /**
     * Temporary biometric lockout.
     */
    LockedOut,

    /**
     * Permanent biometric lockout.
     */
    PermanentlyLockedOut,

    /**
     * User must enroll a biometric.
     */
    EnrollmentRequired,

    /**
     * Device credential must be configured/available.
     */
    CredentialRequired,

    /**
     * Temporary hardware/system problem.
     */
    TemporaryFailure,

    /**
     * Security update is required.
     */
    SecurityUpdateRequired,

    /**
     * Requested authentication method is unsupported.
     */
    Unsupported,

    /**
     * Authentication failed due to an unexpected error.
     */
    Failure
}
