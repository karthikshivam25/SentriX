package com.sentrix.security.biometrics

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

/**
 * SentriX Biometric Authenticator
 *
 * Responsible for executing biometric/device-credential authentication
 * through AndroidX BiometricPrompt.
 *
 * Responsibilities:
 *
 * - Display the Android system biometric prompt.
 * - Apply a SentriX biometric security policy.
 * - Handle successful authentication.
 * - Handle authentication failures.
 * - Handle user cancellation.
 * - Handle lockout conditions.
 * - Handle unavailable authentication mechanisms.
 * - Provide a typed authentication result.
 *
 * This class DOES NOT:
 *
 * - Store fingerprints.
 * - Store facial data.
 * - Access biometric templates.
 * - Implement biometric recognition.
 * - Generate biometric data.
 * - Store authentication secrets.
 * - Decide application-specific authorization rules.
 *
 * Android's biometric subsystem performs the actual biometric matching.
 *
 * Architecture:
 *
 *      SentriX UI
 *          │
 *          ▼
 *   BiometricAuthenticator
 *          │
 *          ▼
 *    BiometricPrompt
 *          │
 *          ▼
 * Android Biometric System
 *          │
 *          ▼
 * Fingerprint / Face / Device Credential
 */
class BiometricAuthenticator {

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    /**
     * Starts biometric authentication.
     *
     * The authentication prompt is displayed by Android's system
     * biometric framework.
     *
     * @param activity Activity that owns the BiometricPrompt lifecycle.
     * @param title Prompt title shown to the user.
     * @param subtitle Optional prompt subtitle.
     * @param description Optional prompt description.
     * @param negativeButtonText Text displayed for the negative action.
     * @param policy SentriX biometric security policy.
     * @param callback Authentication result callback.
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String? = null,
        description: String? = null,
        negativeButtonText: String = "Cancel",
        policy: BiometricSecurityPolicy =
            BiometricManager.getDefaultSecurityPolicy(),
        callback: (BiometricAuthenticationResult) -> Unit
    ) {

        require(title.isNotBlank()) {
            "Biometric prompt title cannot be blank."
        }

        require(negativeButtonText.isNotBlank()) {
            "Negative button text cannot be blank."
        }

        /**
         * Validate that the requested authentication policy is supported
         * before displaying the system prompt.
         */
        val policyValidation =
            BiometricManager.validatePolicy(
                context = activity,
                policy = policy
            )

        when (policyValidation) {

            BiometricPolicyValidation.Supported -> {
                // Continue with authentication.
            }

            is BiometricPolicyValidation.NotSupported -> {

                callback(
                    BiometricAuthenticationResult.NotSupported(
                        policyValidation.reason
                    )
                )

                return
            }

            is BiometricPolicyValidation.TemporarilyUnavailable -> {

                callback(
                    BiometricAuthenticationResult.HardwareUnavailable(
                        policyValidation.reason
                    )
                )

                return
            }

            is BiometricPolicyValidation.NotEnrolled -> {

                callback(
                    BiometricAuthenticationResult.NotEnrolled(
                        policyValidation.reason
                    )
                )

                return
            }

            BiometricPolicyValidation.SecurityUpdateRequired -> {

                callback(
                    BiometricAuthenticationResult.SecurityUpdateRequired
                )

                return
            }

            BiometricPolicyValidation.Unknown -> {

                callback(
                    BiometricAuthenticationResult.UnknownError
                )

                return
            }

            is BiometricPolicyValidation.Error -> {

                callback(
                    BiometricAuthenticationResult.Error(
                        policyValidation.cause
                    )
                )

                return
            }
        }

        /**
         * Build the system biometric prompt.
         *
         * The application never receives biometric templates.
         * Android only returns an authentication outcome.
         */
        val promptInfoBuilder =
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setAllowedAuthenticators(
                    policy.authenticators
                )

        subtitle?.takeIf {
            it.isNotBlank()
        }?.let {
            promptInfoBuilder.setSubtitle(it)
        }

        description?.takeIf {
            it.isNotBlank()
        }?.let {
            promptInfoBuilder.setDescription(it)
        }

        /**
         * Device credential is represented directly by the allowed
         * authenticator configuration.
         *
         * When DEVICE_CREDENTIAL is included, Android controls how the
         * credential fallback is presented.
         *
         * We therefore do not call setNegativeButtonText() when the
         * policy permits device credentials.
         */
        if (
            !policy.allowDeviceCredentialFallback
        ) {

            promptInfoBuilder.setNegativeButtonText(
                negativeButtonText
            )
        }

        val promptInfo =
            try {

                promptInfoBuilder.build()

            } catch (exception: Exception) {

                callback(
                    BiometricAuthenticationResult.Error(
                        exception
                    )
                )

                return
            }

        /**
         * Create the AndroidX biometric prompt.
         *
         * The callback is invoked only with authentication state.
         */
        val biometricPrompt =
            BiometricPrompt(
                activity,
                object :
                    BiometricPrompt.AuthenticationCallback() {

                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {

                        super.onAuthenticationSucceeded(
                            result
                        )

                        callback(
                            BiometricAuthenticationResult.Success
                        )
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {

                        super.onAuthenticationError(
                            errorCode,
                            errString
                        )

                        callback(
                            mapAuthenticationError(
                                errorCode = errorCode,
                                message = errString.toString()
                            )
                        )
                    }

                    override fun onAuthenticationFailed() {

                        super.onAuthenticationFailed()

                        /**
                         * onAuthenticationFailed() does NOT necessarily
                         * mean that the complete authentication operation
                         * has ended.
                         *
                         * Android may allow the user to try again.
                         *
                         * Therefore this callback reports the event but
                         * does not treat it as final cancellation.
                         */
                        callback(
                            BiometricAuthenticationResult.FailedAttempt
                        )
                    }
                }
            )

        try {

            biometricPrompt.authenticate(
                promptInfo
            )

        } catch (exception: Exception) {

            callback(
                BiometricAuthenticationResult.Error(
                    exception
                )
            )
        }
    }

    // -------------------------------------------------------------------------
    // Convenience Authentication Methods
    // -------------------------------------------------------------------------

    /**
     * Performs authentication using the default SentriX policy.
     *
     * Default policy:
     *
     *      Strong biometric OR device credential
     */
    fun authenticateDefault(
        activity: FragmentActivity,
        title: String = "SentriX Security Verification",
        subtitle: String = "Verify your identity to continue",
        description: String? = null,
        callback: (BiometricAuthenticationResult) -> Unit
    ) {

        authenticate(
            activity = activity,
            title = title,
            subtitle = subtitle,
            description = description,
            policy =
                BiometricManager.getDefaultSecurityPolicy(),
            callback = callback
        )
    }

    /**
     * Performs high-security biometric-only authentication.
     *
     * Device credential fallback is disabled.
     *
     * Intended for particularly sensitive operations.
     */
    fun authenticateHighSecurity(
        activity: FragmentActivity,
        title: String = "SentriX High-Security Verification",
        subtitle: String = "Use strong biometric authentication",
        description: String? = null,
        callback: (BiometricAuthenticationResult) -> Unit
    ) {

        authenticate(
            activity = activity,
            title = title,
            subtitle = subtitle,
            description = description,
            policy =
                BiometricManager.getHighSecurityPolicy(),
            callback = callback
        )
    }

    /**
     * Performs flexible biometric authentication.
     *
     * This accepts the biometric classes permitted by the
     * flexible SentriX policy.
     */
    fun authenticateFlexible(
        activity: FragmentActivity,
        title: String = "SentriX Verification",
        subtitle: String = "Verify your identity",
        description: String? = null,
        callback: (BiometricAuthenticationResult) -> Unit
    ) {

        authenticate(
            activity = activity,
            title = title,
            subtitle = subtitle,
            description = description,
            policy =
                BiometricManager.getFlexiblePolicy(),
            callback = callback
        )
    }

    // -------------------------------------------------------------------------
    // Error Mapping
    // -------------------------------------------------------------------------

    /**
     * Converts Android BiometricPrompt error codes into SentriX-specific
     * authentication results.
     *
     * This prevents higher application layers from depending directly
     * on Android framework error constants.
     */
    private fun mapAuthenticationError(
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
    // Authentication State Helpers
    // -------------------------------------------------------------------------

    /**
     * Determines whether an authentication result represents success.
     */
    fun isSuccessful(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.Success
    }

    /**
     * Determines whether authentication was explicitly cancelled.
     */
    fun isCancelled(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.Cancelled
    }

    /**
     * Determines whether authentication is temporarily blocked.
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
     * Determines whether the caller should allow another authentication
     * attempt.
     */
    fun canRetry(
        result: BiometricAuthenticationResult
    ): Boolean {

        return when (result) {

            BiometricAuthenticationResult.Success -> false

            BiometricAuthenticationResult.FailedAttempt -> true

            is BiometricAuthenticationResult.Cancelled -> false

            is BiometricAuthenticationResult.LockedOut -> false

            is BiometricAuthenticationResult.PermanentlyLockedOut -> false

            is BiometricAuthenticationResult.NotSupported -> false

            is BiometricAuthenticationResult.NotEnrolled -> false

            is BiometricAuthenticationResult.NoDeviceCredential -> false

            is BiometricAuthenticationResult.HardwareUnavailable -> true

            is BiometricAuthenticationResult.Timeout -> true

            is BiometricAuthenticationResult.ProcessingError -> true

            is BiometricAuthenticationResult.VendorError -> true

            BiometricAuthenticationResult.SecurityUpdateRequired -> false

            BiometricAuthenticationResult.UnknownError -> false

            is BiometricAuthenticationResult.Error -> false
        }
    }
}

/**
 * Result of a SentriX biometric authentication operation.
 *
 * This abstraction prevents application/domain layers from depending
 * directly on Android BiometricPrompt callback details.
 */
sealed class BiometricAuthenticationResult {

    /**
     * Authentication successfully completed.
     */
    data object Success :
        BiometricAuthenticationResult()

    /**
     * A biometric attempt did not match.
     *
     * This does not necessarily terminate the authentication prompt.
     * Android may allow additional attempts.
     */
    data object FailedAttempt :
        BiometricAuthenticationResult()

    /**
     * User cancelled or explicitly dismissed authentication.
     */
    data class Cancelled(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Authentication was temporarily locked because of repeated
     * failed attempts.
     */
    data class LockedOut(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Authentication has been permanently locked by the biometric
     * subsystem and normally requires device-level authentication or
     * system action before biometric authentication can resume.
     */
    data class PermanentlyLockedOut(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Requested authentication hardware is unavailable.
     */
    data class HardwareUnavailable(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * No required biometric has been enrolled.
     */
    data class NotEnrolled(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Device credential fallback was requested but is unavailable.
     */
    data class NoDeviceCredential(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Authentication operation timed out.
     */
    data class Timeout(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Android could not process the biometric request.
     */
    data class ProcessingError(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Device/vendor-specific biometric error.
     */
    data class VendorError(
        val message: String
    ) : BiometricAuthenticationResult()

    /**
     * Android requires a security update.
     */
    data object SecurityUpdateRequired :
        BiometricAuthenticationResult()

    /**
     * Requested authentication method is not supported.
     */
    data class NotSupported(
        val reason: String
    ) : BiometricAuthenticationResult()

    /**
     * Unknown authentication error.
     */
    data class UnknownError(
        val message: String = "Unknown biometric authentication error."
    ) : BiometricAuthenticationResult()

    /**
     * Unexpected application/system exception.
     */
    data class Error(
        val cause: Throwable
    ) : BiometricAuthenticationResult()
}
