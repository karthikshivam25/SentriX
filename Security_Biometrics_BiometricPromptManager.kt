package com.sentrix.security.biometrics

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

/**
 * SentriX Biometric Prompt Manager
 *
 * Low-level manager responsible for configuring and displaying
 * AndroidX BiometricPrompt.
 *
 * Responsibilities:
 *
 * - Build BiometricPrompt.PromptInfo.
 * - Configure allowed authenticators.
 * - Configure title/subtitle/description.
 * - Configure negative/cancel action when appropriate.
 * - Display the system biometric prompt.
 * - Forward Android authentication callbacks.
 * - Prevent invalid prompt configurations.
 *
 * This class DOES NOT:
 *
 * - Store biometric information.
 * - Access fingerprint or face templates.
 * - Perform biometric matching.
 * - Decide whether an application feature should be unlocked.
 * - Store authentication state permanently.
 * - Manage encryption keys.
 *
 * Android's biometric subsystem remains responsible for biometric
 * processing and verification.
 *
 * Architecture:
 *
 *      BiometricAuthenticator
 *               │
 *               ▼
 *      BiometricPromptManager
 *               │
 *               ▼
 *        AndroidX BiometricPrompt
 *               │
 *               ▼
 *       Android System Biometric
 */
class BiometricPromptManager {

    // -------------------------------------------------------------------------
    // Prompt State
    // -------------------------------------------------------------------------

    /**
     * Tracks whether this manager currently owns an active prompt.
     *
     * BiometricPrompt itself is lifecycle-aware, but this state prevents
     * accidental duplicate prompt requests from the same manager instance.
     */
    private var isPromptActive = false

    // -------------------------------------------------------------------------
    // Prompt Construction
    // -------------------------------------------------------------------------

    /**
     * Creates a BiometricPrompt.PromptInfo configuration.
     *
     * @param title Prompt title.
     * @param subtitle Optional subtitle.
     * @param description Optional description.
     * @param negativeButtonText Text for the negative action when
     *                           device credentials are not enabled.
     * @param policy SentriX biometric security policy.
     */
    fun buildPromptInfo(
        title: String,
        subtitle: String? = null,
        description: String? = null,
        negativeButtonText: String = "Cancel",
        policy: BiometricSecurityPolicy =
            BiometricManager.getDefaultSecurityPolicy()
    ): BiometricPrompt.PromptInfo {

        require(title.isNotBlank()) {
            "Biometric prompt title cannot be blank."
        }

        require(negativeButtonText.isNotBlank()) {
            "Negative button text cannot be blank."
        }

        validatePolicyConfiguration(
            policy
        )

        val builder =
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setAllowedAuthenticators(
                    policy.authenticators
                )

        subtitle
            ?.takeIf { it.isNotBlank() }
            ?.let {
                builder.setSubtitle(it)
            }

        description
            ?.takeIf { it.isNotBlank() }
            ?.let {
                builder.setDescription(it)
            }

        /**
         * Android's BiometricPrompt does not allow a negative button
         * when DEVICE_CREDENTIAL is included in the authenticator set.
         *
         * In that situation, Android controls the credential fallback.
         */
        if (
            !policy.allowDeviceCredentialFallback
        ) {

            builder.setNegativeButtonText(
                negativeButtonText
            )
        }

        return builder.build()
    }

    // -------------------------------------------------------------------------
    // Prompt Creation
    // -------------------------------------------------------------------------

    /**
     * Creates a BiometricPrompt using the supplied activity and callback.
     *
     * This method only creates the prompt. It does not display it.
     */
    fun createPrompt(
        activity: FragmentActivity,
        callback: BiometricPromptCallback
    ): BiometricPrompt {

        requireNotNull(activity) {
            "FragmentActivity cannot be null."
        }

        return BiometricPrompt(
            activity,
            object :
                BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {

                    super.onAuthenticationSucceeded(
                        result
                    )

                    isPromptActive = false

                    callback.onSuccess(
                        result
                    )
                }

                override fun onAuthenticationFailed() {

                    super.onAuthenticationFailed()

                    /**
                     * A failed attempt does not necessarily terminate
                     * the prompt.
                     */
                    callback.onFailedAttempt()
                }

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {

                    super.onAuthenticationError(
                        errorCode,
                        errString
                    )

                    isPromptActive = false

                    callback.onError(
                        errorCode = errorCode,
                        message = errString.toString()
                    )
                }
            }
        )
    }

    // -------------------------------------------------------------------------
    // Prompt Display
    // -------------------------------------------------------------------------

    /**
     * Displays the biometric prompt.
     *
     * @return PromptLaunchResult describing whether the prompt was
     *         successfully launched.
     */
    fun showPrompt(
        prompt: BiometricPrompt,
        promptInfo: BiometricPrompt.PromptInfo
    ): PromptLaunchResult {

        if (isPromptActive) {

            return PromptLaunchResult.AlreadyActive
        }

        return try {

            isPromptActive = true

            prompt.authenticate(
                promptInfo
            )

            PromptLaunchResult.Launched

        } catch (exception: Exception) {

            isPromptActive = false

            PromptLaunchResult.FailedToLaunch(
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Convenience API
    // -------------------------------------------------------------------------

    /**
     * Builds and immediately launches a biometric prompt.
     *
     * This method is useful when a caller does not need separate
     * prompt construction and display phases.
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String? = null,
        description: String? = null,
        negativeButtonText: String = "Cancel",
        policy: BiometricSecurityPolicy =
            BiometricManager.getDefaultSecurityPolicy(),
        callback: BiometricPromptCallback
    ): PromptLaunchResult {

        /**
         * Validate the requested policy before creating the prompt.
         */
        val policyValidation =
            BiometricManager.validatePolicy(
                context = activity,
                policy = policy
            )

        if (
            policyValidation !is
            BiometricPolicyValidation.Supported
        ) {

            return PromptLaunchResult.PolicyUnavailable(
                policyValidation
            )
        }

        val promptInfo =
            try {

                buildPromptInfo(
                    title = title,
                    subtitle = subtitle,
                    description = description,
                    negativeButtonText =
                        negativeButtonText,
                    policy = policy
                )

            } catch (exception: Exception) {

                return PromptLaunchResult.FailedToBuild(
                    exception
                )
            }

        val prompt =
            createPrompt(
                activity = activity,
                callback = callback
            )

        return showPrompt(
            prompt = prompt,
            promptInfo = promptInfo
        )
    }

    /**
     * Convenience method using the default SentriX policy.
     */
    fun authenticateDefault(
        activity: FragmentActivity,
        title: String =
            "SentriX Security Verification",
        subtitle: String =
            "Verify your identity to continue",
        description: String? = null,
        callback: BiometricPromptCallback
    ): PromptLaunchResult {

        return authenticate(
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
     * Convenience method for high-security operations.
     *
     * Strong biometric authentication is required and device credential
     * fallback is disabled.
     */
    fun authenticateHighSecurity(
        activity: FragmentActivity,
        title: String =
            "SentriX High-Security Verification",
        subtitle: String =
            "Strong biometric authentication required",
        description: String? = null,
        callback: BiometricPromptCallback
    ): PromptLaunchResult {

        return authenticate(
            activity = activity,
            title = title,
            subtitle = subtitle,
            description = description,
            policy =
                BiometricManager.getHighSecurityPolicy(),
            callback = callback
        )
    }

    // -------------------------------------------------------------------------
    // Prompt State
    // -------------------------------------------------------------------------

    /**
     * Returns whether this manager currently considers a prompt active.
     */
    fun isPromptActive(): Boolean {
        return isPromptActive
    }

    /**
     * Resets local prompt state.
     *
     * This does not force-dismiss the Android system prompt.
     *
     * It should normally only be used when the owning UI lifecycle
     * has ended and the manager instance is being discarded.
     */
    fun resetState() {
        isPromptActive = false
    }

    // -------------------------------------------------------------------------
    // Policy Validation
    // -------------------------------------------------------------------------

    /**
     * Validates a SentriX biometric policy before passing it to
     * AndroidX BiometricPrompt.
     */
    private fun validatePolicyConfiguration(
        policy: BiometricSecurityPolicy
    ) {

        require(
            policy.authenticators != 0
        ) {
            "At least one biometric authenticator must be configured."
        }

        /**
         * Device credential fallback and an explicit negative button
         * are mutually exclusive in AndroidX BiometricPrompt.
         *
         * The manager handles this automatically by only adding the
         * negative button when credential fallback is disabled.
         */
    }

    // -------------------------------------------------------------------------
    // Prompt Cancellation
    // -------------------------------------------------------------------------

    /**
     * Clears the manager's active state.
     *
     * AndroidX BiometricPrompt does not expose a universal force-cancel
     * API through this abstraction, so lifecycle destruction should be
     * relied upon to dispose of the prompt where appropriate.
     */
    fun markPromptCancelled() {
        isPromptActive = false
    }
}

/**
 * Callback abstraction around AndroidX BiometricPrompt.
 *
 * This keeps the manager's consumers independent of the raw Android
 * callback implementation.
 */
interface BiometricPromptCallback {

    /**
     * Called when authentication succeeds.
     */
    fun onSuccess(
        result: BiometricPrompt.AuthenticationResult
    )

    /**
     * Called when an individual biometric attempt fails.
     *
     * This does not necessarily terminate the prompt.
     */
    fun onFailedAttempt()

    /**
     * Called when authentication terminates with an Android error.
     */
    fun onError(
        errorCode: Int,
        message: String
    )
}

/**
 * Result of attempting to display the biometric prompt.
 */
sealed class PromptLaunchResult {

    /**
     * Prompt was successfully submitted to Android.
     */
    data object Launched :
        PromptLaunchResult()

    /**
     * A prompt is already active for this manager instance.
     */
    data object AlreadyActive :
        PromptLaunchResult()

    /**
     * The requested authentication policy is unavailable.
     */
    data class PolicyUnavailable(
        val validation: BiometricPolicyValidation
    ) : PromptLaunchResult()

    /**
     * Prompt configuration could not be built.
     */
    data class FailedToBuild(
        val cause: Throwable
    ) : PromptLaunchResult()

    /**
     * Android rejected the prompt launch.
     */
    data class FailedToLaunch(
        val cause: Throwable
    ) : PromptLaunchResult()
}
