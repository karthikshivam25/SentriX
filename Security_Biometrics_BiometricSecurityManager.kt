package com.sentrix.security.biometrics

import android.content.Context
import androidx.fragment.app.FragmentActivity

/**
 * SentriX Biometric Security Manager
 *
 * High-level biometric security coordinator for protected SentriX
 * operations.
 *
 * Responsibilities:
 *
 * - Define biometric protection requirements.
 * - Determine whether an operation requires authentication.
 * - Validate the current device against a required security level.
 * - Launch biometric authentication for protected operations.
 * - Track authentication state for the current application session.
 * - Manage authentication expiry.
 * - Support step-up authentication for high-risk operations.
 * - Provide security decisions to higher application layers.
 *
 * This class DOES NOT:
 *
 * - Store biometric templates.
 * - Access fingerprint data.
 * - Access facial recognition data.
 * - Implement biometric recognition.
 * - Store biometric credentials.
 * - Replace Android's biometric security subsystem.
 *
 * Android remains responsible for biometric verification.
 *
 * Architecture:
 *
 *      SentriX Feature
 *            │
 *            ▼
 *   BiometricSecurityManager
 *            │
 *       ┌────┴────┐
 *       ▼         ▼
 * BiometricManager  BiometricAuthenticator
 *       │                 │
 *       │                 ▼
 *       │          BiometricPrompt
 *       │                 │
 *       └────────► Android Biometric System
 */
class BiometricSecurityManager(
    private val context: Context,
    private val biometricAuthenticator: BiometricAuthenticator =
        BiometricAuthenticator()
) {

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    /**
     * Application context is retained instead of an Activity context.
     *
     * This prevents the manager itself from unnecessarily holding
     * an Activity reference.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Timestamp of the last successful authentication.
     *
     * This is kept only in memory.
     *
     * A successful biometric authentication should not be persisted
     * as a permanent authorization token by this manager.
     */
    private var lastSuccessfulAuthenticationTime: Long? =
        null

    /**
     * Security level associated with the most recent authentication.
     */
    private var lastAuthenticationLevel:
            BiometricSecurityLevel? = null

    /**
     * Current session authentication state.
     */
    private var authenticationState:
            BiometricSessionState =
        BiometricSessionState.NotAuthenticated

    // -------------------------------------------------------------------------
    // Authentication State
    // -------------------------------------------------------------------------

    /**
     * Returns the current biometric session state.
     */
    fun getAuthenticationState(): BiometricSessionState {
        return authenticationState
    }

    /**
     * Determines whether the current session has a valid biometric
     * authorization.
     *
     * The authorization automatically expires after the configured
     * timeout.
     */
    fun isAuthenticated(): Boolean {

        val timestamp =
            lastSuccessfulAuthenticationTime
                ?: return false

        val level =
            lastAuthenticationLevel
                ?: return false

        val timeout =
            BiometricSecurityTimeout.DEFAULT_TIMEOUT_MILLIS

        val currentTime =
            System.currentTimeMillis()

        val isWithinTimeout =
            currentTime - timestamp < timeout

        if (!isWithinTimeout) {

            clearAuthenticationState()

            return false
        }

        return authenticationState is
                BiometricSessionState.Authenticated &&
                level != BiometricSecurityLevel.NONE
    }

    /**
     * Determines whether the current session satisfies a minimum
     * authentication level.
     */
    fun satisfiesAuthenticationLevel(
        requiredLevel: BiometricSecurityLevel
    ): Boolean {

        if (!isAuthenticated()) {
            return false
        }

        val authenticatedLevel =
            lastAuthenticationLevel
                ?: return false

        return authenticatedLevel.ordinal >=
                requiredLevel.ordinal
    }

    // -------------------------------------------------------------------------
    // Security Requirement Evaluation
    // -------------------------------------------------------------------------

    /**
     * Determines whether the current device can satisfy a protected
     * operation's biometric security requirement.
     */
    fun evaluateSecurityRequirement(
        requirement: BiometricSecurityRequirement
    ): BiometricSecurityDecision {

        if (!requirement.requiresAuthentication) {

            return BiometricSecurityDecision.NotRequired
        }

        if (
            requirement.requireFreshAuthentication &&
            isAuthenticated()
        ) {

            /**
             * Even if a session is authenticated, a sensitive operation
             * may explicitly require a fresh authentication prompt.
             */
            return BiometricSecurityDecision.AuthenticationRequired
        }

        if (
            !requirement.requireFreshAuthentication &&
            satisfiesAuthenticationLevel(
                requirement.minimumSecurityLevel
            )
        ) {

            return BiometricSecurityDecision.AlreadyAuthenticated
        }

        val availableLevel =
            BiometricManager.getAvailableSecurityLevel(
                applicationContext
            )

        if (availableLevel == BiometricSecurityLevel.NONE) {

            return BiometricSecurityDecision.Unavailable(
                "No supported authentication mechanism is available."
            )
        }

        if (
            availableLevel.ordinal <
            requirement.minimumSecurityLevel.ordinal
        ) {

            return BiometricSecurityDecision.InsufficientSecurityLevel(
                required =
                    requirement.minimumSecurityLevel,
                available =
                    availableLevel
            )
        }

        return BiometricSecurityDecision.AuthenticationRequired
    }

    // -------------------------------------------------------------------------
    // Protected Operation Authentication
    // -------------------------------------------------------------------------

    /**
     * Authenticates a protected SentriX operation.
     *
     * The operation is not considered authorized until the Android
     * biometric system reports successful authentication.
     *
     * @param activity Activity used to display BiometricPrompt.
     * @param requirement Required security policy.
     * @param title Authentication prompt title.
     * @param subtitle Authentication prompt subtitle.
     * @param description Optional prompt description.
     * @param callback Result callback.
     */
    fun authenticateForOperation(
        activity: FragmentActivity,
        requirement: BiometricSecurityRequirement,
        title: String,
        subtitle: String? = null,
        description: String? = null,
        callback: (BiometricSecurityResult) -> Unit
    ) {

        val decision =
            evaluateSecurityRequirement(
                requirement
            )

        when (decision) {

            BiometricSecurityDecision.NotRequired -> {

                authenticationState =
                    BiometricSessionState.NotRequired

                callback(
                    BiometricSecurityResult.NotRequired
                )

                return
            }

            BiometricSecurityDecision.AlreadyAuthenticated -> {

                callback(
                    BiometricSecurityResult.AlreadyAuthenticated
                )

                return
            }

            is BiometricSecurityDecision.Unavailable -> {

                authenticationState =
                    BiometricSessionState.Unavailable

                callback(
                    BiometricSecurityResult.Unavailable(
                        decision.reason
                    )
                )

                return
            }

            is BiometricSecurityDecision.InsufficientSecurityLevel -> {

                authenticationState =
                    BiometricSessionState.InsufficientSecurity

                callback(
                    BiometricSecurityResult.InsufficientSecurityLevel(
                        required =
                            decision.required,
                        available =
                            decision.available
                    )
                )

                return
            }

            BiometricSecurityDecision.AuthenticationRequired -> {
                // Continue with biometric authentication.
            }
        }

        authenticationState =
            BiometricSessionState.Authenticating

        val policy =
            createPolicyForRequirement(
                requirement
            )

        val resultCallback:
            (BiometricAuthenticationResult) -> Unit =
            { result ->

                when (result) {

                    BiometricAuthenticationResult.Success -> {

                        registerSuccessfulAuthentication(
                            requirement.minimumSecurityLevel
                        )

                        callback(
                            BiometricSecurityResult.Authenticated(
                                securityLevel =
                                    requirement.minimumSecurityLevel
                            )
                        )
                    }

                    BiometricAuthenticationResult.FailedAttempt -> {

                        authenticationState =
                            BiometricSessionState.AuthenticationAttemptFailed

                        callback(
                            BiometricSecurityResult.AuthenticationAttemptFailed
                        )
                    }

                    is BiometricAuthenticationResult.Cancelled -> {

                        authenticationState =
                            BiometricSessionState.Cancelled

                        callback(
                            BiometricSecurityResult.Cancelled(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.LockedOut -> {

                        authenticationState =
                            BiometricSessionState.LockedOut

                        callback(
                            BiometricSecurityResult.LockedOut(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.PermanentlyLockedOut -> {

                        authenticationState =
                            BiometricSessionState.PermanentlyLockedOut

                        callback(
                            BiometricSecurityResult.PermanentlyLockedOut(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.HardwareUnavailable -> {

                        authenticationState =
                            BiometricSessionState.Unavailable

                        callback(
                            BiometricSecurityResult.Unavailable(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.NotEnrolled -> {

                        authenticationState =
                            BiometricSessionState.NotEnrolled

                        callback(
                            BiometricSecurityResult.NotEnrolled(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.NoDeviceCredential -> {

                        authenticationState =
                            BiometricSessionState.Unavailable

                        callback(
                            BiometricSecurityResult.Unavailable(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.Timeout -> {

                        authenticationState =
                            BiometricSessionState.AuthenticationFailed

                        callback(
                            BiometricSecurityResult.Timeout(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.ProcessingError -> {

                        authenticationState =
                            BiometricSessionState.AuthenticationFailed

                        callback(
                            BiometricSecurityResult.AuthenticationFailed(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.VendorError -> {

                        authenticationState =
                            BiometricSessionState.AuthenticationFailed

                        callback(
                            BiometricSecurityResult.AuthenticationFailed(
                                result.message
                            )
                        )
                    }

                    BiometricAuthenticationResult.SecurityUpdateRequired -> {

                        authenticationState =
                            BiometricSessionState.SecurityUpdateRequired

                        callback(
                            BiometricSecurityResult.SecurityUpdateRequired
                        )
                    }

                    is BiometricAuthenticationResult.NotSupported -> {

                        authenticationState =
                            BiometricSessionState.Unsupported

                        callback(
                            BiometricSecurityResult.Unsupported(
                                result.reason
                            )
                        )
                    }

                    is BiometricAuthenticationResult.UnknownError -> {

                        authenticationState =
                            BiometricSessionState.AuthenticationFailed

                        callback(
                            BiometricSecurityResult.AuthenticationFailed(
                                result.message
                            )
                        )
                    }

                    is BiometricAuthenticationResult.Error -> {

                        authenticationState =
                            BiometricSessionState.AuthenticationFailed

                        callback(
                            BiometricSecurityResult.Error(
                                result.cause
                            )
                        )
                    }
                }
            }

        biometricAuthenticator.authenticate(
            activity = activity,
            title = title,
            subtitle = subtitle,
            description = description,
            policy = policy,
            callback = resultCallback
        )
    }

    // -------------------------------------------------------------------------
    // Convenience Protected Operations
    // -------------------------------------------------------------------------

    /**
     * Authenticates a normal protected SentriX operation.
     */
    fun authenticateDefault(
        activity: FragmentActivity,
        title: String =
            "SentriX Security Verification",
        subtitle: String =
            "Verify your identity to continue",
        callback: (BiometricSecurityResult) -> Unit
    ) {

        authenticateForOperation(
            activity = activity,
            requirement =
                BiometricSecurityRequirement.default(),
            title = title,
            subtitle = subtitle,
            callback = callback
        )
    }

    /**
     * Authenticates a high-risk SentriX operation.
     *
     * Requires strong biometric authentication and fresh authentication.
     */
    fun authenticateHighSecurity(
        activity: FragmentActivity,
        title: String =
            "SentriX High-Security Verification",
        subtitle: String =
            "Strong biometric authentication required",
        callback: (BiometricSecurityResult) -> Unit
    ) {

        authenticateForOperation(
            activity = activity,
            requirement =
                BiometricSecurityRequirement.highSecurity(),
            title = title,
            subtitle = subtitle,
            callback = callback
        )
    }

    /**
     * Performs step-up authentication.
     *
     * Step-up authentication is used when an already authenticated
     * session needs a stronger authentication level for a sensitive
     * operation.
     */
    fun authenticateStepUp(
        activity: FragmentActivity,
        requiredLevel: BiometricSecurityLevel,
        title: String =
            "Additional Security Verification",
        subtitle: String =
            "Additional verification is required",
        callback: (BiometricSecurityResult) -> Unit
    ) {

        val requirement =
            BiometricSecurityRequirement(
                requiresAuthentication = true,
                minimumSecurityLevel =
                    requiredLevel,
                requireFreshAuthentication = true,
                allowCredentialFallback =
                    requiredLevel !=
                            BiometricSecurityLevel.STRONG_BIOMETRIC
            )

        authenticateForOperation(
            activity = activity,
            requirement = requirement,
            title = title,
            subtitle = subtitle,
            callback = callback
        )
    }

    // -------------------------------------------------------------------------
    // Session Management
    // -------------------------------------------------------------------------

    /**
     * Records a successful authentication.
     *
     * Only an in-memory timestamp is retained.
     */
    private fun registerSuccessfulAuthentication(
        securityLevel: BiometricSecurityLevel
    ) {

        lastSuccessfulAuthenticationTime =
            System.currentTimeMillis()

        lastAuthenticationLevel =
            securityLevel

        authenticationState =
            BiometricSessionState.Authenticated(
                securityLevel
            )
    }

    /**
     * Clears the current biometric authorization state.
     *
     * This should be called when:
     *
     * - User logs out.
     * - Application enters a security-sensitive background state.
     * - Security policy changes.
     * - Authentication should be explicitly invalidated.
     */
    fun clearAuthenticationState() {

        lastSuccessfulAuthenticationTime =
            null

        lastAuthenticationLevel =
            null

        authenticationState =
            BiometricSessionState.NotAuthenticated
    }

    /**
     * Forces the next protected operation to require authentication.
     */
    fun requireReauthentication() {

        clearAuthenticationState()
    }

    /**
     * Returns the timestamp of the last successful authentication.
     *
     * This is intended for internal security diagnostics.
     */
    fun getLastAuthenticationTime(): Long? {
        return lastSuccessfulAuthenticationTime
    }

    /**
     * Returns the security level of the last successful authentication.
     */
    fun getLastAuthenticationLevel():
            BiometricSecurityLevel? {

        return lastAuthenticationLevel
    }

    // -------------------------------------------------------------------------
    // Security-Level Helpers
    // -------------------------------------------------------------------------

    /**
     * Returns the strongest authentication level available on the device.
     */
    fun getAvailableSecurityLevel():
            BiometricSecurityLevel {

        return BiometricManager
            .getAvailableSecurityLevel(
                applicationContext
            )
    }

    /**
     * Determines whether the device can satisfy a required security level.
     */
    fun canSatisfySecurityLevel(
        requiredLevel: BiometricSecurityLevel
    ): Boolean {

        val availableLevel =
            getAvailableSecurityLevel()

        return availableLevel.ordinal >=
                requiredLevel.ordinal
    }

    // -------------------------------------------------------------------------
    // Policy Construction
    // -------------------------------------------------------------------------

    /**
     * Converts an application-level requirement into the corresponding
     * BiometricManager policy.
     */
    private fun createPolicyForRequirement(
        requirement: BiometricSecurityRequirement
    ): BiometricSecurityPolicy {

        return when {

            requirement.minimumSecurityLevel ==
                    BiometricSecurityLevel.STRONG_BIOMETRIC -> {

                BiometricSecurityPolicy(
                    authenticators =
                        BiometricManager
                            .STRONG_BIOMETRIC,
                    allowDeviceCredentialFallback =
                        false,
                    requireStrongBiometric =
                        true
                )
            }

            requirement.minimumSecurityLevel ==
                    BiometricSecurityLevel.BIOMETRIC -> {

                if (
                    requirement.allowCredentialFallback
                ) {

                    BiometricSecurityPolicy(
                        authenticators =
                            BiometricManager
                                .STRONG_BIOMETRIC_OR_CREDENTIAL,
                        allowDeviceCredentialFallback =
                            true,
                        requireStrongBiometric =
                            false
                    )

                } else {

                    BiometricSecurityPolicy(
                        authenticators =
                            BiometricManager
                                .ANY_BIOMETRIC,
                        allowDeviceCredentialFallback =
                            false,
                        requireStrongBiometric =
                            false
                    )
                }
            }

            requirement.minimumSecurityLevel ==
                    BiometricSecurityLevel.DEVICE_CREDENTIAL -> {

                BiometricSecurityPolicy(
                    authenticators =
                        BiometricManager
                            .DEVICE_CREDENTIAL,
                    allowDeviceCredentialFallback =
                        true,
                    requireStrongBiometric =
                        false
                )
            }

            else -> {

                BiometricManager.getDefaultSecurityPolicy()
            }
        }
    }
}

/**
 * Application-level requirement for protected SentriX operations.
 *
 * Examples:
 *
 * - Opening a protected security report.
 * - Viewing sensitive privacy information.
 * - Changing security settings.
 * - Disabling real-time protection.
 * - Accessing sensitive credentials.
 * - Performing enterprise security actions.
 */
data class BiometricSecurityRequirement(
    val requiresAuthentication: Boolean,
    val minimumSecurityLevel: BiometricSecurityLevel,
    val requireFreshAuthentication: Boolean,
    val allowCredentialFallback: Boolean
) {

    companion object {

        /**
         * Standard SentriX protected operation.
         *
         * Strong biometric is preferred, with secure credential fallback.
         */
        fun default(): BiometricSecurityRequirement {

            return BiometricSecurityRequirement(
                requiresAuthentication = true,
                minimumSecurityLevel =
                    BiometricSecurityLevel.BIOMETRIC,
                requireFreshAuthentication = false,
                allowCredentialFallback = true
            )
        }

        /**
         * High-security operation.
         *
         * Requires strong biometric authentication and does not reuse
         * an existing session authentication.
         */
        fun highSecurity(): BiometricSecurityRequirement {

            return BiometricSecurityRequirement(
                requiresAuthentication = true,
                minimumSecurityLevel =
                    BiometricSecurityLevel.STRONG_BIOMETRIC,
                requireFreshAuthentication = true,
                allowCredentialFallback = false
            )
        }

        /**
         * Creates an authentication-free requirement.
         */
        fun none(): BiometricSecurityRequirement {

            return BiometricSecurityRequirement(
                requiresAuthentication = false,
                minimumSecurityLevel =
                    BiometricSecurityLevel.NONE,
                requireFreshAuthentication = false,
                allowCredentialFallback = false
            )
        }
    }
}

/**
 * Decision produced when evaluating whether a protected operation
 * requires biometric authentication.
 */
sealed class BiometricSecurityDecision {

    /**
     * Operation does not require authentication.
     */
    data object NotRequired :
        BiometricSecurityDecision()

    /**
     * Existing session authentication is sufficient.
     */
    data object AlreadyAuthenticated :
        BiometricSecurityDecision()

    /**
     * Authentication prompt must be displayed.
     */
    data object AuthenticationRequired :
        BiometricSecurityDecision()

    /**
     * No supported authentication mechanism is available.
     */
    data class Unavailable(
        val reason: String
    ) : BiometricSecurityDecision()

    /**
     * Device has authentication available, but not at the required
     * security level.
     */
    data class InsufficientSecurityLevel(
        val required: BiometricSecurityLevel,
        val available: BiometricSecurityLevel
    ) : BiometricSecurityDecision()
}

/**
 * Current SentriX biometric session state.
 */
sealed class BiometricSessionState {

    /**
     * No authentication has been performed.
     */
    data object NotAuthenticated :
        BiometricSessionState()

    /**
     * Authentication is not required for the current operation.
     */
    data object NotRequired :
        BiometricSessionState()

    /**
     * Authentication prompt is currently being processed.
     */
    data object Authenticating :
        BiometricSessionState()

    /**
     * User has successfully authenticated.
     */
    data class Authenticated(
        val securityLevel: BiometricSecurityLevel
    ) : BiometricSessionState()

    /**
     * An individual biometric attempt failed.
     */
    data object AuthenticationAttemptFailed :
        BiometricSessionState()

    /**
     * Authentication was cancelled.
     */
    data object Cancelled :
        BiometricSessionState()

    /**
     * Biometric authentication is temporarily unavailable.
     */
    data object Unavailable :
        BiometricSessionState()

    /**
     * No supported biometric is enrolled.
     */
    data object NotEnrolled :
        BiometricSessionState()

    /**
     * Authentication security level is insufficient.
     */
    data object InsufficientSecurity :
        BiometricSessionState()

    /**
     * Authentication mechanism is unsupported.
     */
    data object Unsupported :
        BiometricSessionState()

    /**
     * Authentication is temporarily locked out.
     */
    data object LockedOut :
        BiometricSessionState()

    /**
     * Authentication is permanently locked out.
     */
    data object PermanentlyLockedOut :
        BiometricSessionState()

    /**
     * Android requires a security update.
     */
    data object SecurityUpdateRequired :
        BiometricSessionState()

    /**
     * Authentication failed.
     */
    data object AuthenticationFailed :
        BiometricSessionState()
}

/**
 * Result returned after evaluating or executing a protected
 * SentriX security operation.
 */
sealed class BiometricSecurityResult {

    /**
     * Operation did not require authentication.
     */
    data object NotRequired :
        BiometricSecurityResult()

    /**
     * Existing authentication is sufficient.
     */
    data object AlreadyAuthenticated :
        BiometricSecurityResult()

    /**
     * Authentication succeeded.
     */
    data class Authenticated(
        val securityLevel: BiometricSecurityLevel
    ) : BiometricSecurityResult()

    /**
     * Individual biometric attempt failed.
     */
    data object AuthenticationAttemptFailed :
        BiometricSecurityResult()

    /**
     * User cancelled authentication.
     */
    data class Cancelled(
        val message: String
    ) : BiometricSecurityResult()

    /**
     * Authentication is temporarily locked out.
     */
    data class LockedOut(
        val message: String
    ) : BiometricSecurityResult()

    /**
     * Authentication is permanently locked out.
     */
    data class PermanentlyLockedOut(
        val message: String
    ) : BiometricSecurityResult()

    /**
     * Authentication mechanism is unavailable.
     */
    data class Unavailable(
        val message: String
    ) : BiometricSecurityResult()

    /**
     * Required security level is not available.
     */
    data class InsufficientSecurityLevel(
        val required: BiometricSecurityLevel,
        val available: BiometricSecurityLevel
    ) : BiometricSecurityResult()

    /**
     * No compatible biometric has been enrolled.
     */
    data class NotEnrolled(
        val message: String
    ) : BiometricSecurityResult()

    /**
     * Authentication timed out.
     */
    data class Timeout(
        val message: String
    ) : BiometricSecurityResult()

    /**
     * Generic authentication failure.
     */
    data class AuthenticationFailed(
        val message: String
    ) : BiometricSecurityResult()

    /**
     * Android requires a security update.
     */
    data object SecurityUpdateRequired :
        BiometricSecurityResult()

    /**
     * Requested authentication mechanism is unsupported.
     */
    data class Unsupported(
        val reason: String
    ) : BiometricSecurityResult()

    /**
     * Unexpected error.
     */
    data class Error(
        val cause: Throwable
    ) : BiometricSecurityResult()
}

/**
 * Authentication session timeout configuration.
 */
object BiometricSecurityTimeout {

    /**
     * Default authorization lifetime.
     *
     * The authorization state is intentionally short-lived.
     *
     * High-security operations can additionally require fresh
     * authentication regardless of this timeout.
     */
    const val DEFAULT_TIMEOUT_MILLIS =
        5 * 60 * 1000L
}
