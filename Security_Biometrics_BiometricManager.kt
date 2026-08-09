package com.sentrix.security.biometrics

import android.content.Context
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricManager as AndroidBiometricManager

/**
 * SentriX Biometric Manager
 *
 * Central manager for biometric capability detection and biometric
 * authentication policy.
 *
 * Responsibilities:
 *
 * - Detect biometric hardware availability.
 * - Determine whether biometric authentication can be used.
 * - Determine supported authenticator types.
 * - Check whether device credentials can be used as fallback.
 * - Expose biometric capability information.
 * - Validate SentriX biometric security requirements.
 * - Provide authentication configuration for the UI layer.
 *
 * This class DOES NOT:
 *
 * - Display biometric prompts directly.
 * - Manage Activity/Fragment UI.
 * - Store biometric templates.
 * - Store fingerprints or face data.
 * - Capture biometric information.
 * - Implement fingerprint/face recognition itself.
 *
 * Android's system biometric framework is responsible for the actual
 * biometric processing.
 *
 * Architecture:
 *
 *      Presentation
 *           │
 *           ▼
 *      BiometricManager
 *           │
 *           ▼
 *      AndroidX Biometric
 *           │
 *           ▼
 *      Android System Biometric Hardware
 *
 * For actual authentication UI, use the separate
 * BiometricAuthenticator / BiometricPrompt integration layer.
 */
object BiometricManager {

    // -------------------------------------------------------------------------
    // Authenticator Policies
    // -------------------------------------------------------------------------

    /**
     * Strong biometric authentication.
     *
     * BIOMETRIC_STRONG generally represents biometric methods meeting
     * Android's strongest biometric security class.
     */
    const val STRONG_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG

    /**
     * Weak biometric authentication.
     *
     * This may include biometric methods that do not satisfy the
     * strongest Android biometric security class.
     */
    const val WEAK_BIOMETRIC =
        Authenticators.BIOMETRIC_WEAK

    /**
     * Device credential authentication.
     *
     * This includes:
     *
     * - PIN
     * - Password
     * - Pattern
     */
    const val DEVICE_CREDENTIAL =
        Authenticators.DEVICE_CREDENTIAL

    /**
     * Strong biometric OR device credential.
     *
     * Recommended when SentriX wants a secure fallback mechanism.
     */
    const val STRONG_BIOMETRIC_OR_CREDENTIAL =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.DEVICE_CREDENTIAL

    /**
     * Biometric-only policy.
     *
     * Allows either strong or weak biometrics but does not allow
     * device credentials as fallback.
     */
    const val ANY_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.BIOMETRIC_WEAK

    // -------------------------------------------------------------------------
    // Availability
    // -------------------------------------------------------------------------

    /**
     * Returns the AndroidX biometric manager.
     */
    private fun getAndroidBiometricManager(
        context: Context
    ): AndroidBiometricManager {

        return AndroidBiometricManager.from(
            context.applicationContext
        )
    }

    /**
     * Checks whether strong biometric authentication is available.
     *
     * Strong biometric authentication is preferred for high-risk
     * SentriX operations.
     */
    fun isStrongBiometricAvailable(
        context: Context
    ): Boolean {

        return getAuthenticationStatus(
            context = context,
            authenticators = Authenticators.BIOMETRIC_STRONG
        ).isAvailable
    }

    /**
     * Checks whether any biometric authentication is available.
     */
    fun isBiometricAvailable(
        context: Context
    ): Boolean {

        return getAuthenticationStatus(
            context = context,
            authenticators = ANY_BIOMETRIC
        ).isAvailable
    }

    /**
     * Checks whether biometric authentication or device credentials
     * can satisfy the specified policy.
     */
    fun isAuthenticationAvailable(
        context: Context,
        authenticators: Int =
            STRONG_BIOMETRIC_OR_CREDENTIAL
    ): Boolean {

        return getAuthenticationStatus(
            context = context,
            authenticators = authenticators
        ).isAvailable
    }

    // -------------------------------------------------------------------------
    // Authentication Status
    // -------------------------------------------------------------------------

    /**
     * Returns a detailed biometric capability status.
     *
     * The returned status allows SentriX to distinguish between:
     *
     * - Hardware unavailable.
     * - Hardware exists but no biometric is enrolled.
     * - Authentication is temporarily unavailable.
     * - Authentication is permanently unavailable.
     * - Authentication is available.
     */
    fun getAuthenticationStatus(
        context: Context,
        authenticators: Int =
            STRONG_BIOMETRIC_OR_CREDENTIAL
    ): BiometricAvailability {

        return try {

            val biometricManager =
                getAndroidBiometricManager(
                    context
                )

            val result =
                biometricManager.canAuthenticate(
                    authenticators
                )

            when (result) {

                AndroidBiometricManager.BIOMETRIC_SUCCESS -> {

                    BiometricAvailability.Available
                }

                AndroidBiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {

                    BiometricAvailability.NoHardware
                }

                AndroidBiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {

                    BiometricAvailability.HardwareUnavailable
                }

                AndroidBiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {

                    BiometricAvailability.NoneEnrolled
                }

                AndroidBiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {

                    BiometricAvailability.SecurityUpdateRequired
                }

                AndroidBiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> {

                    BiometricAvailability.Unsupported
                }

                AndroidBiometricManager.BIOMETRIC_STATUS_UNKNOWN -> {

                    BiometricAvailability.Unknown
                }

                else -> {

                    BiometricAvailability.Unknown
                }
            }

        } catch (exception: Exception) {

            BiometricAvailability.Error(
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Policy-Specific Checks
    // -------------------------------------------------------------------------

    /**
     * Checks whether SentriX can require strong biometric authentication.
     */
    fun canUseStrongBiometric(
        context: Context
    ): Boolean {

        return getAuthenticationStatus(
            context = context,
            authenticators =
                Authenticators.BIOMETRIC_STRONG
        ).isAvailable
    }

    /**
     * Checks whether SentriX can require biometric authentication
     * without a device credential fallback.
     */
    fun canUseBiometricOnly(
        context: Context
    ): Boolean {

        return getAuthenticationStatus(
            context = context,
            authenticators = ANY_BIOMETRIC
        ).isAvailable
    }

    /**
     * Checks whether SentriX can use strong biometric authentication
     * with device credential fallback.
     */
    fun canUseBiometricWithCredentialFallback(
        context: Context
    ): Boolean {

        return getAuthenticationStatus(
            context = context,
            authenticators =
                STRONG_BIOMETRIC_OR_CREDENTIAL
        ).isAvailable
    }

    /**
     * Checks whether device credentials are configured and usable.
     *
     * This is evaluated through the Android biometric capability API.
     */
    fun canUseDeviceCredential(
        context: Context
    ): Boolean {

        return getAuthenticationStatus(
            context = context,
            authenticators =
                DEVICE_CREDENTIAL
        ).isAvailable
    }

    // -------------------------------------------------------------------------
    // SentriX Security Policies
    // -------------------------------------------------------------------------

    /**
     * Returns the recommended authentication policy for normal
     * SentriX protected operations.
     *
     * Strong biometrics are preferred, with device credentials available
     * as a secure fallback.
     */
    fun getDefaultSecurityPolicy(): BiometricSecurityPolicy {

        return BiometricSecurityPolicy(
            authenticators =
                STRONG_BIOMETRIC_OR_CREDENTIAL,
            allowDeviceCredentialFallback = true,
            requireStrongBiometric = true
        )
    }

    /**
     * Returns a high-security policy intended for sensitive operations.
     *
     * Device credential fallback is disabled.
     */
    fun getHighSecurityPolicy(): BiometricSecurityPolicy {

        return BiometricSecurityPolicy(
            authenticators =
                Authenticators.BIOMETRIC_STRONG,
            allowDeviceCredentialFallback = false,
            requireStrongBiometric = true
        )
    }

    /**
     * Returns a convenience authentication policy where any biometric
     * class can be accepted.
     *
     * This should not be used automatically for high-risk operations.
     */
    fun getFlexiblePolicy(): BiometricSecurityPolicy {

        return BiometricSecurityPolicy(
            authenticators = ANY_BIOMETRIC,
            allowDeviceCredentialFallback = false,
            requireStrongBiometric = false
        )
    }

    /**
     * Validates whether a requested policy is currently supported.
     */
    fun validatePolicy(
        context: Context,
        policy: BiometricSecurityPolicy
    ): BiometricPolicyValidation {

        val status =
            getAuthenticationStatus(
                context = context,
                authenticators =
                    policy.authenticators
            )

        return when (status) {

            BiometricAvailability.Available -> {
                BiometricPolicyValidation.Supported
            }

            BiometricAvailability.NoHardware -> {
                BiometricPolicyValidation.NotSupported(
                    "Biometric hardware is unavailable."
                )
            }

            BiometricAvailability.HardwareUnavailable -> {
                BiometricPolicyValidation.TemporarilyUnavailable(
                    "Biometric hardware is temporarily unavailable."
                )
            }

            BiometricAvailability.NoneEnrolled -> {
                BiometricPolicyValidation.NotEnrolled(
                    "No supported biometric or credential is enrolled."
                )
            }

            BiometricAvailability.SecurityUpdateRequired -> {
                BiometricPolicyValidation.SecurityUpdateRequired
            }

            BiometricAvailability.Unsupported -> {
                BiometricPolicyValidation.NotSupported(
                    "Requested authentication policy is unsupported."
                )
            }

            BiometricAvailability.Unknown -> {
                BiometricPolicyValidation.Unknown
            }

            is BiometricAvailability.Error -> {
                BiometricPolicyValidation.Error(
                    status.cause
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // Capability Information
    // -------------------------------------------------------------------------

    /**
     * Returns a complete capability report for SentriX.
     */
    fun getCapabilityReport(
        context: Context
    ): BiometricCapabilityReport {

        val strongStatus =
            getAuthenticationStatus(
                context = context,
                authenticators =
                    Authenticators.BIOMETRIC_STRONG
            )

        val anyBiometricStatus =
            getAuthenticationStatus(
                context = context,
                authenticators =
                    ANY_BIOMETRIC
            )

        val credentialStatus =
            getAuthenticationStatus(
                context = context,
                authenticators =
                    DEVICE_CREDENTIAL
            )

        val combinedStatus =
            getAuthenticationStatus(
                context = context,
                authenticators =
                    STRONG_BIOMETRIC_OR_CREDENTIAL
            )

        return BiometricCapabilityReport(
            strongBiometricAvailable =
                strongStatus.isAvailable,

            biometricAvailable =
                anyBiometricStatus.isAvailable,

            deviceCredentialAvailable =
                credentialStatus.isAvailable,

            biometricWithCredentialFallbackAvailable =
                combinedStatus.isAvailable,

            strongBiometricStatus =
                strongStatus,

            biometricStatus =
                anyBiometricStatus,

            deviceCredentialStatus =
                credentialStatus,

            combinedAuthenticationStatus =
                combinedStatus
        )
    }

    // -------------------------------------------------------------------------
    // Security Level
    // -------------------------------------------------------------------------

    /**
     * Determines the strongest authentication level currently available.
     *
     * The returned value is intended for SentriX security policy decisions.
     */
    fun getAvailableSecurityLevel(
        context: Context
    ): BiometricSecurityLevel {

        if (
            canUseStrongBiometric(
                context
            )
        ) {
            return BiometricSecurityLevel.STRONG_BIOMETRIC
        }

        if (
            canUseBiometricOnly(
                context
            )
        ) {
            return BiometricSecurityLevel.BIOMETRIC
        }

        if (
            canUseDeviceCredential(
                context
            )
        ) {
            return BiometricSecurityLevel.DEVICE_CREDENTIAL
        }

        return BiometricSecurityLevel.NONE
    }

    /**
     * Determines whether the current device satisfies a minimum
     * SentriX security level.
     */
    fun satisfiesSecurityLevel(
        context: Context,
        requiredLevel: BiometricSecurityLevel
    ): Boolean {

        val currentLevel =
            getAvailableSecurityLevel(
                context
            )

        return currentLevel.ordinal >=
                requiredLevel.ordinal
    }

    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /**
     * Performs a lightweight biometric subsystem initialization check.
     *
     * No authentication prompt is displayed.
     */
    fun initialize(
        context: Context
    ): BiometricInitializationResult {

        return try {

            val report =
                getCapabilityReport(
                    context
                )

            BiometricInitializationResult.Success(
                report
            )

        } catch (exception: Exception) {

            BiometricInitializationResult.Failure(
                exception
            )
        }
    }
}

/**
 * Detailed biometric availability state.
 */
sealed class BiometricAvailability {

    /**
     * Requested authentication method is available.
     */
    data object Available : BiometricAvailability()

    /**
     * Device has no required biometric hardware.
     */
    data object NoHardware : BiometricAvailability()

    /**
     * Biometric hardware exists but is temporarily unavailable.
     */
    data object HardwareUnavailable : BiometricAvailability()

    /**
     * Hardware exists but no compatible authentication method
     * has been enrolled.
     */
    data object NoneEnrolled : BiometricAvailability()

    /**
     * Android requires a security update before authentication can
     * be used.
     */
    data object SecurityUpdateRequired : BiometricAvailability()

    /**
     * Requested authenticator combination is unsupported.
     */
    data object Unsupported : BiometricAvailability()

    /**
     * Android returned an unknown status.
     */
    data object Unknown : BiometricAvailability()

    /**
     * Unexpected manager/system failure.
     */
    data class Error(
        val cause: Throwable
    ) : BiometricAvailability()

    /**
     * Convenience property for checking availability.
     */
    val isAvailable: Boolean
        get() = this is Available
}

/**
 * SentriX biometric security policy.
 *
 * The policy describes what level of authentication a protected
 * operation requires.
 */
data class BiometricSecurityPolicy(
    val authenticators: Int,
    val allowDeviceCredentialFallback: Boolean,
    val requireStrongBiometric: Boolean
)

/**
 * Result of validating a biometric security policy.
 */
sealed class BiometricPolicyValidation {

    /**
     * Requested policy is currently supported.
     */
    data object Supported :
        BiometricPolicyValidation()

    /**
     * Device does not support requested authentication.
     */
    data class NotSupported(
        val reason: String
    ) : BiometricPolicyValidation()

    /**
     * Authentication hardware is temporarily unavailable.
     */
    data class TemporarilyUnavailable(
        val reason: String
    ) : BiometricPolicyValidation()

    /**
     * No required authentication method has been enrolled.
     */
    data class NotEnrolled(
        val reason: String
    ) : BiometricPolicyValidation()

    /**
     * Security update is required.
     */
    data object SecurityUpdateRequired :
        BiometricPolicyValidation()

    /**
     * Android returned an unknown capability state.
     */
    data object Unknown :
        BiometricPolicyValidation()

    /**
     * Unexpected system error.
     */
    data class Error(
        val cause: Throwable
    ) : BiometricPolicyValidation()
}

/**
 * Complete biometric capability report.
 */
data class BiometricCapabilityReport(
    val strongBiometricAvailable: Boolean,
    val biometricAvailable: Boolean,
    val deviceCredentialAvailable: Boolean,
    val biometricWithCredentialFallbackAvailable: Boolean,
    val strongBiometricStatus: BiometricAvailability,
    val biometricStatus: BiometricAvailability,
    val deviceCredentialStatus: BiometricAvailability,
    val combinedAuthenticationStatus: BiometricAvailability
)

/**
 * Security strength currently available on the device.
 *
 * Ordering represents increasing security strength.
 */
enum class BiometricSecurityLevel {

    /**
     * No supported authentication mechanism available.
     */
    NONE,

    /**
     * Device credential such as PIN/password/pattern.
     */
    DEVICE_CREDENTIAL,

    /**
     * General biometric authentication.
     */
    BIOMETRIC,

    /**
     * Android strong-class biometric authentication.
     */
    STRONG_BIOMETRIC
}

/**
 * Result of biometric subsystem initialization.
 */
sealed class BiometricInitializationResult {

    /**
     * Biometric subsystem was successfully inspected.
     */
    data class Success(
        val capabilityReport: BiometricCapabilityReport
    ) : BiometricInitializationResult()

    /**
     * Biometric subsystem initialization failed.
     */
    data class Failure(
        val cause: Throwable
    ) : BiometricInitializationResult()
}
