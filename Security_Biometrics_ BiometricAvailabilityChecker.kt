package com.sentrix.security.biometrics

import android.content.Context
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricManager as AndroidBiometricManager

/**
 * SentriX Biometric Availability Checker
 *
 * Provides a lightweight, read-only capability checker for the Android
 * biometric subsystem.
 *
 * Responsibilities:
 *
 * - Check whether biometric hardware exists.
 * - Check whether biometric authentication is currently available.
 * - Check whether biometrics have been enrolled.
 * - Check strong biometric availability.
 * - Check device credential availability.
 * - Check combined biometric + credential availability.
 * - Provide a detailed availability report.
 *
 * This class DOES NOT:
 *
 * - Display BiometricPrompt.
 * - Authenticate users.
 * - Store biometric information.
 * - Manage biometric security sessions.
 * - Generate or manage encryption keys.
 * - Change device biometric settings.
 *
 * Android's BiometricManager remains the source of truth for
 * biometric capability.
 *
 * Architecture:
 *
 *      SentriX Feature
 *           │
 *           ▼
 * BiometricAvailabilityChecker
 *           │
 *           ▼
 * AndroidX BiometricManager
 *           │
 *           ▼
 * Android Biometric Framework
 */
object BiometricAvailabilityChecker {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /**
     * Strong biometric authenticator.
     *
     * Suitable for high-security SentriX operations.
     */
    private const val STRONG_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG

    /**
     * Any biometric authenticator supported by AndroidX.
     */
    private const val ANY_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.BIOMETRIC_WEAK

    /**
     * Device credential authenticator.
     */
    private const val DEVICE_CREDENTIAL =
        Authenticators.DEVICE_CREDENTIAL

    /**
     * Strong biometric with device credential fallback.
     */
    private const val STRONG_BIOMETRIC_OR_CREDENTIAL =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.DEVICE_CREDENTIAL

    // -------------------------------------------------------------------------
    // AndroidX Manager
    // -------------------------------------------------------------------------

    /**
     * Returns the AndroidX biometric manager associated with the
     * supplied application context.
     */
    private fun getAndroidManager(
        context: Context
    ): AndroidBiometricManager {

        return AndroidBiometricManager.from(
            context.applicationContext
        )
    }

    // -------------------------------------------------------------------------
    // General Availability
    // -------------------------------------------------------------------------

    /**
     * Checks whether any biometric authentication is currently
     * available.
     *
     * This includes both strong and weak biometric classes.
     */
    fun isBiometricAvailable(
        context: Context
    ): Boolean {

        return check(
            context = context,
            authenticators = ANY_BIOMETRIC
        ).isAvailable
    }

    /**
     * Checks whether strong biometric authentication is available.
     *
     * This should be preferred for sensitive SentriX operations.
     */
    fun isStrongBiometricAvailable(
        context: Context
    ): Boolean {

        return check(
            context = context,
            authenticators = STRONG_BIOMETRIC
        ).isAvailable
    }

    /**
     * Checks whether device credential authentication is available.
     *
     * Device credentials include supported:
     *
     * - PIN
     * - Password
     * - Pattern
     */
    fun isDeviceCredentialAvailable(
        context: Context
    ): Boolean {

        return check(
            context = context,
            authenticators = DEVICE_CREDENTIAL
        ).isAvailable
    }

    /**
     * Checks whether strong biometric authentication or device
     * credential fallback is available.
     */
    fun isStrongBiometricWithCredentialAvailable(
        context: Context
    ): Boolean {

        return check(
            context = context,
            authenticators =
                STRONG_BIOMETRIC_OR_CREDENTIAL
        ).isAvailable
    }

    // -------------------------------------------------------------------------
    // Detailed Status
    // -------------------------------------------------------------------------

    /**
     * Performs a detailed capability check.
     *
     * @param context Android context.
     * @param authenticators Authentication classes that should be checked.
     */
    fun check(
        context: Context,
        authenticators: Int
    ): BiometricAvailabilityStatus {

        if (authenticators == 0) {

            return BiometricAvailabilityStatus.InvalidRequest
        }

        return try {

            val result =
                getAndroidManager(
                    context
                ).canAuthenticate(
                    authenticators
                )

            mapStatus(
                result
            )

        } catch (exception: Exception) {

            BiometricAvailabilityStatus.Error(
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Strong Biometric Status
    // -------------------------------------------------------------------------

    /**
     * Returns detailed strong-biometric availability.
     */
    fun checkStrongBiometric(
        context: Context
    ): BiometricAvailabilityStatus {

        return check(
            context = context,
            authenticators = STRONG_BIOMETRIC
        )
    }

    /**
     * Returns detailed general biometric availability.
     */
    fun checkBiometric(
        context: Context
    ): BiometricAvailabilityStatus {

        return check(
            context = context,
            authenticators = ANY_BIOMETRIC
        )
    }

    /**
     * Returns detailed device credential availability.
     */
    fun checkDeviceCredential(
        context: Context
    ): BiometricAvailabilityStatus {

        return check(
            context = context,
            authenticators = DEVICE_CREDENTIAL
        )
    }

    /**
     * Returns detailed strong-biometric + credential availability.
     */
    fun checkStrongBiometricWithCredential(
        context: Context
    ): BiometricAvailabilityStatus {

        return check(
            context = context,
            authenticators =
                STRONG_BIOMETRIC_OR_CREDENTIAL
        )
    }

    // -------------------------------------------------------------------------
    // Enrollment Checks
    // -------------------------------------------------------------------------

    /**
     * Determines whether a compatible biometric is enrolled.
     *
     * Note:
     *
     * Android's BiometricManager.canAuthenticate() does not expose
     * biometric enrollment as a separate boolean API. A
     * BIOMETRIC_ERROR_NONE_ENROLLED result is therefore used to
     * identify the enrollment state.
     */
    fun isBiometricEnrolled(
        context: Context
    ): Boolean {

        val status =
            checkBiometric(
                context
            )

        return status is
                BiometricAvailabilityStatus.Available
    }

    /**
     * Determines whether a strong biometric is enrolled and available.
     */
    fun isStrongBiometricEnrolled(
        context: Context
    ): Boolean {

        val status =
            checkStrongBiometric(
                context
            )

        return status is
                BiometricAvailabilityStatus.Available
    }

    /**
     * Determines whether biometric enrollment is missing.
     */
    fun requiresBiometricEnrollment(
        context: Context
    ): Boolean {

        val status =
            checkBiometric(
                context
            )

        return status is
                BiometricAvailabilityStatus.NoneEnrolled
    }

    // -------------------------------------------------------------------------
    // Hardware Checks
    // -------------------------------------------------------------------------

    /**
     * Determines whether biometric hardware appears to be available.
     *
     * A false result can mean:
     *
     * - No hardware exists.
     * - Hardware is temporarily unavailable.
     * - The requested biometric class is unsupported.
     *
     * Use checkBiometric() when the exact reason is required.
     */
    fun hasBiometricHardware(
        context: Context
    ): Boolean {

        val status =
            checkBiometric(
                context
            )

        return status !is
                BiometricAvailabilityStatus.NoHardware
    }

    /**
     * Determines whether the biometric hardware is temporarily
     * unavailable.
     */
    fun isHardwareTemporarilyUnavailable(
        context: Context
    ): Boolean {

        return checkBiometric(
            context
        ) is
                BiometricAvailabilityStatus.HardwareUnavailable
    }

    // -------------------------------------------------------------------------
    // Security Update Checks
    // -------------------------------------------------------------------------

    /**
     * Determines whether Android requires a security update before
     * biometric authentication can be used.
     */
    fun requiresSecurityUpdate(
        context: Context
    ): Boolean {

        return checkBiometric(
            context
        ) is
                BiometricAvailabilityStatus.SecurityUpdateRequired
    }

    // -------------------------------------------------------------------------
    // Capability Report
    // -------------------------------------------------------------------------

    /**
     * Builds a complete biometric capability report.
     *
     * This is useful for:
     *
     * - SentriX Settings.
     * - Security Dashboard.
     * - Device Security Health.
     * - Diagnostics.
     * - Security readiness checks.
     */
    fun getCapabilityReport(
        context: Context
    ): BiometricAvailabilityReport {

        val biometricStatus =
            checkBiometric(
                context
            )

        val strongBiometricStatus =
            checkStrongBiometric(
                context
            )

        val credentialStatus =
            checkDeviceCredential(
                context
            )

        val combinedStatus =
            checkStrongBiometricWithCredential(
                context
            )

        return BiometricAvailabilityReport(
            biometricStatus =
                biometricStatus,

            strongBiometricStatus =
                strongBiometricStatus,

            deviceCredentialStatus =
                credentialStatus,

            strongBiometricWithCredentialStatus =
                combinedStatus,

            biometricAvailable =
                biometricStatus.isAvailable,

            strongBiometricAvailable =
                strongBiometricStatus.isAvailable,

            deviceCredentialAvailable =
                credentialStatus.isAvailable,

            strongBiometricWithCredentialAvailable =
                combinedStatus.isAvailable,

            biometricEnrolled =
                biometricStatus.isAvailable,

            strongBiometricEnrolled =
                strongBiometricStatus.isAvailable
        )
    }

    // -------------------------------------------------------------------------
    // SentriX Security Readiness
    // -------------------------------------------------------------------------

    /**
     * Determines whether the device meets the default SentriX
     * biometric security requirement.
     *
     * Default requirement:
     *
     *      Strong biometric OR device credential
     */
    fun isSentriXSecurityReady(
        context: Context
    ): Boolean {

        return isStrongBiometricWithCredentialAvailable(
            context
        )
    }

    /**
     * Determines whether the device meets the high-security
     * SentriX biometric requirement.
     *
     * High-security requirement:
     *
     *      Strong biometric only
     */
    fun isSentriXHighSecurityReady(
        context: Context
    ): Boolean {

        return isStrongBiometricAvailable(
            context
        )
    }

    /**
     * Returns a high-level SentriX readiness state.
     */
    fun getSentriXReadiness(
        context: Context
    ): SentriXBiometricReadiness {

        val strongStatus =
            checkStrongBiometric(
                context
            )

        val combinedStatus =
            checkStrongBiometricWithCredential(
                context
            )

        if (
            strongStatus.isAvailable
        ) {

            return SentriXBiometricReadiness.HighSecurityReady
        }

        if (
            combinedStatus.isAvailable
        ) {

            return SentriXBiometricReadiness.StandardSecurityReady
        }

        return when {

            strongStatus is
                    BiometricAvailabilityStatus.NoneEnrolled -> {

                SentriXBiometricReadiness.NotEnrolled
            }

            strongStatus is
                    BiometricAvailabilityStatus.NoHardware -> {

                SentriXBiometricReadiness.NoHardware
            }

            strongStatus is
                    BiometricAvailabilityStatus.SecurityUpdateRequired -> {

                SentriXBiometricReadiness.SecurityUpdateRequired
            }

            strongStatus is
                    BiometricAvailabilityStatus.HardwareUnavailable -> {

                SentriXBiometricReadiness.HardwareUnavailable
            }

            else -> {

                SentriXBiometricReadiness.Unavailable
            }
        }
    }

    // -------------------------------------------------------------------------
    // Android Result Mapping
    // -------------------------------------------------------------------------

    /**
     * Converts AndroidX BiometricManager status codes into
     * SentriX-specific availability states.
     */
    private fun mapStatus(
        result: Int
    ): BiometricAvailabilityStatus {

        return when (result) {

            AndroidBiometricManager.BIOMETRIC_SUCCESS -> {

                BiometricAvailabilityStatus.Available
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {

                BiometricAvailabilityStatus.NoHardware
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {

                BiometricAvailabilityStatus.HardwareUnavailable
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {

                BiometricAvailabilityStatus.NoneEnrolled
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {

                BiometricAvailabilityStatus.SecurityUpdateRequired
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> {

                BiometricAvailabilityStatus.Unsupported
            }

            AndroidBiometricManager.BIOMETRIC_STATUS_UNKNOWN -> {

                BiometricAvailabilityStatus.Unknown
            }

            else -> {

                BiometricAvailabilityStatus.Unknown
            }
        }
    }
}

/**
 * Detailed biometric availability state.
 */
sealed class BiometricAvailabilityStatus {

    /**
     * Requested authentication mechanism is available.
     */
    data object Available :
        BiometricAvailabilityStatus()

    /**
     * Required biometric hardware does not exist.
     */
    data object NoHardware :
        BiometricAvailabilityStatus()

    /**
     * Hardware exists but is temporarily unavailable.
     */
    data object HardwareUnavailable :
        BiometricAvailabilityStatus()

    /**
     * Hardware exists but no compatible biometric has been enrolled.
     */
    data object NoneEnrolled :
        BiometricAvailabilityStatus()

    /**
     * Android requires a security update.
     */
    data object SecurityUpdateRequired :
        BiometricAvailabilityStatus()

    /**
     * Requested authenticator combination is unsupported.
     */
    data object Unsupported :
        BiometricAvailabilityStatus()

    /**
     * Android returned an unknown status.
     */
    data object Unknown :
        BiometricAvailabilityStatus()

    /**
     * Caller supplied an invalid authenticator configuration.
     */
    data object InvalidRequest :
        BiometricAvailabilityStatus()

    /**
     * Unexpected system exception.
     */
    data class Error(
        val cause: Throwable
    ) : BiometricAvailabilityStatus()

    /**
     * Convenience property for checking successful availability.
     */
    val isAvailable: Boolean
        get() = this is Available
}

/**
 * Complete SentriX biometric capability report.
 *
 * This is a snapshot of the device's current authentication
 * capabilities.
 */
data class BiometricAvailabilityReport(
    val biometricStatus: BiometricAvailabilityStatus,
    val strongBiometricStatus: BiometricAvailabilityStatus,
    val deviceCredentialStatus: BiometricAvailabilityStatus,
    val strongBiometricWithCredentialStatus:
        BiometricAvailabilityStatus,

    val biometricAvailable: Boolean,
    val strongBiometricAvailable: Boolean,
    val deviceCredentialAvailable: Boolean,
    val strongBiometricWithCredentialAvailable: Boolean,

    val biometricEnrolled: Boolean,
    val strongBiometricEnrolled: Boolean
)

/**
 * High-level SentriX biometric readiness.
 */
enum class SentriXBiometricReadiness {

    /**
     * Strong biometric authentication is available.
     */
    HighSecurityReady,

    /**
     * Standard SentriX authentication can use strong biometric
     * with device credential fallback.
     */
    StandardSecurityReady,

    /**
     * Biometric hardware exists but enrollment is required.
     */
    NotEnrolled,

    /**
     * No biometric hardware is available.
     */
    NoHardware,

    /**
     * Hardware is temporarily unavailable.
     */
    HardwareUnavailable,

    /**
     * Android requires a security update.
     */
    SecurityUpdateRequired,

    /**
     * Authentication is unavailable for another reason.
     */
    Unavailable
}
