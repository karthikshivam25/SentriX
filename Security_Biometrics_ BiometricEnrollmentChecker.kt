package com.sentrix.security.biometrics

import android.content.Context
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricManager as AndroidBiometricManager

/**
 * SentriX Biometric Enrollment Checker
 *
 * Specialized checker for determining whether the authentication
 * mechanisms required by SentriX have been enrolled and are currently
 * usable.
 *
 * Responsibilities:
 *
 * - Check biometric enrollment.
 * - Check strong biometric enrollment.
 * - Check device credential enrollment.
 * - Determine whether SentriX standard security requirements
 *   can be satisfied.
 * - Determine whether SentriX high-security requirements
 *   can be satisfied.
 * - Provide detailed enrollment status.
 * - Provide enrollment/readiness recommendations.
 *
 * This class DOES NOT:
 *
 * - Display biometric prompts.
 * - Authenticate the user.
 * - Access biometric templates.
 * - Read fingerprint data.
 * - Read facial recognition data.
 * - Modify device security settings.
 * - Store biometric information.
 *
 * Android remains responsible for biometric enrollment and
 * authentication.
 *
 * Architecture:
 *
 *      SentriX Security Layer
 *               │
 *               ▼
 *      BiometricEnrollmentChecker
 *               │
 *               ▼
 *      AndroidX BiometricManager
 *               │
 *               ▼
 *      Android Security Framework
 */
object BiometricEnrollmentChecker {

    // -------------------------------------------------------------------------
    // Authenticator Configurations
    // -------------------------------------------------------------------------

    /**
     * Strong biometric authentication.
     *
     * Used for high-security SentriX operations.
     */
    private const val STRONG_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG

    /**
     * Any supported biometric authentication.
     */
    private const val ANY_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.BIOMETRIC_WEAK

    /**
     * Device credential authentication.
     */
    private const val DEVICE_CREDENTIAL =
        Authenticators.DEVICE_CREDENTIAL

    /**
     * Strong biometric with secure credential fallback.
     */
    private const val STRONG_BIOMETRIC_OR_CREDENTIAL =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.DEVICE_CREDENTIAL

    // -------------------------------------------------------------------------
    // AndroidX Manager
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

    // -------------------------------------------------------------------------
    // General Enrollment Checks
    // -------------------------------------------------------------------------

    /**
     * Determines whether any biometric authentication is enrolled
     * and currently usable.
     */
    fun isBiometricEnrolled(
        context: Context
    ): Boolean {

        return checkBiometricEnrollment(
            context
        ).isEnrolled
    }

    /**
     * Determines whether strong biometric authentication is enrolled
     * and currently usable.
     */
    fun isStrongBiometricEnrolled(
        context: Context
    ): Boolean {

        return checkStrongBiometricEnrollment(
            context
        ).isEnrolled
    }

    /**
     * Determines whether a device credential is configured and usable.
     *
     * This includes supported:
     *
     * - PIN
     * - Password
     * - Pattern
     */
    fun isDeviceCredentialEnrolled(
        context: Context
    ): Boolean {

        return checkDeviceCredentialEnrollment(
            context
        ).isEnrolled
    }

    // -------------------------------------------------------------------------
    // Detailed Enrollment Checks
    // -------------------------------------------------------------------------

    /**
     * Checks enrollment for any supported biometric method.
     */
    fun checkBiometricEnrollment(
        context: Context
    ): BiometricEnrollmentStatus {

        return check(
            context = context,
            authenticators = ANY_BIOMETRIC
        )
    }

    /**
     * Checks enrollment specifically for strong biometric
     * authentication.
     */
    fun checkStrongBiometricEnrollment(
        context: Context
    ): BiometricEnrollmentStatus {

        return check(
            context = context,
            authenticators = STRONG_BIOMETRIC
        )
    }

    /**
     * Checks whether device credentials are configured.
     */
    fun checkDeviceCredentialEnrollment(
        context: Context
    ): BiometricEnrollmentStatus {

        return check(
            context = context,
            authenticators = DEVICE_CREDENTIAL
        )
    }

    /**
     * Checks whether strong biometric authentication with
     * device credential fallback is available.
     */
    fun checkStrongBiometricWithCredentialEnrollment(
        context: Context
    ): BiometricEnrollmentStatus {

        return check(
            context = context,
            authenticators =
                STRONG_BIOMETRIC_OR_CREDENTIAL
        )
    }

    // -------------------------------------------------------------------------
    // Generic Enrollment Check
    // -------------------------------------------------------------------------

    /**
     * Performs an enrollment/capability check for a specified
     * authenticator configuration.
     *
     * Android's BiometricManager.canAuthenticate() is used as the
     * authoritative source.
     */
    fun check(
        context: Context,
        authenticators: Int
    ): BiometricEnrollmentStatus {

        if (authenticators == 0) {

            return BiometricEnrollmentStatus.InvalidRequest
        }

        return try {

            val result =
                getAndroidBiometricManager(
                    context
                ).canAuthenticate(
                    authenticators
                )

            mapResult(
                result
            )

        } catch (exception: Exception) {

            BiometricEnrollmentStatus.Error(
                exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Enrollment Requirement Checks
    // -------------------------------------------------------------------------

    /**
     * Determines whether the user needs to enroll a biometric.
     */
    fun requiresBiometricEnrollment(
        context: Context
    ): Boolean {

        return checkBiometricEnrollment(
            context
        ) is
                BiometricEnrollmentStatus.NotEnrolled
    }

    /**
     * Determines whether the user needs to enroll a strong biometric.
     */
    fun requiresStrongBiometricEnrollment(
        context: Context
    ): Boolean {

        return checkStrongBiometricEnrollment(
            context
        ) is
                BiometricEnrollmentStatus.NotEnrolled
    }

    /**
     * Determines whether device credentials need to be configured.
     */
    fun requiresDeviceCredential(
        context: Context
    ): Boolean {

        return checkDeviceCredentialEnrollment(
            context
        ) is
                BiometricEnrollmentStatus.NotEnrolled
    }

    // -------------------------------------------------------------------------
    // Hardware Checks
    // -------------------------------------------------------------------------

    /**
     * Determines whether biometric hardware exists.
     */
    fun hasBiometricHardware(
        context: Context
    ): Boolean {

        val status =
            checkBiometricEnrollment(
                context
            )

        return status !is
                BiometricEnrollmentStatus.NoHardware
    }

    /**
     * Determines whether strong biometric hardware is available.
     */
    fun hasStrongBiometricHardware(
        context: Context
    ): Boolean {

        val status =
            checkStrongBiometricEnrollment(
                context
            )

        return status !is
                BiometricEnrollmentStatus.NoHardware
    }

    // -------------------------------------------------------------------------
    // SentriX Enrollment Requirements
    // -------------------------------------------------------------------------

    /**
     * Determines whether the device satisfies SentriX's standard
     * biometric security requirement.
     *
     * Standard requirement:
     *
     *      Strong biometric OR device credential
     */
    fun isSentriXStandardEnrollmentReady(
        context: Context
    ): Boolean {

        return checkStrongBiometricWithCredentialEnrollment(
            context
        ).isEnrolled
    }

    /**
     * Determines whether the device satisfies SentriX's high-security
     * biometric requirement.
     *
     * High-security requirement:
     *
     *      Strong biometric
     */
    fun isSentriXHighSecurityEnrollmentReady(
        context: Context
    ): Boolean {

        return checkStrongBiometricEnrollment(
            context
        ).isEnrolled
    }

    // -------------------------------------------------------------------------
    // Enrollment Report
    // -------------------------------------------------------------------------

    /**
     * Builds a complete biometric enrollment report.
     *
     * This report can be consumed by:
     *
     * - SentriX Settings.
     * - Device Trust.
     * - Security Health.
     * - Onboarding.
     * - Security Dashboard.
     */
    fun getEnrollmentReport(
        context: Context
    ): BiometricEnrollmentReport {

        val biometricStatus =
            checkBiometricEnrollment(
                context
            )

        val strongBiometricStatus =
            checkStrongBiometricEnrollment(
                context
            )

        val credentialStatus =
            checkDeviceCredentialEnrollment(
                context
            )

        val combinedStatus =
            checkStrongBiometricWithCredentialEnrollment(
                context
            )

        return BiometricEnrollmentReport(
            biometricStatus =
                biometricStatus,

            strongBiometricStatus =
                strongBiometricStatus,

            deviceCredentialStatus =
                credentialStatus,

            strongBiometricWithCredentialStatus =
                combinedStatus,

            biometricEnrolled =
                biometricStatus.isEnrolled,

            strongBiometricEnrolled =
                strongBiometricStatus.isEnrolled,

            deviceCredentialEnrolled =
                credentialStatus.isEnrolled,

            standardSecurityReady =
                combinedStatus.isEnrolled,

            highSecurityReady =
                strongBiometricStatus.isEnrolled
        )
    }

    // -------------------------------------------------------------------------
    // Enrollment Recommendations
    // -------------------------------------------------------------------------

    /**
     * Provides a SentriX enrollment recommendation based on the
     * current device state.
     */
    fun getEnrollmentRecommendation(
        context: Context
    ): BiometricEnrollmentRecommendation {

        val report =
            getEnrollmentReport(
                context
            )

        if (
            report.highSecurityReady
        ) {

            return BiometricEnrollmentRecommendation.ReadyForHighSecurity
        }

        if (
            report.standardSecurityReady
        ) {

            return BiometricEnrollmentRecommendation.ReadyForStandardSecurity
        }

        if (
            report.strongBiometricStatus is
            BiometricEnrollmentStatus.NotEnrolled
        ) {

            return BiometricEnrollmentRecommendation.EnrollStrongBiometric
        }

        if (
            report.deviceCredentialStatus is
            BiometricEnrollmentStatus.NotEnrolled
        ) {

            return BiometricEnrollmentRecommendation.ConfigureDeviceCredential
        }

        if (
            report.biometricStatus is
            BiometricEnrollmentStatus.NoHardware
        ) {

            return BiometricEnrollmentRecommendation.NoBiometricHardware
        }

        if (
            report.biometricStatus is
            BiometricEnrollmentStatus.SecurityUpdateRequired
        ) {

            return BiometricEnrollmentRecommendation.SecurityUpdateRequired
        }

        if (
            report.biometricStatus is
            BiometricEnrollmentStatus.HardwareUnavailable
        ) {

            return BiometricEnrollmentRecommendation.HardwareUnavailable
        }

        return BiometricEnrollmentRecommendation.Unavailable
    }

    // -------------------------------------------------------------------------
    // Enrollment State
    // -------------------------------------------------------------------------

    /**
     * Determines the overall enrollment state.
     */
    fun getEnrollmentState(
        context: Context
    ): BiometricEnrollmentState {

        val report =
            getEnrollmentReport(
                context
            )

        return when {

            report.highSecurityReady -> {

                BiometricEnrollmentState.HighSecurityReady
            }

            report.standardSecurityReady -> {

                BiometricEnrollmentState.StandardSecurityReady
            }

            report.strongBiometricStatus is
                    BiometricEnrollmentStatus.NotEnrolled -> {

                BiometricEnrollmentState.BiometricEnrollmentRequired
            }

            report.deviceCredentialStatus is
                    BiometricEnrollmentStatus.NotEnrolled -> {

                BiometricEnrollmentState.DeviceCredentialRequired
            }

            report.biometricStatus is
                    BiometricEnrollmentStatus.NoHardware -> {

                BiometricEnrollmentState.NoHardware
            }

            report.biometricStatus is
                    BiometricEnrollmentStatus.HardwareUnavailable -> {

                BiometricEnrollmentState.HardwareUnavailable
            }

            report.biometricStatus is
                    BiometricEnrollmentStatus.SecurityUpdateRequired -> {

                BiometricEnrollmentState.SecurityUpdateRequired
            }

            else -> {

                BiometricEnrollmentState.Unavailable
            }
        }
    }

    // -------------------------------------------------------------------------
    // Android Result Mapping
    // -------------------------------------------------------------------------

    /**
     * Converts AndroidX BiometricManager status codes into
     * SentriX enrollment states.
     */
    private fun mapResult(
        result: Int
    ): BiometricEnrollmentStatus {

        return when (result) {

            AndroidBiometricManager.BIOMETRIC_SUCCESS -> {

                BiometricEnrollmentStatus.Enrolled
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {

                BiometricEnrollmentStatus.NotEnrolled
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {

                BiometricEnrollmentStatus.NoHardware
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {

                BiometricEnrollmentStatus.HardwareUnavailable
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {

                BiometricEnrollmentStatus.SecurityUpdateRequired
            }

            AndroidBiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> {

                BiometricEnrollmentStatus.Unsupported
            }

            AndroidBiometricManager.BIOMETRIC_STATUS_UNKNOWN -> {

                BiometricEnrollmentStatus.Unknown
            }

            else -> {

                BiometricEnrollmentStatus.Unknown
            }
        }
    }
}

/**
 * Detailed biometric enrollment status.
 */
sealed class BiometricEnrollmentStatus {

    /**
     * Required authentication mechanism is enrolled and usable.
     */
    data object Enrolled :
        BiometricEnrollmentStatus()

    /**
     * Required biometric/authentication mechanism exists but has
     * not been enrolled.
     */
    data object NotEnrolled :
        BiometricEnrollmentStatus()

    /**
     * Required biometric hardware does not exist.
     */
    data object NoHardware :
        BiometricEnrollmentStatus()

    /**
     * Hardware exists but is temporarily unavailable.
     */
    data object HardwareUnavailable :
        BiometricEnrollmentStatus()

    /**
     * Android requires a security update.
     */
    data object SecurityUpdateRequired :
        BiometricEnrollmentStatus()

    /**
     * Requested authenticator configuration is unsupported.
     */
    data object Unsupported :
        BiometricEnrollmentStatus()

    /**
     * Android returned an unknown state.
     */
    data object Unknown :
        BiometricEnrollmentStatus()

    /**
     * Caller supplied an invalid authenticator configuration.
     */
    data object InvalidRequest :
        BiometricEnrollmentStatus()

    /**
     * Unexpected system error.
     */
    data class Error(
        val cause: Throwable
    ) : BiometricEnrollmentStatus()

    /**
     * Indicates whether the requested authentication method
     * is actually enrolled and usable.
     */
    val isEnrolled: Boolean
        get() = this is Enrolled
}

/**
 * Complete SentriX biometric enrollment report.
 */
data class BiometricEnrollmentReport(
    val biometricStatus:
        BiometricEnrollmentStatus,

    val strongBiometricStatus:
        BiometricEnrollmentStatus,

    val deviceCredentialStatus:
        BiometricEnrollmentStatus,

    val strongBiometricWithCredentialStatus:
        BiometricEnrollmentStatus,

    val biometricEnrolled: Boolean,

    val strongBiometricEnrolled: Boolean,

    val deviceCredentialEnrolled: Boolean,

    val standardSecurityReady: Boolean,

    val highSecurityReady: Boolean
)

/**
 * Recommendation produced by the SentriX enrollment checker.
 */
enum class BiometricEnrollmentRecommendation {

    /**
     * Strong biometric is ready for high-security operations.
     */
    ReadyForHighSecurity,

    /**
     * Standard SentriX authentication requirements are satisfied.
     */
    ReadyForStandardSecurity,

    /**
     * Strong biometric enrollment is recommended/required.
     */
    EnrollStrongBiometric,

    /**
     * Device credential should be configured.
     */
    ConfigureDeviceCredential,

    /**
     * Device has no biometric hardware.
     */
    NoBiometricHardware,

    /**
     * Android security update is required.
     */
    SecurityUpdateRequired,

    /**
     * Hardware is temporarily unavailable.
     */
    HardwareUnavailable,

    /**
     * Enrollment state could not be determined or is unavailable.
     */
    Unavailable
}

/**
 * Overall SentriX enrollment state.
 */
enum class BiometricEnrollmentState {

    /**
     * Strong biometric is enrolled and ready.
     */
    HighSecurityReady,

    /**
     * Standard SentriX security requirement is satisfied.
     */
    StandardSecurityReady,

    /**
     * Strong biometric enrollment is required.
     */
    BiometricEnrollmentRequired,

    /**
     * Device credential enrollment/configuration is required.
     */
    DeviceCredentialRequired,

    /**
     * No biometric hardware exists.
     */
    NoHardware,

    /**
     * Biometric hardware is temporarily unavailable.
     */
    HardwareUnavailable,

    /**
     * Security update is required.
     */
    SecurityUpdateRequired,

    /**
     * Authentication enrollment is unavailable.
     */
    Unavailable
}
