package com.sentrix.security.biometrics

import android.content.Context

/**
 * SentriX Biometric Validator
 *
 * Central validation component for biometric security requirements.
 *
 * Responsibilities:
 *
 * - Validate biometric security policies.
 * - Validate biometric security requirements.
 * - Validate device biometric capabilities.
 * - Validate enrollment state.
 * - Validate authentication results.
 * - Validate minimum security levels.
 * - Validate whether a protected operation may proceed.
 * - Provide detailed validation results.
 *
 * This class DOES NOT:
 *
 * - Display BiometricPrompt.
 * - Perform biometric authentication.
 * - Access biometric templates.
 * - Store fingerprint or facial information.
 * - Modify device biometric settings.
 * - Manage biometric sessions.
 *
 * It is intentionally designed as a validation layer between
 * SentriX security components and biometric authentication.
 *
 * Architecture:
 *
 *      SentriX Operation
 *            │
 *            ▼
 *      BiometricValidator
 *            │
 *       ┌────┴────┐
 *       ▼         ▼
 * BiometricManager   EnrollmentChecker
 *       │         │
 *       └────┬────┘
 *            ▼
 *      Validation Result
 *            │
 *            ▼
 *   BiometricSecurityManager
 */
object BiometricValidator {

    // -------------------------------------------------------------------------
    // Policy Validation
    // -------------------------------------------------------------------------

    /**
     * Validates a SentriX biometric security policy.
     *
     * This validates the policy structure itself. It does not determine
     * whether the current device supports that policy.
     */
    fun validatePolicy(
        policy: BiometricSecurityPolicy
    ): BiometricValidationResult {

        if (
            policy.authenticators == 0
        ) {

            return BiometricValidationResult.InvalidPolicy(
                "At least one biometric authenticator must be configured."
            )
        }

        if (
            policy.requireStrongBiometric &&
            !containsStrongBiometric(
                policy.authenticators
            )
        ) {

            return BiometricValidationResult.InvalidPolicy(
                "A policy requiring strong biometric authentication " +
                        "must include BIOMETRIC_STRONG."
            )
        }

        /**
         * DEVICE_CREDENTIAL and an explicit negative button are
         * mutually exclusive in AndroidX BiometricPrompt.
         *
         * BiometricSecurityPolicy represents this through
         * allowDeviceCredentialFallback.
         */
        if (
            policy.allowDeviceCredentialFallback &&
            !containsDeviceCredential(
                policy.authenticators
            )
        ) {

            return BiometricValidationResult.InvalidPolicy(
                "Credential fallback is enabled but DEVICE_CREDENTIAL " +
                        "is not included in the authenticator policy."
            )
        }

        return BiometricValidationResult.Valid
    }

    // -------------------------------------------------------------------------
    // Security Requirement Validation
    // -------------------------------------------------------------------------

    /**
     * Validates an application-level biometric security requirement.
     */
    fun validateRequirement(
        requirement: BiometricSecurityRequirement
    ): BiometricValidationResult {

        if (
            !requirement.requiresAuthentication
        ) {

            if (
                requirement.minimumSecurityLevel !=
                BiometricSecurityLevel.NONE
            ) {

                return BiometricValidationResult.InvalidRequirement(
                    "A requirement that does not require authentication " +
                            "must use security level NONE."
                )
            }

            if (
                requirement.requireFreshAuthentication
            ) {

                return BiometricValidationResult.InvalidRequirement(
                    "Fresh authentication cannot be required when " +
                            "authentication itself is disabled."
                )
            }

            return BiometricValidationResult.Valid
        }

        if (
            requirement.minimumSecurityLevel ==
            BiometricSecurityLevel.NONE
        ) {

            return BiometricValidationResult.InvalidRequirement(
                "An authentication requirement must specify a minimum " +
                        "security level."
            )
        }

        if (
            requirement.minimumSecurityLevel ==
            BiometricSecurityLevel.STRONG_BIOMETRIC &&
            requirement.allowCredentialFallback
        ) {

            return BiometricValidationResult.InvalidRequirement(
                "Strong biometric-only authentication cannot allow " +
                        "device credential fallback."
            )
        }

        return BiometricValidationResult.Valid
    }

    // -------------------------------------------------------------------------
    // Device Validation
    // -------------------------------------------------------------------------

    /**
     * Validates whether the current device can satisfy a requested
     * authentication policy.
     */
    fun validateDevicePolicy(
        context: Context,
        policy: BiometricSecurityPolicy
    ): BiometricValidationResult {

        val policyValidation =
            validatePolicy(
                policy
            )

        if (
            policyValidation !is
            BiometricValidationResult.Valid
        ) {

            return policyValidation
        }

        val managerValidation =
            BiometricManager.validatePolicy(
                context = context,
                policy = policy
            )

        return when (managerValidation) {

            BiometricPolicyValidation.Supported -> {

                BiometricValidationResult.Valid
            }

            is BiometricPolicyValidation.NotSupported -> {

                BiometricValidationResult.Unsupported(
                    managerValidation.reason
                )
            }

            is BiometricPolicyValidation.TemporarilyUnavailable -> {

                BiometricValidationResult.TemporarilyUnavailable(
                    managerValidation.reason
                )
            }

            is BiometricPolicyValidation.NotEnrolled -> {

                BiometricValidationResult.EnrollmentRequired(
                    managerValidation.reason
                )
            }

            BiometricPolicyValidation.SecurityUpdateRequired -> {

                BiometricValidationResult.SecurityUpdateRequired
            }

            BiometricPolicyValidation.Unknown -> {

                BiometricValidationResult.Unknown
            }

            is BiometricPolicyValidation.Error -> {

                BiometricValidationResult.Error(
                    managerValidation.cause
                )
            }
        }
    }

    /**
     * Validates whether the current device can satisfy a specific
     * security level.
     */
    fun validateSecurityLevel(
        context: Context,
        requiredLevel: BiometricSecurityLevel
    ): BiometricValidationResult {

        if (
            requiredLevel ==
            BiometricSecurityLevel.NONE
        ) {

            return BiometricValidationResult.Valid
        }

        val availableLevel =
            BiometricManager.getAvailableSecurityLevel(
                context
            )

        return if (
            availableLevel.ordinal >=
            requiredLevel.ordinal
        ) {

            BiometricValidationResult.Valid

        } else {

            BiometricValidationResult.InsufficientSecurityLevel(
                required = requiredLevel,
                available = availableLevel
            )
        }
    }

    // -------------------------------------------------------------------------
    // Enrollment Validation
    // -------------------------------------------------------------------------

    /**
     * Validates whether the required biometric authentication
     * mechanism is enrolled.
     */
    fun validateEnrollment(
        context: Context,
        requiredLevel: BiometricSecurityLevel
    ): BiometricValidationResult {

        return when (requiredLevel) {

            BiometricSecurityLevel.NONE -> {

                BiometricValidationResult.Valid
            }

            BiometricSecurityLevel.STRONG_BIOMETRIC -> {

                when (
                    val status =
                        BiometricEnrollmentChecker
                            .checkStrongBiometricEnrollment(
                                context
                            )
                ) {

                    BiometricEnrollmentStatus.Enrolled -> {

                        BiometricValidationResult.Valid
                    }

                    BiometricEnrollmentStatus.NotEnrolled -> {

                        BiometricValidationResult.EnrollmentRequired(
                            "A strong biometric must be enrolled."
                        )
                    }

                    BiometricEnrollmentStatus.NoHardware -> {

                        BiometricValidationResult.NoHardware
                    }

                    BiometricEnrollmentStatus.HardwareUnavailable -> {

                        BiometricValidationResult.TemporarilyUnavailable(
                            "Strong biometric hardware is temporarily unavailable."
                        )
                    }

                    BiometricEnrollmentStatus.SecurityUpdateRequired -> {

                        BiometricValidationResult.SecurityUpdateRequired
                    }

                    BiometricEnrollmentStatus.Unsupported -> {

                        BiometricValidationResult.Unsupported(
                            "Strong biometric authentication is unsupported."
                        )
                    }

                    BiometricEnrollmentStatus.Unknown -> {

                        BiometricValidationResult.Unknown
                    }

                    BiometricEnrollmentStatus.InvalidRequest -> {

                        BiometricValidationResult.InvalidRequirement(
                            "Invalid strong biometric enrollment request."
                        )
                    }

                    is BiometricEnrollmentStatus.Error -> {

                        BiometricValidationResult.Error(
                            status.cause
                        )
                    }
                }
            }

            BiometricSecurityLevel.BIOMETRIC -> {

                when (
                    val status =
                        BiometricEnrollmentChecker
                            .checkBiometricEnrollment(
                                context
                            )
                ) {

                    BiometricEnrollmentStatus.Enrolled -> {

                        BiometricValidationResult.Valid
                    }

                    BiometricEnrollmentStatus.NotEnrolled -> {

                        BiometricValidationResult.EnrollmentRequired(
                            "A supported biometric must be enrolled."
                        )
                    }

                    BiometricEnrollmentStatus.NoHardware -> {

                        BiometricValidationResult.NoHardware
                    }

                    BiometricEnrollmentStatus.HardwareUnavailable -> {

                        BiometricValidationResult.TemporarilyUnavailable(
                            "Biometric hardware is temporarily unavailable."
                        )
                    }

                    BiometricEnrollmentStatus.SecurityUpdateRequired -> {

                        BiometricValidationResult.SecurityUpdateRequired
                    }

                    BiometricEnrollmentStatus.Unsupported -> {

                        BiometricValidationResult.Unsupported(
                            "Biometric authentication is unsupported."
                        )
                    }

                    BiometricEnrollmentStatus.Unknown -> {

                        BiometricValidationResult.Unknown
                    }

                    BiometricEnrollmentStatus.InvalidRequest -> {

                        BiometricValidationResult.InvalidRequirement(
                            "Invalid biometric enrollment request."
                        )
                    }

                    is BiometricEnrollmentStatus.Error -> {

                        BiometricValidationResult.Error(
                            status.cause
                        )
                    }
                }
            }

            BiometricSecurityLevel.DEVICE_CREDENTIAL -> {

                when (
                    val status =
                        BiometricEnrollmentChecker
                            .checkDeviceCredentialEnrollment(
                                context
                            )
                ) {

                    BiometricEnrollmentStatus.Enrolled -> {

                        BiometricValidationResult.Valid
                    }

                    BiometricEnrollmentStatus.NotEnrolled -> {

                        BiometricValidationResult.EnrollmentRequired(
                            "A device PIN, password, or pattern must be configured."
                        )
                    }

                    BiometricEnrollmentStatus.NoHardware -> {

                        BiometricValidationResult.NoHardware
                    }

                    BiometricEnrollmentStatus.HardwareUnavailable -> {

                        BiometricValidationResult.TemporarilyUnavailable(
                            "Device credential authentication is temporarily unavailable."
                        )
                    }

                    BiometricEnrollmentStatus.SecurityUpdateRequired -> {

                        BiometricValidationResult.SecurityUpdateRequired
                    }

                    BiometricEnrollmentStatus.Unsupported -> {

                        BiometricValidationResult.Unsupported(
                            "Device credential authentication is unsupported."
                        )
                    }

                    BiometricEnrollmentStatus.Unknown -> {

                        BiometricValidationResult.Unknown
                    }

                    BiometricEnrollmentStatus.InvalidRequest -> {

                        BiometricValidationResult.InvalidRequirement(
                            "Invalid device credential enrollment request."
                        )
                    }

                    is BiometricEnrollmentStatus.Error -> {

                        BiometricValidationResult.Error(
                            status.cause
                        )
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Operation Validation
    // -------------------------------------------------------------------------

    /**
     * Performs complete validation for a protected SentriX operation.
     *
     * Validation sequence:
     *
     * 1. Validate requirement structure.
     * 2. Determine whether authentication is required.
     * 3. Check current security level.
     * 4. Check enrollment/capability.
     * 5. Return a final authorization readiness result.
     */
    fun validateProtectedOperation(
        context: Context,
        requirement: BiometricSecurityRequirement
    ): BiometricValidationResult {

        val requirementValidation =
            validateRequirement(
                requirement
            )

        if (
            requirementValidation !is
            BiometricValidationResult.Valid
        ) {

            return requirementValidation
        }

        if (
            !requirement.requiresAuthentication
        ) {

            return BiometricValidationResult.Valid
        }

        val securityValidation =
            validateSecurityLevel(
                context = context,
                requiredLevel =
                    requirement.minimumSecurityLevel
            )

        if (
            securityValidation !is
            BiometricValidationResult.Valid
        ) {

            return securityValidation
        }

        return validateEnrollment(
            context = context,
            requiredLevel =
                requirement.minimumSecurityLevel
        )
    }

    // -------------------------------------------------------------------------
    // Authentication Result Validation
    // -------------------------------------------------------------------------

    /**
     * Validates whether an authentication result is sufficient for
     * a required security level.
     */
    fun validateAuthenticationResult(
        result: SentriXBiometricResult,
        requiredLevel: BiometricSecurityLevel
    ): BiometricValidationResult {

        if (
            result !is
            SentriXBiometricResult.Authenticated
        ) {

            return BiometricValidationResult.AuthenticationFailed(
                getResultDescription(
                    result
                )
            )
        }

        if (
            result.securityLevel.ordinal <
            requiredLevel.ordinal
        ) {

            return BiometricValidationResult.InsufficientSecurityLevel(
                required = requiredLevel,
                available =
                    result.securityLevel
            )
        }

        return BiometricValidationResult.Valid
    }

    /**
     * Validates a raw authentication result.
     *
     * This method is useful when the caller only needs to know whether
     * authentication succeeded, without a specific security level.
     */
    fun validateAuthenticationResult(
        result: BiometricAuthenticationResult
    ): BiometricValidationResult {

        return when (result) {

            BiometricAuthenticationResult.Success -> {

                BiometricValidationResult.Valid
            }

            BiometricAuthenticationResult.FailedAttempt -> {

                BiometricValidationResult.AuthenticationFailed(
                    "Biometric authentication attempt failed."
                )
            }

            is BiometricAuthenticationResult.Cancelled -> {

                BiometricValidationResult.AuthenticationCancelled(
                    result.message
                )
            }

            is BiometricAuthenticationResult.LockedOut -> {

                BiometricValidationResult.AuthenticationLockedOut(
                    result.message
                )
            }

            is BiometricAuthenticationResult.PermanentlyLockedOut -> {

                BiometricValidationResult.AuthenticationLockedOut(
                    result.message
                )
            }

            is BiometricAuthenticationResult.HardwareUnavailable -> {

                BiometricValidationResult.TemporarilyUnavailable(
                    result.message
                )
            }

            is BiometricAuthenticationResult.NotEnrolled -> {

                BiometricValidationResult.EnrollmentRequired(
                    result.message
                )
            }

            is BiometricAuthenticationResult.NoDeviceCredential -> {

                BiometricValidationResult.EnrollmentRequired(
                    result.message
                )
            }

            is BiometricAuthenticationResult.Timeout -> {

                BiometricValidationResult.TemporarilyUnavailable(
                    result.message
                )
            }

            is BiometricAuthenticationResult.ProcessingError -> {

                BiometricValidationResult.AuthenticationFailed(
                    result.message
                )
            }

            is BiometricAuthenticationResult.VendorError -> {

                BiometricValidationResult.AuthenticationFailed(
                    result.message
                )
            }

            BiometricAuthenticationResult.SecurityUpdateRequired -> {

                BiometricValidationResult.SecurityUpdateRequired
            }

            is BiometricAuthenticationResult.NotSupported -> {

                BiometricValidationResult.Unsupported(
                    result.reason
                )
            }

            is BiometricAuthenticationResult.UnknownError -> {

                BiometricValidationResult.AuthenticationFailed(
                    result.message
                )
            }

            is BiometricAuthenticationResult.Error -> {

                BiometricValidationResult.Error(
                    result.cause
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // Result State Helpers
    // -------------------------------------------------------------------------

    /**
     * Determines whether the normalized result is valid for
     * continuing a protected operation.
     */
    fun canProceed(
        result: SentriXBiometricResult,
        requiredLevel: BiometricSecurityLevel
    ): Boolean {

        return validateAuthenticationResult(
            result = result,
            requiredLevel = requiredLevel
        ) is BiometricValidationResult.Valid
    }

    /**
     * Determines whether a raw authentication result succeeded.
     */
    fun isAuthenticationSuccessful(
        result: BiometricAuthenticationResult
    ): Boolean {

        return result is
                BiometricAuthenticationResult.Success
    }

    /**
     * Determines whether a normalized authentication result succeeded.
     */
    fun isAuthenticationSuccessful(
        result: SentriXBiometricResult
    ): Boolean {

        return result is
                SentriXBiometricResult.Authenticated
    }

    /**
     * Determines whether authentication should be retried.
     */
    fun shouldRetry(
        result: BiometricAuthenticationResult
    ): Boolean {

        return when (result) {

            BiometricAuthenticationResult.Success ->
                false

            BiometricAuthenticationResult.FailedAttempt ->
                true

            is BiometricAuthenticationResult.HardwareUnavailable ->
                true

            is BiometricAuthenticationResult.Timeout ->
                true

            is BiometricAuthenticationResult.ProcessingError ->
                true

            is BiometricAuthenticationResult.VendorError ->
                true

            else ->
                false
        }
    }

    // -------------------------------------------------------------------------
    // Security Policy Helpers
    // -------------------------------------------------------------------------

    /**
     * Determines whether a policy contains strong biometric
     * authentication.
     */
    fun requiresStrongBiometric(
        policy: BiometricSecurityPolicy
    ): Boolean {

        return containsStrongBiometric(
            policy.authenticators
        )
    }

    /**
     * Determines whether a policy contains device credential fallback.
     */
    fun allowsDeviceCredential(
        policy: BiometricSecurityPolicy
    ): Boolean {

        return containsDeviceCredential(
            policy.authenticators
        )
    }

    /**
     * Determines whether a policy is biometric-only.
     */
    fun isBiometricOnly(
        policy: BiometricSecurityPolicy
    ): Boolean {

        return !containsDeviceCredential(
            policy.authenticators
        )
    }

    /**
     * Determines whether a policy permits high-security
     * biometric authentication.
     */
    fun isHighSecurityPolicy(
        policy: BiometricSecurityPolicy
    ): Boolean {

        return policy.requireStrongBiometric &&
                containsStrongBiometric(
                    policy.authenticators
                ) &&
                !policy.allowDeviceCredentialFallback
    }

    // -------------------------------------------------------------------------
    // Internal Helpers
    // -------------------------------------------------------------------------

    /**
     * Determines whether the authenticator configuration contains
     * strong biometric authentication.
     */
    private fun containsStrongBiometric(
        authenticators: Int
    ): Boolean {

        return (
            authenticators and
                    androidx.biometric.BiometricManager.Authenticators
                        .BIOMETRIC_STRONG
            ) != 0
    }

    /**
     * Determines whether the authenticator configuration contains
     * device credential authentication.
     */
    private fun containsDeviceCredential(
        authenticators: Int
    ): Boolean {

        return (
            authenticators and
                    androidx.biometric.BiometricManager.Authenticators
                        .DEVICE_CREDENTIAL
            ) != 0
    }

    /**
     * Generates a safe description of an authentication result.
     *
     * Raw exception details are intentionally not exposed as
     * security decisions.
     */
    private fun getResultDescription(
        result: SentriXBiometricResult
    ): String {

        return when (result) {

            is SentriXBiometricResult.Authenticated ->
                "Authentication succeeded."

            is SentriXBiometricResult.RetryableFailure ->
                "Authentication attempt failed."

            is SentriXBiometricResult.TemporaryFailure ->
                "Authentication is temporarily unavailable."

            is SentriXBiometricResult.Cancelled ->
                "Authentication was cancelled."

            is SentriXBiometricResult.LockedOut ->
                "Authentication is locked."

            is SentriXBiometricResult.ConfigurationRequired ->
                "Authentication configuration is required."

            is SentriXBiometricResult.Unsupported ->
                "Authentication is unsupported."

            is SentriXBiometricResult.Failure ->
                "Authentication failed."
        }
    }
}

/**
 * Result returned by SentriX biometric validation.
 *
 * Higher layers can use this result to make security decisions without
 * depending on Android biometric error codes.
 */
sealed class BiometricValidationResult {

    /**
     * Validation succeeded.
     */
    data object Valid :
        BiometricValidationResult()

    /**
     * Biometric security policy is structurally invalid.
     */
    data class InvalidPolicy(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Application-level biometric requirement is invalid.
     */
    data class InvalidRequirement(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Requested biometric mechanism is unsupported.
     */
    data class Unsupported(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Required authentication has not been enrolled.
     */
    data class EnrollmentRequired(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Required biometric hardware does not exist.
     */
    data object NoHardware :
        BiometricValidationResult()

    /**
     * Authentication hardware/system is temporarily unavailable.
     */
    data class TemporarilyUnavailable(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Current authentication level does not satisfy the requested
     * minimum security level.
     */
    data class InsufficientSecurityLevel(
        val required: BiometricSecurityLevel,
        val available: BiometricSecurityLevel
    ) : BiometricValidationResult()

    /**
     * Authentication was cancelled.
     */
    data class AuthenticationCancelled(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Authentication has been locked out.
     */
    data class AuthenticationLockedOut(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Authentication itself failed.
     */
    data class AuthenticationFailed(
        val reason: String
    ) : BiometricValidationResult()

    /**
     * Device security update is required.
     */
    data object SecurityUpdateRequired :
        BiometricValidationResult()

    /**
     * Unknown validation state.
     */
    data object Unknown :
        BiometricValidationResult()

    /**
     * Unexpected system/application error.
     */
    data class Error(
        val cause: Throwable
    ) : BiometricValidationResult()
}
