package com.sentrix.security.biometrics

import androidx.biometric.BiometricManager.Authenticators

/**
 * SentriX Biometric Constants
 *
 * Centralized constants used by the SentriX biometric security subsystem.
 *
 * Responsibilities:
 *
 * - Define biometric authenticator combinations.
 * - Define authentication timeout values.
 * - Define failure thresholds.
 * - Define prompt defaults.
 * - Define security-related limits.
 * - Define biometric session configuration.
 * - Define safe operational constants.
 *
 * IMPORTANT:
 *
 * This file contains configuration constants only.
 * It must not contain authentication logic, UI logic, or biometric
 * processing code.
 */
object BiometricConstants {

    // =========================================================================
    // Authenticator Constants
    // =========================================================================

    /**
     * Strong biometric authentication.
     *
     * Intended for high-security SentriX operations.
     *
     * Examples:
     *
     * - Security configuration changes.
     * - Disabling real-time protection.
     * - Accessing highly sensitive security information.
     * - Critical enterprise actions.
     */
    const val AUTHENTICATOR_STRONG_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG

    /**
     * Weak biometric authentication.
     *
     * Should generally not be used for the highest-risk SentriX
     * operations.
     */
    const val AUTHENTICATOR_WEAK_BIOMETRIC =
        Authenticators.BIOMETRIC_WEAK

    /**
     * Device credential authentication.
     *
     * Android may use:
     *
     * - PIN
     * - Password
     * - Pattern
     */
    const val AUTHENTICATOR_DEVICE_CREDENTIAL =
        Authenticators.DEVICE_CREDENTIAL

    /**
     * Any supported biometric authentication.
     */
    const val AUTHENTICATOR_ANY_BIOMETRIC =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.BIOMETRIC_WEAK

    /**
     * Strong biometric OR device credential.
     *
     * Recommended default policy for normal protected SentriX
     * operations.
     */
    const val AUTHENTICATOR_STRONG_OR_CREDENTIAL =
        Authenticators.BIOMETRIC_STRONG or
                Authenticators.DEVICE_CREDENTIAL

    /**
     * Strong biometric only.
     *
     * Used when device credential fallback must not be accepted.
     */
    const val AUTHENTICATOR_HIGH_SECURITY =
        Authenticators.BIOMETRIC_STRONG

    // =========================================================================
    // Authentication Timeout Constants
    // =========================================================================

    /**
     * Default amount of time that a successful SentriX authentication
     * remains valid in the in-memory application session.
     *
     * Five minutes.
     */
    const val DEFAULT_AUTHENTICATION_TIMEOUT_MILLIS =
        5 * 60 * 1000L

    /**
     * Short authentication session.
     *
     * One minute.
     *
     * Suitable for sensitive UI flows where frequent re-authentication
     * is acceptable.
     */
    const val SHORT_AUTHENTICATION_TIMEOUT_MILLIS =
        1 * 60 * 1000L

    /**
     * Extended authentication session.
     *
     * Fifteen minutes.
     *
     * Should only be used for lower-risk protected operations.
     */
    const val EXTENDED_AUTHENTICATION_TIMEOUT_MILLIS =
        15 * 60 * 1000L

    /**
     * High-security authentication timeout.
     *
     * Zero means that the authentication should be considered
     * fresh-only and should not be reused as a long-lived session.
     */
    const val HIGH_SECURITY_AUTHENTICATION_TIMEOUT_MILLIS =
        0L

    // =========================================================================
    // Authentication Attempt Constants
    // =========================================================================

    /**
     * Maximum number of biometric attempts that SentriX tracks
     * during one application authentication session.
     *
     * This DOES NOT override Android's biometric lockout policy.
     */
    const val MAX_TRACKED_FAILED_ATTEMPTS =
        5

    /**
     * Number of failed attempts considered a repeated-failure pattern
     * for SentriX telemetry.
     */
    const val REPEATED_FAILURE_THRESHOLD =
        3

    /**
     * Number of attempts after which SentriX may classify the session
     * as having a high failure rate.
     *
     * Android remains responsible for actual biometric lockout.
     */
    const val HIGH_FAILURE_THRESHOLD =
        5

    // =========================================================================
    // Prompt Constants
    // =========================================================================

    /**
     * Default biometric prompt title.
     */
    const val DEFAULT_PROMPT_TITLE =
        "SentriX Security Verification"

    /**
     * Default biometric prompt subtitle.
     */
    const val DEFAULT_PROMPT_SUBTITLE =
        "Verify your identity to continue"

    /**
     * Default high-security prompt title.
     */
    const val HIGH_SECURITY_PROMPT_TITLE =
        "SentriX High-Security Verification"

    /**
     * Default high-security prompt subtitle.
     */
    const val HIGH_SECURITY_PROMPT_SUBTITLE =
        "Strong biometric authentication required"

    /**
     * Default step-up authentication title.
     */
    const val STEP_UP_PROMPT_TITLE =
        "Additional Security Verification"

    /**
     * Default step-up authentication subtitle.
     */
    const val STEP_UP_PROMPT_SUBTITLE =
        "Additional verification is required"

    /**
     * Default biometric prompt negative button.
     *
     * This is only used when device credential fallback is NOT included
     * in the allowed authenticator configuration.
     */
    const val DEFAULT_NEGATIVE_BUTTON_TEXT =
        "Cancel"

    /**
     * Maximum allowed prompt title length.
     *
     * Prevents unexpectedly large values from entering prompt
     * configuration.
     */
    const val MAX_PROMPT_TITLE_LENGTH =
        100

    /**
     * Maximum allowed prompt subtitle length.
     */
    const val MAX_PROMPT_SUBTITLE_LENGTH =
        150

    /**
     * Maximum allowed prompt description length.
     */
    const val MAX_PROMPT_DESCRIPTION_LENGTH =
        300

    // =========================================================================
    // Error / Message Constants
    // =========================================================================

    /**
     * Maximum framework/vendor error message length retained by
     * SentriX security components.
     */
    const val MAX_ERROR_MESSAGE_LENGTH =
        256

    /**
     * Generic authentication failure message.
     */
    const val MESSAGE_AUTHENTICATION_FAILED =
        "Authentication could not be completed."

    /**
     * Generic authentication cancelled message.
     */
    const val MESSAGE_AUTHENTICATION_CANCELLED =
        "Authentication was cancelled."

    /**
     * Generic authentication unavailable message.
     */
    const val MESSAGE_AUTHENTICATION_UNAVAILABLE =
        "Biometric authentication is temporarily unavailable."

    /**
     * Generic enrollment message.
     */
    const val MESSAGE_BIOMETRIC_ENROLLMENT_REQUIRED =
        "Enroll a biometric on this device to use biometric protection."

    /**
     * Generic credential configuration message.
     */
    const val MESSAGE_DEVICE_CREDENTIAL_REQUIRED =
        "Configure a device PIN, password, or pattern."

    /**
     * Generic security update message.
     */
    const val MESSAGE_SECURITY_UPDATE_REQUIRED =
        "A device security update is required."

    /**
     * Generic unsupported authentication message.
     */
    const val MESSAGE_AUTHENTICATION_UNSUPPORTED =
        "This authentication method is not supported on this device."

    /**
     * Generic lockout message.
     */
    const val MESSAGE_AUTHENTICATION_LOCKED =
        "Biometric authentication is temporarily locked."

    /**
     * Generic permanent lockout message.
     */
    const val MESSAGE_AUTHENTICATION_PERMANENTLY_LOCKED =
        "Biometric authentication is locked. Use device security settings."

    // =========================================================================
    // Security Level Constants
    // =========================================================================

    /**
     * Minimum security level for standard protected SentriX operations.
     */
    val DEFAULT_SECURITY_LEVEL =
        BiometricSecurityLevel.BIOMETRIC

    /**
     * Security level required for high-risk SentriX operations.
     */
    val HIGH_SECURITY_LEVEL =
        BiometricSecurityLevel.STRONG_BIOMETRIC

    /**
     * Security level used when authentication is explicitly disabled.
     */
    val NO_AUTHENTICATION_SECURITY_LEVEL =
        BiometricSecurityLevel.NONE

    // =========================================================================
    // Session Constants
    // =========================================================================

    /**
     * Indicates that authentication state should not be persisted
     * beyond the current application process.
     */
    const val SESSION_PERSISTENCE_DISABLED =
        true

    /**
     * Indicates that biometric templates must never be stored by
     * SentriX.
     *
     * Actual biometric templates remain under Android's secure
     * biometric subsystem.
     */
    const val STORE_BIOMETRIC_TEMPLATES =
        false

    /**
     * Indicates that raw biometric information must never be exposed
     * to SentriX application code.
     */
    const val EXPOSE_RAW_BIOMETRIC_DATA =
        false

    // =========================================================================
    // Security Operation Constants
    // =========================================================================

    /**
     * Standard protected operation timeout.
     */
    const val STANDARD_OPERATION_TIMEOUT_MILLIS =
        5 * 60 * 1000L

    /**
     * High-risk operation timeout.
     *
     * High-risk operations should normally require fresh authentication.
     */
    const val HIGH_RISK_OPERATION_TIMEOUT_MILLIS =
        0L

    /**
     * Step-up authentication timeout.
     *
     * Step-up authentication should be short-lived.
     */
    const val STEP_UP_AUTHENTICATION_TIMEOUT_MILLIS =
        60 * 1000L

    // =========================================================================
    // Audit Constants
    // =========================================================================

    /**
     * Enables SentriX biometric security event classification.
     */
    const val AUDIT_EVENTS_ENABLED =
        true

    /**
     * Do not store raw biometric framework messages as sensitive
     * authentication data.
     */
    const val STORE_RAW_BIOMETRIC_MESSAGES =
        false

    /**
     * Indicates that biometric audit events should contain only
     * security metadata and result classifications.
     */
    const val AUDIT_RAW_BIOMETRIC_DATA =
        false

    // =========================================================================
    // Security Feature Names
    // =========================================================================

    /**
     * Feature identifier used by SentriX security telemetry.
     */
    const val FEATURE_NAME =
        "biometric_authentication"

    /**
     * High-security feature identifier.
     */
    const val HIGH_SECURITY_FEATURE_NAME =
        "biometric_high_security"

    /**
     * Step-up authentication feature identifier.
     */
    const val STEP_UP_FEATURE_NAME =
        "biometric_step_up"

    // =========================================================================
    // Validation Constants
    // =========================================================================

    /**
     * Minimum valid authentication timeout.
     */
    const val MIN_AUTHENTICATION_TIMEOUT_MILLIS =
        0L

    /**
     * Maximum supported application authentication timeout.
     *
     * One hour.
     *
     * This is an application-level safety limit and does not alter
     * Android biometric behavior.
     */
    const val MAX_AUTHENTICATION_TIMEOUT_MILLIS =
        60 * 60 * 1000L

    /**
     * Minimum number of tracked authentication attempts.
     */
    const val MIN_TRACKED_FAILED_ATTEMPTS =
        1

    /**
     * Maximum number of tracked authentication attempts.
     */
    const val MAX_ALLOWED_TRACKED_FAILED_ATTEMPTS =
        10

    // =========================================================================
    // Private Constructor Protection
    // =========================================================================

    /**
     * Prevents accidental instantiation.
     *
     * All constants are exposed through this singleton object.
     */
    private fun BiometricConstants() {
        // Constants-only container.
    }
}
