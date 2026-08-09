package com.sentrix.security.integrity

import android.content.Context
import android.content.pm.PackageInfo
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * SentriX Integrity Validator
 *
 * Enterprise-grade validator for application integrity results.
 *
 * Responsibilities:
 *
 * - Validate IntegrityCheckReport objects.
 * - Validate package identity.
 * - Validate APK fingerprint integrity.
 * - Validate signing certificate fingerprints.
 * - Validate trusted integrity baselines.
 * - Validate runtime integrity findings.
 * - Enforce configurable integrity policies.
 * - Produce a normalized validation result.
 *
 * IntegrityChecker:
 *
 *      "What did we observe?"
 *
 * IntegrityValidator:
 *
 *      "Does what we observed satisfy our security policy?"
 *
 * IntegrityManager:
 *
 *      "How should the application coordinate and react to it?"
 *
 * This separation keeps SentriX's integrity architecture maintainable.
 *
 * This class DOES NOT:
 *
 * - Replace Android Verified Boot.
 * - Replace Play Integrity.
 * - Perform root detection.
 * - Perform APK hashing as its primary responsibility.
 * - Modify application files.
 * - Bypass Android security mechanisms.
 */
class IntegrityValidator(
    context: Context
) {

    /**
     * Application context prevents accidental retention of an Activity.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Package manager used for package-level validation.
     */
    private val packageManager =
        applicationContext.packageManager

    // =========================================================================
    // Main Validation
    // =========================================================================

    /**
     * Validates the current application's integrity report using the
     * default SentriX policy.
     */
    fun validate(
        report: IntegrityCheckReport
    ): IntegrityValidationResult {

        return validate(
            report = report,
            policy =
                IntegrityValidationPolicy.default()
        )
    }

    /**
     * Validates an integrity report against a security policy.
     */
    fun validate(
        report: IntegrityCheckReport,
        policy: IntegrityValidationPolicy
    ): IntegrityValidationResult {

        val policyError =
            validatePolicyConfiguration(
                policy
            )

        if (
            policyError != null
        ) {

            return IntegrityValidationResult
                .ConfigurationError(
                    policyError
                )
        }

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        // ---------------------------------------------------------------------
        // Package validation
        // ---------------------------------------------------------------------

        findings +=
            validatePackageIdentity(
                report
            )

        // ---------------------------------------------------------------------
        // APK fingerprint validation
        // ---------------------------------------------------------------------

        if (
            policy.requireApkFingerprint
        ) {

            findings +=
                validateApkFingerprint(
                    report
                )
        }

        // ---------------------------------------------------------------------
        // Signature fingerprint validation
        // ---------------------------------------------------------------------

        if (
            policy.requireSignatureFingerprint
        ) {

            findings +=
                validateSignatureFingerprint(
                    report
                )
        }

        // ---------------------------------------------------------------------
        // Package metadata
        // ---------------------------------------------------------------------

        findings +=
            validatePackageMetadata(
                report
            )

        // ---------------------------------------------------------------------
        // Runtime findings
        // ---------------------------------------------------------------------

        if (
            policy.validateRuntimeIntegrity
        ) {

            findings +=
                validateRuntimeIndicators(
                    report,
                    policy
                )
        }

        // ---------------------------------------------------------------------
        // Report findings
        // ---------------------------------------------------------------------

        findings +=
            validateExistingIntegrityFindings(
                report,
                policy
            )

        // ---------------------------------------------------------------------
        // Overall validation
        // ---------------------------------------------------------------------

        val severity =
            calculateValidationSeverity(
                findings
            )

        val decision =
            determineDecision(
                severity =
                    severity,
                policy =
                    policy
            )

        return IntegrityValidationResult
            .Evaluated(

                packageName =
                    report.packageName,

                valid =
                    decision ==
                            IntegrityValidationDecision
                                .ALLOW,

                severity =
                    severity,

                decision =
                    decision,

                findings =
                    findings.distinct(),

                validatedAtMillis =
                    System.currentTimeMillis()
            )
    }

    // =========================================================================
    // Baseline Validation
    // =========================================================================

    /**
     * Validates a report against a trusted integrity baseline.
     */
    fun validateAgainstBaseline(
        report: IntegrityCheckReport,
        baseline: IntegrityBaseline
    ): IntegrityValidationResult {

        return validateAgainstBaseline(
            report =
                report,
            baseline =
                baseline,
            policy =
                IntegrityValidationPolicy.default()
        )
    }

    /**
     * Performs baseline validation using a custom policy.
     */
    fun validateAgainstBaseline(
        report: IntegrityCheckReport,
        baseline: IntegrityBaseline,
        policy: IntegrityValidationPolicy
    ): IntegrityValidationResult {

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        // ---------------------------------------------------------------------
        // Package name
        // ---------------------------------------------------------------------

        if (
            report.packageName !=
            baseline.packageName
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .PACKAGE_NAME_MISMATCH,

                    severity =
                        IntegrityValidationSeverity
                            .CRITICAL,

                    message =
                        "Current package name does not match " +
                                "the trusted integrity baseline."
                )
        }

        // ---------------------------------------------------------------------
        // Package fingerprint
        // ---------------------------------------------------------------------

        if (
            report.packageFingerprint !=
            baseline.packageFingerprint
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .PACKAGE_FINGERPRINT_MISMATCH,

                    severity =
                        IntegrityValidationSeverity
                            .HIGH,

                    message =
                        "Package fingerprint does not match " +
                                "the trusted baseline."
                )
        }

        // ---------------------------------------------------------------------
        // APK fingerprint
        // ---------------------------------------------------------------------

        if (
            policy.requireApkFingerprint &&
            baseline.apkFingerprint != null
        ) {

            if (
                report.apkFingerprint == null
            ) {

                findings +=
                    IntegrityValidationFinding(

                        type =
                            IntegrityValidationFindingType
                                .APK_FINGERPRINT_MISSING,

                        severity =
                            IntegrityValidationSeverity
                                .CRITICAL,

                        message =
                            "APK fingerprint is required but unavailable."
                    )

            } else if (
                !secureEquals(
                    report.apkFingerprint,
                    baseline.apkFingerprint
                )
            ) {

                findings +=
                    IntegrityValidationFinding(

                        type =
                            IntegrityValidationFindingType
                                .APK_FINGERPRINT_MISMATCH,

                        severity =
                            IntegrityValidationSeverity
                                .CRITICAL,

                        message =
                            "Installed APK fingerprint does not match " +
                                    "the trusted baseline."
                    )
            }
        }

        // ---------------------------------------------------------------------
        // Signature fingerprint
        // ---------------------------------------------------------------------

        if (
            policy.requireSignatureFingerprint &&
            baseline.signatureFingerprint != null
        ) {

            if (
                report.signatureFingerprint == null
            ) {

                findings +=
                    IntegrityValidationFinding(

                        type =
                            IntegrityValidationFindingType
                                .SIGNATURE_FINGERPRINT_MISSING,

                        severity =
                            IntegrityValidationSeverity
                                .CRITICAL,

                        message =
                            "Signing certificate fingerprint is required " +
                                    "but unavailable."
                    )

            } else if (
                !secureEquals(
                    report.signatureFingerprint,
                    baseline.signatureFingerprint
                )
            ) {

                findings +=
                    IntegrityValidationFinding(

                        type =
                            IntegrityValidationFindingType
                                .SIGNATURE_FINGERPRINT_MISMATCH,

                        severity =
                            IntegrityValidationSeverity
                                .CRITICAL,

                        message =
                            "Application signing fingerprint does not match " +
                                    "the trusted baseline."
                    )
            }
        }

        return createValidationResult(
            packageName =
                report.packageName,
            findings =
                findings,
            policy =
                policy
        )
    }

    // =========================================================================
    // Package Validation
    // =========================================================================

    /**
     * Validates that the inspected package identity is internally consistent.
     */
    private fun validatePackageIdentity(
        report: IntegrityCheckReport
    ): List<IntegrityValidationFinding> {

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        if (
            report.packageName.isBlank()
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .PACKAGE_NAME_MISSING,

                    severity =
                        IntegrityValidationSeverity
                            .CRITICAL,

                    message =
                        "Package name is missing from the integrity report."
                )

            return findings
        }

        if (
            !isValidPackageName(
                report.packageName
            )
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .INVALID_PACKAGE_NAME,

                    severity =
                        IntegrityValidationSeverity
                            .HIGH,

                    message =
                        "Package name does not follow Android package naming rules."
                )

            return findings
        }

        val installedPackage =
            try {

                getPackageInfo(
                    report.packageName
                )

            } catch (
                _: Exception
            ) {

                null
            }

        if (
            installedPackage == null
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .PACKAGE_NOT_INSTALLED,

                    severity =
                        IntegrityValidationSeverity
                            .CRITICAL,

                    message =
                        "The inspected package is not currently installed " +
                                "or is not accessible."
                )

            return findings
        }

        return findings
    }

    /**
     * Performs basic Android package-name validation.
     */
    fun isValidPackageName(
        packageName: String
    ): Boolean {

        if (
            packageName.isBlank()
        ) {

            return false
        }

        val parts =
            packageName.split(
                "."
            )

        if (
            parts.size < 2
        ) {

            return false
        }

        return parts.all {
            part ->
            part.isNotBlank() &&
                    part[0].isLetter() &&
                    part.all {
                        character ->
                        character.isLetterOrDigit() ||
                                character == '_'
                    }
        }
    }

    /**
     * Retrieves installed package information.
     */
    private fun getPackageInfo(
        packageName: String
    ): PackageInfo? {

        return try {

            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.TIRAMISU
            ) {

                packageManager.getPackageInfo(
                    packageName,
                    PackageManager
                        .PackageInfoFlags
                        .of(
                            0L
                        )
                )

            } else {

                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(
                    packageName,
                    0
                )
            }

        } catch (
            _: PackageManager.NameNotFoundException
        ) {

            null
        }
    }

    // =========================================================================
    // APK Fingerprint Validation
    // =========================================================================

    /**
     * Validates that an APK fingerprint is present and correctly formatted.
     */
    private fun validateApkFingerprint(
        report: IntegrityCheckReport
    ): List<IntegrityValidationFinding> {

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        val fingerprint =
            report.apkFingerprint

        if (
            fingerprint.isNullOrBlank()
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .APK_FINGERPRINT_MISSING,

                    severity =
                        IntegrityValidationSeverity
                            .CRITICAL,

                    message =
                        "APK SHA-256 fingerprint is missing."
                )

            return findings
        }

        if (
            !isSha256Fingerprint(
                fingerprint
            )
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .APK_FINGERPRINT_INVALID,

                    severity =
                        IntegrityValidationSeverity
                            .HIGH,

                    message =
                        "APK fingerprint is not a valid SHA-256 fingerprint."
                )
        }

        return findings
    }

    /**
     * Validates a supplied APK fingerprint directly.
     */
    fun validateApkFingerprint(
        fingerprint: String
    ): Boolean {

        return isSha256Fingerprint(
            fingerprint
        )
    }

    // =========================================================================
    // Signature Validation
    // =========================================================================

    /**
     * Validates signing certificate fingerprint presence and format.
     */
    private fun validateSignatureFingerprint(
        report: IntegrityCheckReport
    ): List<IntegrityValidationFinding> {

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        val fingerprint =
            report.signatureFingerprint

        if (
            fingerprint.isNullOrBlank()
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .SIGNATURE_FINGERPRINT_MISSING,

                    severity =
                        IntegrityValidationSeverity
                            .CRITICAL,

                    message =
                        "Signing certificate fingerprint is missing."
                )

            return findings
        }

        if (
            !isSha256Fingerprint(
                fingerprint
            )
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .SIGNATURE_FINGERPRINT_INVALID,

                    severity =
                        IntegrityValidationSeverity
                            .HIGH,

                    message =
                        "Signing certificate fingerprint is not a valid SHA-256 fingerprint."
                )
        }

        return findings
    }

    /**
     * Validates a signing certificate fingerprint directly.
     */
    fun validateSignatureFingerprint(
        fingerprint: String
    ): Boolean {

        return isSha256Fingerprint(
            fingerprint
        )
    }

    // =========================================================================
    // Package Metadata Validation
    // =========================================================================

    /**
     * Validates package metadata contained within an integrity report.
     */
    private fun validatePackageMetadata(
        report: IntegrityCheckReport
    ): List<IntegrityValidationFinding> {

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        val metadata =
            report.packageMetadata
                ?: return listOf(
                    IntegrityValidationFinding(

                        type =
                            IntegrityValidationFindingType
                                .PACKAGE_METADATA_MISSING,

                        severity =
                            IntegrityValidationSeverity
                                .HIGH,

                        message =
                            "Package metadata is missing from the report."
                    )
                )

        if (
            metadata.packageName !=
            report.packageName
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .PACKAGE_METADATA_MISMATCH,

                    severity =
                        IntegrityValidationSeverity
                            .HIGH,

                    message =
                        "Package metadata does not match the report package name."
                )
        }

        if (
            metadata.versionCode < 0L
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .INVALID_VERSION_CODE,

                    severity =
                        IntegrityValidationSeverity
                            .MEDIUM,

                    message =
                        "Package version code is invalid."
                )
        }

        if (
            metadata.targetSdk <= 0
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .INVALID_TARGET_SDK,

                    severity =
                        IntegrityValidationSeverity
                            .MEDIUM,

                    message =
                        "Target SDK information is invalid."
                )
        }

        if (
            metadata.sourcePath.isBlank()
        ) {

            findings +=
                IntegrityValidationFinding(

                    type =
                        IntegrityValidationFindingType
                            .APK_PATH_MISSING,

                    severity =
                        IntegrityValidationSeverity
                            .HIGH,

                    message =
                        "APK source path is missing."
                )
        }

        return findings
    }

    // =========================================================================
    // Runtime Validation
    // =========================================================================

    /**
     * Validates runtime integrity indicators according to policy.
     */
    private fun validateRuntimeIndicators(
        report: IntegrityCheckReport,
        policy: IntegrityValidationPolicy
    ): List<IntegrityValidationFinding> {

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        report.findings
            .filter {
                it.type ==
                        IntegrityFindingType
                            .DEBUGGER_CONNECTED ||
                        it.type ==
                        IntegrityFindingType
                            .WAITING_FOR_DEBUGGER ||
                        it.type ==
                        IntegrityFindingType
                            .DEBUGGABLE_APPLICATION ||
                        it.type ==
                        IntegrityFindingType
                            .LIKELY_EMULATOR
            }
            .forEach {
                finding ->

                when (
                    finding.type
                ) {

                    IntegrityFindingType
                        .DEBUGGER_CONNECTED -> {

                        if (
                            policy.blockDebugger
                        ) {

                            findings +=
                                IntegrityValidationFinding(

                                    type =
                                        IntegrityValidationFindingType
                                            .DEBUGGER_DETECTED,

                                    severity =
                                        IntegrityValidationSeverity
                                            .HIGH,

                                    message =
                                        "A debugger is connected to the application."
                                )
                        }
                    }

                    IntegrityFindingType
                        .WAITING_FOR_DEBUGGER -> {

                        if (
                            policy.blockDebugger
                        ) {

                            findings +=
                                IntegrityValidationFinding(

                                    type =
                                        IntegrityValidationFindingType
                                            .DEBUGGER_WAITING_STATE,

                                    severity =
                                        IntegrityValidationSeverity
                                            .HIGH,

                                    message =
                                        "The application is waiting for a debugger."
                                )
                        }
                    }

                    IntegrityFindingType
                        .DEBUGGABLE_APPLICATION -> {

                        if (
                            policy.blockDebuggableBuild
                        ) {

                            findings +=
                                IntegrityValidationFinding(

                                    type =
                                        IntegrityValidationFindingType
                                            .DEBUGGABLE_BUILD,

                                    severity =
                                        IntegrityValidationSeverity
                                            .HIGH,

                                    message =
                                        "The application is marked as debuggable."
                                )
                        }
                    }

                    IntegrityFindingType
                        .LIKELY_EMULATOR -> {

                        if (
                            policy.blockEmulator
                        ) {

                            findings +=
                                IntegrityValidationFinding(

                                    type =
                                        IntegrityValidationFindingType
                                            .EMULATOR_INDICATOR,

                                    severity =
                                        IntegrityValidationSeverity
                                            .MEDIUM,

                                    message =
                                        "The runtime contains emulator-like characteristics."
                                )
                        }
                    }

                    else ->
                        Unit
                }
            }

        return findings
    }

    // =========================================================================
    // Existing Finding Validation
    // =========================================================================

    /**
     * Converts important IntegrityChecker findings into validator findings.
     */
    private fun validateExistingIntegrityFindings(
        report: IntegrityCheckReport,
        policy: IntegrityValidationPolicy
    ): List<IntegrityValidationFinding> {

        val findings =
            mutableListOf<IntegrityValidationFinding>()

        report.findings.forEach {
            finding ->

            when (
                finding.type
            ) {

                IntegrityFindingType
                    .APK_NOT_FOUND,

                IntegrityFindingType
                    .APK_HASH_FAILED -> {

                    findings +=
                        IntegrityValidationFinding(

                            type =
                                IntegrityValidationFindingType
                                    .APK_INTEGRITY_FAILURE,

                            severity =
                                IntegrityValidationSeverity
                                    .CRITICAL,

                            message =
                                finding.description
                        )
                }

                IntegrityFindingType
                    .SIGNATURE_UNAVAILABLE -> {

                    findings +=
                        IntegrityValidationFinding(

                            type =
                                IntegrityValidationFindingType
                                    .SIGNATURE_INTEGRITY_FAILURE,

                            severity =
                                IntegrityValidationSeverity
                                    .CRITICAL,

                            message =
                                finding.description
                        )
                }

                IntegrityFindingType
                    .PACKAGE_METADATA_UNAVAILABLE -> {

                    findings +=
                        IntegrityValidationFinding(

                            type =
                                IntegrityValidationFindingType
                                    .PACKAGE_METADATA_FAILURE,

                            severity =
                                IntegrityValidationSeverity
                                    .HIGH,

                            message =
                                finding.description
                        )
                }

                IntegrityFindingType
                    .APK_FINGERPRINT_MISMATCH -> {

                    if (
                        policy.blockFingerprintMismatch
                    ) {

                        findings +=
                            IntegrityValidationFinding(

                                type =
                                    IntegrityValidationFindingType
                                        .APK_FINGERPRINT_MISMATCH,

                                severity =
                                    IntegrityValidationSeverity
                                        .CRITICAL,

                                message =
                                    finding.description
                            )
                    }
                }

                IntegrityFindingType
                    .SIGNATURE_FINGERPRINT_MISMATCH -> {

                    if (
                        policy.blockSignatureMismatch
                    ) {

                        findings +=
                            IntegrityValidationFinding(

                                type =
                                    IntegrityValidationFindingType
                                        .SIGNATURE_FINGERPRINT_MISMATCH,

                                severity =
                                    IntegrityValidationSeverity
                                        .CRITICAL,

                                message =
                                    finding.description
                            )
                    }
                }

                IntegrityFindingType
                    .PACKAGE_FINGERPRINT_MISMATCH -> {

                    if (
                        policy.blockPackageMismatch
                    ) {

                        findings +=
                            IntegrityValidationFinding(

                                type =
                                    IntegrityValidationFindingType
                                        .PACKAGE_FINGERPRINT_MISMATCH,

                                severity =
                                    IntegrityValidationSeverity
                                        .HIGH,

                                message =
                                    finding.description
                            )
                    }
                }

                IntegrityFindingType
                    .INSPECTION_FAILURE -> {

                    findings +=
                        IntegrityValidationFinding(

                            type =
                                IntegrityValidationFindingType
                                    .INSPECTION_FAILURE,

                            severity =
                                IntegrityValidationSeverity
                                    .CRITICAL,

                            message =
                                finding.description
                        )
                }

                else ->
                    Unit
            }
        }

        return findings
    }

    // =========================================================================
    // Fingerprint Format Validation
    // =========================================================================

    /**
     * Validates a SHA-256 fingerprint.
     *
     * Supported representations:
     *
     *      AA:BB:CC...
     *
     * and:
     *
     *      AABBCC...
     */
    fun isSha256Fingerprint(
        fingerprint: String
    ): Boolean {

        val normalized =
            fingerprint
                .trim()
                .replace(
                    ":",
                    ""
                )
                .replace(
                    "-",
                    ""
                )
                .uppercase()

        if (
            normalized.length != 64
        ) {

            return false
        }

        return normalized.all {
            it in
                    '0'..'9' ||
                    it in
                    'A'..'F'
        }
    }

    /**
     * Normalizes a fingerprint into colon-separated uppercase SHA-256 format.
     */
    fun normalizeSha256Fingerprint(
        fingerprint: String
    ): String? {

        val normalized =
            fingerprint
                .trim()
                .replace(
                    ":",
                    ""
                )
                .replace(
                    "-",
                    ""
                )
                .uppercase()

        if (
            normalized.length != 64 ||
            !normalized.all {
                it in
                        '0'..'9' ||
                        it in
                        'A'..'F'
            }
        ) {

            return null
        }

        return normalized
            .chunked(
                2
            )
            .joinToString(":")
    }

    // =========================================================================
    // Cryptographic Comparison
    // =========================================================================

    /**
     * Performs constant-time comparison after normalization.
     *
     * This avoids using ordinary String equality when comparing security
     * fingerprints.
     */
    private fun secureEquals(
        first: String,
        second: String
    ): Boolean {

        val normalizedFirst =
            normalizeFingerprintForComparison(
                first
            )

        val normalizedSecond =
            normalizeFingerprintForComparison(
                second
            )

        if (
            normalizedFirst.length !=
            normalizedSecond.length
        ) {

            return false
        }

        var result =
            0

        for (
            index in
                normalizedFirst.indices
        ) {

            result =
                result or
                        (
                            normalizedFirst[index]
                                .code xor
                                    normalizedSecond[index]
                                        .code
                            )
        }

        return result == 0
    }

    /**
     * Normalizes a fingerprint for comparison.
     */
    private fun normalizeFingerprintForComparison(
        fingerprint: String
    ): String {

        return fingerprint
            .replace(
                ":",
                ""
            )
            .replace(
                "-",
                ""
            )
            .trim()
            .uppercase()
    }

    // =========================================================================
    // Severity
    // =========================================================================

    /**
     * Returns the highest validation severity.
     */
    private fun calculateValidationSeverity(
        findings:
            List<IntegrityValidationFinding>
    ): IntegrityValidationSeverity {

        return findings
            .maxByOrNull {
                it.severity.priority
            }
            ?.severity
            ?: IntegrityValidationSeverity
                .SAFE
    }

    // =========================================================================
    // Decision
    // =========================================================================

    /**
     * Determines the final validation decision.
     */
    private fun determineDecision(
        severity:
            IntegrityValidationSeverity,

        policy:
            IntegrityValidationPolicy
    ): IntegrityValidationDecision {

        return when (
            severity
        ) {

            IntegrityValidationSeverity
                .CRITICAL ->

                IntegrityValidationDecision
                    .BLOCK

            IntegrityValidationSeverity
                .HIGH ->

                if (
                    policy.blockHighRisk
                ) {

                    IntegrityValidationDecision
                        .BLOCK

                } else {

                    IntegrityValidationDecision
                        .WARN
                }

            IntegrityValidationSeverity
                .MEDIUM ->

                IntegrityValidationDecision
                    .WARN

            IntegrityValidationSeverity
                .LOW ->

                IntegrityValidationDecision
                    .ALLOW

            IntegrityValidationSeverity
                .SAFE ->

                IntegrityValidationDecision
                    .ALLOW
        }
    }

    // =========================================================================
    // Result Construction
    // =========================================================================

    /**
     * Creates a normalized validation result.
     */
    private fun createValidationResult(
        packageName: String,
        findings:
            List<IntegrityValidationFinding>,
        policy:
            IntegrityValidationPolicy
    ): IntegrityValidationResult {

        val distinctFindings =
            findings.distinct()

        val severity =
            calculateValidationSeverity(
                distinctFindings
            )

        val decision =
            determineDecision(
                severity =
                    severity,
                policy =
                    policy
            )

        return IntegrityValidationResult
            .Evaluated(

                packageName =
                    packageName,

                valid =
                    decision ==
                            IntegrityValidationDecision
                                .ALLOW,

                severity =
                    severity,

                decision =
                    decision,

                findings =
                    distinctFindings,

                validatedAtMillis =
                    System.currentTimeMillis()
            )
    }

    // =========================================================================
    // Policy Validation
    // =========================================================================

    /**
     * Validates policy configuration.
     */
    private fun validatePolicyConfiguration(
        policy:
            IntegrityValidationPolicy
    ): String? {

        if (
            policy.minimumTargetSdk < 0
        ) {

            return "Minimum target SDK cannot be negative."
        }

        return null
    }

    // =========================================================================
    // Convenience APIs
    // =========================================================================

    /**
     * Returns true when the report satisfies the default policy.
     */
    fun isValid(
        report: IntegrityCheckReport
    ): Boolean {

        return validate(
            report
        ) is IntegrityValidationResult.Evaluated &&
                (
                    validate(
                        report
                    ) as IntegrityValidationResult
                        .Evaluated
                    ).decision ==
                        IntegrityValidationDecision
                            .ALLOW
    }

    /**
     * Returns true when the report should be blocked.
     */
    fun shouldBlock(
        report: IntegrityCheckReport
    ): Boolean {

        val result =
            validate(
                report
            )

        return result is
                IntegrityValidationResult.Evaluated &&
                result.decision ==
                IntegrityValidationDecision
                    .BLOCK
    }

    /**
     * Returns true when the report requires a warning.
     */
    fun shouldWarn(
        report: IntegrityCheckReport
    ): Boolean {

        val result =
            validate(
                report
            )

        return result is
                IntegrityValidationResult.Evaluated &&
                result.decision ==
                IntegrityValidationDecision
                    .WARN
    }

    /**
     * Returns the highest validation severity.
     */
    fun getSeverity(
        report: IntegrityCheckReport
    ): IntegrityValidationSeverity {

        val result =
            validate(
                report
            )

        return when (
            result
        ) {

            is IntegrityValidationResult.Evaluated ->
                result.severity

            is IntegrityValidationResult.ConfigurationError ->
                IntegrityValidationSeverity
                    .CRITICAL
        }
    }
}

// =============================================================================
// Policy
// =============================================================================

/**
 * SentriX integrity-validation policy.
 */
data class IntegrityValidationPolicy(

    /**
     * APK SHA-256 fingerprint must be present.
     */
    val requireApkFingerprint: Boolean = true,

    /**
     * Signing certificate fingerprint must be present.
     */
    val requireSignatureFingerprint: Boolean = true,

    /**
     * Validate runtime integrity indicators.
     */
    val validateRuntimeIntegrity: Boolean = true,

    /**
     * Treat APK fingerprint mismatches as blocking.
     */
    val blockFingerprintMismatch: Boolean = true,

    /**
     * Treat signing certificate mismatches as blocking.
     */
    val blockSignatureMismatch: Boolean = true,

    /**
     * Treat package fingerprint mismatches as blocking.
     */
    val blockPackageMismatch: Boolean = true,

    /**
     * Block debugger-connected applications.
     */
    val blockDebugger: Boolean = true,

    /**
     * Block debuggable builds.
     */
    val blockDebuggableBuild: Boolean = true,

    /**
     * Block emulator indicators.
     *
     * This should generally be false for consumer applications because
     * emulator detection is heuristic.
     */
    val blockEmulator: Boolean = false,

    /**
     * Block high-risk validation states.
     */
    val blockHighRisk: Boolean = true,

    /**
     * Minimum target SDK required by policy.
     */
    val minimumTargetSdk: Int = 0
) {

    companion object {

        /**
         * Default SentriX validation policy.
         */
        fun default():
                IntegrityValidationPolicy {

            return IntegrityValidationPolicy()
        }

        /**
         * Strict policy for sensitive enterprise operations.
         */
        fun strict():
                IntegrityValidationPolicy {

            return IntegrityValidationPolicy(

                requireApkFingerprint =
                    true,

                requireSignatureFingerprint =
                    true,

                validateRuntimeIntegrity =
                    true,

                blockFingerprintMismatch =
                    true,

                blockSignatureMismatch =
                    true,

                blockPackageMismatch =
                    true,

                blockDebugger =
                    true,

                blockDebuggableBuild =
                    true,

                blockEmulator =
                    true,

                blockHighRisk =
                    true,

                minimumTargetSdk =
                    35
            )
        }

        /**
         * Monitoring policy.
         *
         * Integrity anomalies are surfaced as warnings rather than
         * automatically blocking the application.
         */
        fun monitoring():
                IntegrityValidationPolicy {

            return IntegrityValidationPolicy(

                requireApkFingerprint =
                    true,

                requireSignatureFingerprint =
                    true,

                validateRuntimeIntegrity =
                    true,

                blockFingerprintMismatch =
                    true,

                blockSignatureMismatch =
                    true,

                blockPackageMismatch =
                    false,

                blockDebugger =
                    false,

                blockDebuggableBuild =
                    false,

                blockEmulator =
                    false,

                blockHighRisk =
                    false,

                minimumTargetSdk =
                    0
            )
        }
    }
}

// =============================================================================
// Validation Result
// =============================================================================

/**
 * Final integrity validation result.
 */
sealed class IntegrityValidationResult {

    /**
     * Integrity report was evaluated against policy.
     */
    data class Evaluated(

        val packageName: String,

        val valid: Boolean,

        val severity:
            IntegrityValidationSeverity,

        val decision:
            IntegrityValidationDecision,

        val findings:
            List<IntegrityValidationFinding>,

        val validatedAtMillis: Long

    ) : IntegrityValidationResult()

    /**
     * Validation policy itself was invalid.
     */
    data class ConfigurationError(
        val reason: String
    ) : IntegrityValidationResult()
}

/**
 * Severity of a validation finding.
 */
enum class IntegrityValidationSeverity(
    val priority: Int
) {

    SAFE(
        priority = 0
    ),

    LOW(
        priority = 1
    ),

    MEDIUM(
        priority = 2
    ),

    HIGH(
        priority = 3
    ),

    CRITICAL(
        priority = 4
    )
}

/**
 * Final integrity-validation decision.
 */
enum class IntegrityValidationDecision {

    /**
     * Integrity satisfies the configured policy.
     */
    ALLOW,

    /**
     * Integrity has an issue but policy permits continuation.
     */
    WARN,

    /**
     * Integrity violates the configured security policy.
     */
    BLOCK
}

/**
 * Individual validation finding.
 */
data class IntegrityValidationFinding(

    val type:
        IntegrityValidationFindingType,

    val severity:
        IntegrityValidationSeverity,

    val message: String
)

/**
 * Integrity validation finding categories.
 */
enum class IntegrityValidationFindingType {

    PACKAGE_NAME_MISSING,

    INVALID_PACKAGE_NAME,

    PACKAGE_NOT_INSTALLED,

    PACKAGE_NAME_MISMATCH,

    PACKAGE_FINGERPRINT_MISMATCH,

    APK_FINGERPRINT_MISSING,

    APK_FINGERPRINT_INVALID,

    APK_FINGERPRINT_MISMATCH,

    APK_INTEGRITY_FAILURE,

    SIGNATURE_FINGERPRINT_MISSING,

    SIGNATURE_FINGERPRINT_INVALID,

    SIGNATURE_FINGERPRINT_MISMATCH,

    SIGNATURE_INTEGRITY_FAILURE,

    PACKAGE_METADATA_MISSING,

    PACKAGE_METADATA_MISMATCH,

    PACKAGE_METADATA_FAILURE,

    INVALID_VERSION_CODE,

    INVALID_TARGET_SDK,

    APK_PATH_MISSING,

    DEBUGGER_DETECTED,

    DEBUGGER_WAITING_STATE,

    DEBUGGABLE_BUILD,

    EMULATOR_INDICATOR,

    INSPECTION_FAILURE
}
