package com.sentrix.security.antitamper

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

/**
 * SignatureTamperDetector
 *
 * Detects potential application signing-identity tampering.
 *
 * The signing identity is one of the strongest application-integrity
 * signals available to an Android application because a modified or
 * repackaged APK will normally be signed with a different certificate.
 *
 * Responsibilities:
 *
 * - Retrieve the application's signing certificates.
 * - Support modern Android signing APIs.
 * - Support legacy Android versions.
 * - Calculate SHA-256 certificate fingerprints.
 * - Compare fingerprints against trusted certificates.
 * - Support legitimate signing-key rotation.
 * - Produce structured signature-integrity evidence.
 *
 * This class does NOT:
 *
 * - modify certificates
 * - alter the application
 * - terminate the application
 * - perform destructive countermeasures
 * - make unrelated runtime tampering decisions
 *
 * Architecture:
 *
 * AntiTamperManager
 *        ↓
 * SignatureTamperDetector
 *        ↓
 * SignatureTamperResult
 *        ↓
 * AntiTamperValidator
 *
 * IMPORTANT:
 *
 * Trusted certificate fingerprints are security-sensitive.
 * They should not rely solely on a mutable local preference or
 * other attacker-controlled storage.
 */
class SignatureTamperDetector(
    private val context: Context,
    private val configuration: SignatureTamperConfiguration =
        SignatureTamperConfiguration()
) {

    /**
     * Package manager used to retrieve signing information.
     */
    private val packageManager: PackageManager =
        context.packageManager

    /**
     * Current application package name.
     */
    private val packageName: String =
        context.packageName

    /**
     * Performs the complete signing-integrity assessment.
     */
    fun detect(): SignatureTamperResult {

        val evidence =
            mutableListOf<SignatureTamperEvidence>()

        var checksPerformed = 0
        var checksSuccessful = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * Retrieve signing certificates
         * ---------------------------------------------------------
         */
        val certificates =
            try {

                checksPerformed++

                val result =
                    getSigningCertificates()

                checksSuccessful++

                result

            } catch (_: Exception) {

                checksFailed++

                evidence += SignatureTamperEvidence(
                    type =
                        SignatureTamperEvidenceType.CERTIFICATE_READ_FAILED,
                    source = "PackageManager",
                    description =
                        "Application signing certificates could not be retrieved.",
                    severity = SignatureTamperSeverity.HIGH,
                    confidence = 0.70
                )

                emptyList()
            }

        /**
         * ---------------------------------------------------------
         * No certificates
         * ---------------------------------------------------------
         */
        if (certificates.isEmpty()) {

            evidence += SignatureTamperEvidence(
                type =
                    SignatureTamperEvidenceType.CERTIFICATE_UNAVAILABLE,
                source = "SigningInfo",
                description =
                    "No application signing certificates were returned.",
                severity = SignatureTamperSeverity.HIGH,
                confidence = 0.70
            )

            return createResult(
                evidence = evidence,
                checksPerformed = checksPerformed,
                checksSuccessful = checksSuccessful,
                checksFailed = checksFailed
            )
        }

        /**
         * ---------------------------------------------------------
         * Calculate fingerprints
         * ---------------------------------------------------------
         */
        val fingerprints =
            certificates.mapIndexed { index, signature ->

                val fingerprint =
                    calculateSha256(
                        signature.toByteArray()
                    )

                evidence += SignatureTamperEvidence(
                    type =
                        SignatureTamperEvidenceType.CERTIFICATE_FINGERPRINT,
                    source = "SigningCertificate",
                    description =
                        "SHA-256 fingerprint of the application signing certificate.",
                    certificateIndex = index,
                    value = fingerprint,
                    severity = SignatureTamperSeverity.INFO,
                    confidence = 1.0
                )

                fingerprint
            }

        /**
         * ---------------------------------------------------------
         * Trusted certificate comparison
         * ---------------------------------------------------------
         */
        val trustedFingerprints =
            configuration
                .trustedCertificateSha256
                .map {
                    normalizeFingerprint(it)
                }
                .toSet()

        if (trustedFingerprints.isEmpty()) {

            evidence += SignatureTamperEvidence(
                type =
                    SignatureTamperEvidenceType.TRUSTED_CERTIFICATE_NOT_CONFIGURED,
                source = "SignatureTamperConfiguration",
                description =
                    "No trusted signing certificate fingerprint is configured.",
                severity = SignatureTamperSeverity.MEDIUM,
                confidence = 1.0
            )

        } else {

            val normalizedObserved =
                fingerprints.map {
                    normalizeFingerprint(it)
                }

            val matchingCertificates =
                normalizedObserved.filter {
                    it in trustedFingerprints
                }

            if (matchingCertificates.isNotEmpty()) {

                evidence += SignatureTamperEvidence(
                    type =
                        SignatureTamperEvidenceType.CERTIFICATE_MATCH,
                    source = "TrustedCertificate",
                    description =
                        "At least one application signing certificate matches the trusted certificate set.",
                    value =
                        matchingCertificates.joinToString(","),
                    expectedValue =
                        trustedFingerprints.joinToString(","),
                    severity = SignatureTamperSeverity.INFO,
                    confidence = 1.0
                )

            } else {

                evidence += SignatureTamperEvidence(
                    type =
                        SignatureTamperEvidenceType.CERTIFICATE_MISMATCH,
                    source = "TrustedCertificate",
                    description =
                        "None of the observed application signing certificates match the trusted certificate set.",
                    value =
                        normalizedObserved.joinToString(","),
                    expectedValue =
                        trustedFingerprints.joinToString(","),
                    severity = SignatureTamperSeverity.CRITICAL,
                    confidence = 1.0
                )
            }

            /**
             * Additional evidence when unexpected certificates are
             * present alongside an otherwise trusted certificate.
             *
             * This can happen with certificate rotation or unusual
             * signing configurations, so it remains evidence for
             * the validator rather than automatically being classified
             * as tampering.
             */
            val unexpectedCertificates =
                normalizedObserved.filter {
                    it !in trustedFingerprints
                }

            if (
                matchingCertificates.isNotEmpty() &&
                unexpectedCertificates.isNotEmpty()
            ) {

                evidence += SignatureTamperEvidence(
                    type =
                        SignatureTamperEvidenceType.UNEXPECTED_CERTIFICATE,
                    source = "TrustedCertificate",
                    description =
                        "An additional signing certificate was observed that is not present in the trusted certificate set.",
                    value =
                        unexpectedCertificates.joinToString(","),
                    expectedValue =
                        trustedFingerprints.joinToString(","),
                    severity = SignatureTamperSeverity.MEDIUM,
                    confidence = 0.90
                )
            }
        }

        /**
         * ---------------------------------------------------------
         * Certificate count
         * ---------------------------------------------------------
         */
        evidence += SignatureTamperEvidence(
            type =
                SignatureTamperEvidenceType.CERTIFICATE_COUNT,
            source = "SigningInfo",
            description =
                "Number of signing certificates observed.",
            value =
                certificates.size.toString(),
            severity = SignatureTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * ---------------------------------------------------------
         * Signing scheme metadata
         * ---------------------------------------------------------
         */
        collectSigningSchemeEvidence(
            evidence
        )

        return createResult(
            evidence = evidence,
            checksPerformed = checksPerformed,
            checksSuccessful = checksSuccessful,
            checksFailed = checksFailed
        )
    }

    /**
     * Retrieves the application's signing certificates.
     *
     * Android 9+ uses SigningInfo.
     * Older Android versions expose Signature[] directly.
     */
    @Suppress("DEPRECATION")
    private fun getSigningCertificates():
            List<Signature> {

        val packageInfo =
            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.P
            ) {

                packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )

            } else {

                packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.P
        ) {

            val signingInfo =
                packageInfo.signingInfo
                    ?: return emptyList()

            /**
             * When multiple signers are present, these represent
             * the current APK signing certificates.
             */
            if (
                signingInfo.hasMultipleSigners()
            ) {

                signingInfo.apkContentsSigners
                    ?.toList()
                    ?: emptyList()

            } else {

                /**
                 * For normal single-signer applications, the history
                 * is useful for supporting signing-key rotation.
                 *
                 * Whether history or current signer is used as the
                 * authoritative identity is controlled by configuration.
                 */
                if (
                    configuration.includeSigningCertificateHistory
                ) {

                    signingInfo
                        .signingCertificateHistory
                        ?.toList()
                        ?: emptyList()

                } else {

                    signingInfo
                        .apkContentsSigners
                        ?.toList()
                        ?: emptyList()
                }
            }

        } else {

            packageInfo.signatures
                ?.toList()
                ?: emptyList()
        }
    }

    /**
     * Collects information about the signing schemes supported
     * by the installed package.
     *
     * This is contextual evidence only.
     */
    private fun collectSigningSchemeEvidence(
        evidence: MutableList<SignatureTamperEvidence>
    ) {

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.N
        ) {

            val packageInfo =
                try {

                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES
                    )

                } catch (_: Exception) {

                    return
                }

            val signingInfo =
                packageInfo.signingInfo
                    ?: return

            /**
             * APK Signature Scheme v3/v4 rotation information is
             * represented by SigningInfo on modern Android versions.
             *
             * We record whether signing history exists rather than
             * attempting to infer tampering from history alone.
             */
            val hasHistory =
                signingInfo
                    .signingCertificateHistory
                    ?.isNotEmpty()
                    == true

            evidence += SignatureTamperEvidence(
                type =
                    SignatureTamperEvidenceType.SIGNING_HISTORY_AVAILABLE,
                source = "SigningInfo",
                description =
                    "Android reports signing certificate history availability.",
                value = hasHistory.toString(),
                severity = SignatureTamperSeverity.INFO,
                confidence = 1.0
            )
        }
    }

    /**
     * Calculates SHA-256 fingerprint of certificate bytes.
     */
    private fun calculateSha256(
        data: ByteArray
    ): String {

        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(data)

        return digest.joinToString("") {
            "%02X".format(it)
        }
    }

    /**
     * Normalizes fingerprints so formats such as:
     *
     * AA:BB:CC
     *
     * and
     *
     * AABBCC
     *
     * compare identically.
     */
    private fun normalizeFingerprint(
        fingerprint: String
    ): String {

        return fingerprint
            .replace(":", "")
            .replace(" ", "")
            .replace("-", "")
            .trim()
            .uppercase()
    }

    /**
     * Creates the final detector result.
     */
    private fun createResult(
        evidence: List<SignatureTamperEvidence>,
        checksPerformed: Int,
        checksSuccessful: Int,
        checksFailed: Int
    ): SignatureTamperResult {

        val mismatchDetected =
            evidence.any {
                it.type ==
                        SignatureTamperEvidenceType.CERTIFICATE_MISMATCH
            }

        val unexpectedCertificate =
            evidence.any {
                it.type ==
                        SignatureTamperEvidenceType.UNEXPECTED_CERTIFICATE
            }

        val trustedConfigurationMissing =
            evidence.any {
                it.type ==
                        SignatureTamperEvidenceType.TRUSTED_CERTIFICATE_NOT_CONFIGURED
            }

        val status =
            when {

                mismatchDetected ->
                    SignatureTamperStatus.SIGNATURE_TAMPER_DETECTED

                unexpectedCertificate ->
                    SignatureTamperStatus.SUSPICIOUS

                trustedConfigurationMissing ->
                    SignatureTamperStatus.TRUST_CONFIGURATION_MISSING

                checksFailed > 0 ->
                    SignatureTamperStatus.CHECK_INCOMPLETE

                else ->
                    SignatureTamperStatus.SIGNATURE_VALID
            }

        return SignatureTamperResult(
            packageName = packageName,
            status = status,
            evidence = evidence,
            checksPerformed = checksPerformed,
            checksSuccessful = checksSuccessful,
            checksFailed = checksFailed,
            detectionCompleted =
                checksFailed == 0 &&
                        evidence.none {
                            it.type ==
                                    SignatureTamperEvidenceType.CERTIFICATE_UNAVAILABLE
                        },
            detectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Returns true when a trusted signing certificate mismatch
     * was detected.
     */
    fun isSignatureTampered(): Boolean {

        return detect().status ==
                SignatureTamperStatus.SIGNATURE_TAMPER_DETECTED
    }

    /**
     * Returns true when the installed signing identity matches
     * the trusted configuration.
     */
    fun isSignatureTrusted(): Boolean {

        return detect().status ==
                SignatureTamperStatus.SIGNATURE_VALID
    }

    /**
     * Returns all observed certificate fingerprints.
     */
    fun getCertificateFingerprints():
            List<String> {

        return detect()
            .evidence
            .filter {
                it.type ==
                        SignatureTamperEvidenceType.CERTIFICATE_FINGERPRINT
            }
            .mapNotNull {
                it.value
            }
    }

    /**
     * Returns all signature mismatch evidence.
     */
    fun getMismatchEvidence():
            List<SignatureTamperEvidence> {

        return detect()
            .evidence
            .filter {
                it.type ==
                        SignatureTamperEvidenceType.CERTIFICATE_MISMATCH
            }
    }

    /**
     * Returns all signature-related evidence.
     */
    fun getEvidence():
            List<SignatureTamperEvidence> {

        return detect().evidence
    }

    /**
     * Returns the package name being inspected.
     */
    fun getPackageName(): String {

        return packageName
    }
}

/**
 * Trusted signing identity configuration.
 *
 * trustedCertificateSha256 can contain multiple fingerprints to
 * support legitimate signing-key rotation.
 */
data class SignatureTamperConfiguration(

    /**
     * Trusted SHA-256 certificate fingerprints.
     */
    val trustedCertificateSha256:
        Set<String> = emptySet(),

    /**
     * Whether signing certificate history should be included
     * when collecting certificates on Android 9+.
     *
     * This is useful when the application supports signing-key
     * rotation.
     */
    val includeSigningCertificateHistory:
        Boolean = true
)

/**
 * Complete signature-integrity result.
 */
data class SignatureTamperResult(

    /**
     * Application package being inspected.
     */
    val packageName: String,

    /**
     * Overall signature-integrity state.
     */
    val status: SignatureTamperStatus,

    /**
     * Collected evidence.
     */
    val evidence: List<SignatureTamperEvidence>,

    /**
     * Number of signature checks performed.
     */
    val checksPerformed: Int,

    /**
     * Number of successful checks.
     */
    val checksSuccessful: Int,

    /**
     * Number of failed checks.
     */
    val checksFailed: Int,

    /**
     * Whether detection completed.
     */
    val detectionCompleted: Boolean,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long
) {

    /**
     * Indicates a trusted signing identity mismatch.
     */
    val isTampered: Boolean
        get() =
            status ==
                    SignatureTamperStatus.SIGNATURE_TAMPER_DETECTED

    /**
     * Indicates the signing identity was successfully validated.
     */
    val isTrusted: Boolean
        get() =
            status ==
                    SignatureTamperStatus.SIGNATURE_VALID

    /**
     * Returns observed certificate fingerprints.
     */
    val fingerprints: List<String>
        get() =
            evidence
                .filter {
                    it.type ==
                            SignatureTamperEvidenceType.CERTIFICATE_FINGERPRINT
                }
                .mapNotNull {
                    it.value
                }

    /**
     * Returns the strongest evidence severity.
     */
    val highestSeverity:
            SignatureTamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: SignatureTamperSeverity.INFO

    private fun severityWeight(
        severity: SignatureTamperSeverity
    ): Int {

        return when (severity) {

            SignatureTamperSeverity.INFO -> 0
            SignatureTamperSeverity.LOW -> 1
            SignatureTamperSeverity.MEDIUM -> 2
            SignatureTamperSeverity.HIGH -> 3
            SignatureTamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Signature-integrity state.
 */
enum class SignatureTamperStatus {

    /**
     * Current signing identity matches the trusted configuration.
     */
    SIGNATURE_VALID,

    /**
     * Current signing identity does not match trusted configuration.
     */
    SIGNATURE_TAMPER_DETECTED,

    /**
     * Suspicious certificate information exists.
     */
    SUSPICIOUS,

    /**
     * Trusted signing configuration has not been supplied.
     */
    TRUST_CONFIGURATION_MISSING,

    /**
     * Signature assessment could not be fully completed.
     */
    CHECK_INCOMPLETE
}

/**
 * Individual signing-integrity evidence.
 */
data class SignatureTamperEvidence(

    /**
     * Evidence category.
     */
    val type: SignatureTamperEvidenceType,

    /**
     * Source of evidence.
     */
    val source: String,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Certificate index when applicable.
     */
    val certificateIndex: Int? = null,

    /**
     * Observed value.
     */
    val value: String? = null,

    /**
     * Expected trusted value.
     */
    val expectedValue: String? = null,

    /**
     * Security severity.
     */
    val severity: SignatureTamperSeverity,

    /**
     * Confidence in the observation.
     */
    val confidence: Double
)

/**
 * Signature-integrity evidence categories.
 */
enum class SignatureTamperEvidenceType {

    /**
     * SHA-256 certificate fingerprint.
     */
    CERTIFICATE_FINGERPRINT,

    /**
     * At least one trusted certificate matched.
     */
    CERTIFICATE_MATCH,

    /**
     * No trusted certificate matched.
     */
    CERTIFICATE_MISMATCH,

    /**
     * Additional unexpected certificate observed.
     */
    UNEXPECTED_CERTIFICATE,

    /**
     * Number of certificates observed.
     */
    CERTIFICATE_COUNT,

    /**
     * Signing certificate information unavailable.
     */
    CERTIFICATE_UNAVAILABLE,

    /**
     * Certificate retrieval failed.
     */
    CERTIFICATE_READ_FAILED,

    /**
     * Signing history is available.
     */
    SIGNING_HISTORY_AVAILABLE,

    /**
     * No trusted certificate configuration supplied.
     */
    TRUSTED_CERTIFICATE_NOT_CONFIGURED
}

/**
 * Severity of signature-integrity evidence.
 */
enum class SignatureTamperSeverity {

    /**
     * Informational observation.
     */
    INFO,

    /**
     * Weak signal.
     */
    LOW,

    /**
     * Moderate signal.
     */
    MEDIUM,

    /**
     * Strong signal.
     */
    HIGH,

    /**
     * Critical signing-identity mismatch.
     */
    CRITICAL
}
