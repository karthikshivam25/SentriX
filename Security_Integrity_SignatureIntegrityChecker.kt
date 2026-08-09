package com.sentrix.security.integrity

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

/**
 * SentriX Signature Integrity Checker
 *
 * Performs cryptographic verification of Android application signing
 * certificates.
 *
 * Responsibilities:
 *
 * - Retrieve application signing certificates.
 * - Calculate certificate fingerprints.
 * - Support SHA-256 and SHA-512 fingerprints.
 * - Handle Android signing-key rotation.
 * - Detect multiple active signers.
 * - Compare current signing identity with trusted fingerprints.
 * - Validate certificate fingerprint formatting.
 * - Produce structured signature-integrity results.
 *
 * This class focuses ONLY on signing identity.
 *
 * It does NOT:
 *
 * - Calculate APK file hashes.
 * - Perform APK integrity checks.
 * - Perform root detection.
 * - Perform Play Integrity verification.
 * - Perform certificate pinning.
 * - Decide the final application security response.
 *
 * Architecture:
 *
 *       SignatureIntegrityChecker
 *                  │
 *        ┌─────────┼─────────┐
 *        ▼         ▼         ▼
 *    Signers    SHA-256   SHA-512
 *        │         │         │
 *        └─────────┼─────────┘
 *                  ▼
 *        SignatureIntegrityReport
 *                  │
 *                  ▼
 *          IntegrityValidator
 */
class SignatureIntegrityChecker(
    context: Context
) {

    /**
     * Application context prevents accidental retention of Activities.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Package manager used to retrieve PackageInfo and signing information.
     */
    private val packageManager =
        applicationContext.packageManager

    /**
     * Default package is the currently running SentriX application.
     */
    private val applicationPackageName =
        applicationContext.packageName

    // =========================================================================
    // Main Check
    // =========================================================================

    /**
     * Checks the signing identity of the current SentriX application.
     */
    fun check():
            SignatureIntegrityReport {

        return check(
            applicationPackageName
        )
    }

    /**
     * Checks the signing identity of a specified installed package.
     */
    fun check(
        packageName: String
    ): SignatureIntegrityReport {

        val normalizedPackage =
            packageName.trim()

        if (
            normalizedPackage.isBlank()
        ) {

            return SignatureIntegrityReport.failure(
                packageName =
                    packageName,
                reason =
                    "Package name must not be blank."
            )
        }

        val packageInfo =
            getPackageInfo(
                normalizedPackage
            )
                ?: return SignatureIntegrityReport.failure(
                    packageName =
                        normalizedPackage,
                    reason =
                        "Package information could not be retrieved."
                )

        val signingInfo =
            readSigningInfo(
                packageInfo
            )

        if (
            signingInfo.signatures.isEmpty()
        ) {

            return SignatureIntegrityReport.failure(
                packageName =
                    normalizedPackage,
                reason =
                    "No signing certificates could be retrieved."
            )
        }

        val certificates =
            signingInfo.signatures.mapIndexed {
                index,
                signature ->

                createCertificateInfo(
                    index =
                        index,
                    signature =
                        signature
                )
            }

        val activeFingerprints =
            certificates
                .map {
                    it.sha256Fingerprint
                }
                .distinct()
                .sorted()

        val historicalFingerprints =
            signingInfo.historicalSignatures
                .map {
                    createCertificateInfo(
                        index =
                            0,
                        signature =
                            it
                    )
                }
                .map {
                    it.sha256Fingerprint
                }
                .distinct()
                .sorted()

        val combinedFingerprint =
            createCombinedFingerprint(
                activeFingerprints
            )

        val findings =
            mutableListOf<SignatureIntegrityFinding>()

        if (
            signingInfo.hasMultipleSigners
        ) {

            findings +=
                SignatureIntegrityFinding(

                    type =
                        SignatureIntegrityFindingType
                            .MULTIPLE_ACTIVE_SIGNERS,

                    severity =
                        SignatureIntegritySeverity
                            .MEDIUM,

                    message =
                        "Application contains multiple active signing certificates."
                )
        }

        if (
            certificates.isEmpty()
        ) {

            findings +=
                SignatureIntegrityFinding(

                    type =
                        SignatureIntegrityFindingType
                            .SIGNATURE_CERTIFICATE_MISSING,

                    severity =
                        SignatureIntegritySeverity
                            .CRITICAL,

                    message =
                        "No active signing certificate was found."
                )
        }

        val severity =
            findings
                .maxByOrNull {
                    it.severity.priority
                }
                ?.severity
                ?: SignatureIntegritySeverity
                    .SAFE

        return SignatureIntegrityReport(

            packageName =
                normalizedPackage,

            certificates =
                certificates,

            activeSha256Fingerprints =
                activeFingerprints,

            activeSha512Fingerprints =
                certificates
                    .map {
                        it.sha512Fingerprint
                    }
                    .distinct()
                    .sorted(),

            historicalSha256Fingerprints =
                historicalFingerprints,

            hasMultipleSigners =
                signingInfo.hasMultipleSigners,

            signingHistoryAvailable =
                signingInfo.historicalSignatures
                    .isNotEmpty(),

            combinedSha256Fingerprint =
                combinedFingerprint,

            findings =
                findings,

            severity =
                severity,

            checkedAtMillis =
                System.currentTimeMillis()
        )
    }

    // =========================================================================
    // Package Information
    // =========================================================================

    /**
     * Retrieves PackageInfo using the Android-version-specific API.
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
                            PackageManager
                                .GET_SIGNING_CERTIFICATES
                                .toLong()
                        )
                )

            } else {

                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(
                    packageName,
                    PackageManager
                        .GET_SIGNING_CERTIFICATES
                )
            }

        } catch (
            _: PackageManager.NameNotFoundException
        ) {

            null

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Signing Information
    // =========================================================================

    /**
     * Reads Android signing information.
     *
     * Android 9+ exposes SigningInfo, which also allows us to account for
     * legitimate signing-key rotation.
     */
    private fun readSigningInfo(
        packageInfo: PackageInfo
    ): SigningInformation {

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.P
        ) {

            val signingInfo =
                packageInfo.signingInfo
                    ?: return SigningInformation.empty()

            val activeSignatures =
                if (
                    signingInfo.hasMultipleSigners()
                ) {

                    signingInfo.apkContentsSigners
                        ?.toList()
                        ?: emptyList()

                } else {

                    signingInfo.apkContentsSigners
                        ?.toList()
                        ?: emptyList()
                }

            val historicalSignatures =
                if (
                    signingInfo.hasMultipleSigners()
                ) {

                    emptyList()

                } else {

                    signingInfo
                        .signingCertificateHistory
                        ?.toList()
                        ?: emptyList()
                }

            return SigningInformation(

                signatures =
                    activeSignatures,

                historicalSignatures =
                    historicalSignatures,

                hasMultipleSigners =
                    signingInfo.hasMultipleSigners()
            )
        }

        /*
         * Android versions before API 28 expose PackageInfo.signatures.
         */
        @Suppress("DEPRECATION")
        val signatures =
            packageInfo.signatures
                ?.toList()
                ?: emptyList()

        return SigningInformation(

            signatures =
                signatures,

            historicalSignatures =
                emptyList(),

            hasMultipleSigners =
                signatures.size > 1
        )
    }

    // =========================================================================
    // Certificate Information
    // =========================================================================

    /**
     * Creates a structured certificate-information object.
     */
    private fun createCertificateInfo(
        index: Int,
        signature: Signature
    ): SignatureCertificateInfo {

        val certificateBytes =
            signature.toByteArray()

        return SignatureCertificateInfo(

            index =
                index,

            certificateSize =
                certificateBytes.size,

            sha256Fingerprint =
                calculateFingerprint(
                    data =
                        certificateBytes,
                    algorithm =
                        SignatureHashAlgorithm
                            .SHA_256
                ),

            sha512Fingerprint =
                calculateFingerprint(
                    data =
                        certificateBytes,
                    algorithm =
                        SignatureHashAlgorithm
                            .SHA_512
                )
        )
    }

    // =========================================================================
    // Fingerprint APIs
    // =========================================================================

    /**
     * Returns active SHA-256 signing fingerprints.
     */
    fun getSha256Fingerprints(
        packageName: String =
            applicationPackageName
    ): List<String> {

        return check(
            packageName
        )
            .activeSha256Fingerprints
    }

    /**
     * Returns active SHA-512 signing fingerprints.
     */
    fun getSha512Fingerprints(
        packageName: String =
            applicationPackageName
    ): List<String> {

        return check(
            packageName
        )
            .activeSha512Fingerprints
    }

    /**
     * Returns historical SHA-256 signing fingerprints.
     *
     * This is useful when the application has undergone legitimate
     * signing-key rotation.
     */
    fun getHistoricalSha256Fingerprints(
        packageName: String =
            applicationPackageName
    ): List<String> {

        return check(
            packageName
        )
            .historicalSha256Fingerprints
    }

    /**
     * Returns the combined SHA-256 fingerprint of active signers.
     */
    fun getCombinedSha256Fingerprint(
        packageName: String =
            applicationPackageName
    ): String? {

        return check(
            packageName
        )
            .combinedSha256Fingerprint
    }

    // =========================================================================
    // Trusted Fingerprint Validation
    // =========================================================================

    /**
     * Checks whether any currently active signer matches a trusted
     * SHA-256 fingerprint.
     */
    fun matchesTrustedSha256Fingerprint(
        packageName: String =
            applicationPackageName,
        trustedFingerprints:
            Collection<String>
    ): Boolean {

        if (
            trustedFingerprints.isEmpty()
        ) {

            return false
        }

        val current =
            getSha256Fingerprints(
                packageName
            )

        val trusted =
            trustedFingerprints
                .map {
                    normalizeFingerprint(
                        it
                    )
                }
                .filter {
                    it.isNotBlank()
                }
                .toSet()

        return current.any {
            fingerprint ->

            normalizeFingerprint(
                fingerprint
            ) in trusted
        }
    }

    /**
     * Checks whether the active signing identity matches the exact expected
     * combined fingerprint.
     */
    fun matchesCombinedFingerprint(
        packageName: String =
            applicationPackageName,
        expectedFingerprint: String
    ): Boolean {

        val actual =
            getCombinedSha256Fingerprint(
                packageName
            )
                ?: return false

        return secureEquals(
            actual,
            expectedFingerprint
        )
    }

    /**
     * Validates a signing fingerprint directly.
     */
    fun isValidSha256Fingerprint(
        fingerprint: String
    ): Boolean {

        return isValidFingerprint(
            fingerprint =
                fingerprint,
            expectedLength =
                64
        )
    }

    /**
     * Validates a SHA-512 fingerprint directly.
     */
    fun isValidSha512Fingerprint(
        fingerprint: String
    ): Boolean {

        return isValidFingerprint(
            fingerprint =
                fingerprint,
            expectedLength =
                128
        )
    }

    // =========================================================================
    // Signing-Key Rotation
    // =========================================================================

    /**
     * Determines whether a fingerprint belongs to the application's
     * signing history.
     *
     * This allows SentriX to distinguish an unknown signer from a legitimate
     * key-rotation scenario.
     */
    fun belongsToSigningHistory(
        fingerprint: String,
        packageName: String =
            applicationPackageName
    ): Boolean {

        val normalized =
            normalizeFingerprint(
                fingerprint
            )

        if (
            normalized.isBlank()
        ) {

            return false
        }

        val report =
            check(
                packageName
            )

        val active =
            report.activeSha256Fingerprints
                .map {
                    normalizeFingerprint(
                        it
                    )
                }

        val historical =
            report.historicalSha256Fingerprints
                .map {
                    normalizeFingerprint(
                        it
                    )
                }

        return normalized in active ||
                normalized in historical
    }

    /**
     * Determines whether the application currently uses a signer that is
     * different from a supplied historical fingerprint.
     */
    fun hasSigningKeyChanged(
        expectedFingerprint: String,
        packageName: String =
            applicationPackageName
    ): Boolean {

        val current =
            getSha256Fingerprints(
                packageName
            )

        val expected =
            normalizeFingerprint(
                expectedFingerprint
            )

        return current.none {
            secureEquals(
                it,
                expected
            )
        }
    }

    // =========================================================================
    // Certificate Count
    // =========================================================================

    /**
     * Returns the number of active signing certificates.
     */
    fun getActiveSignerCount(
        packageName: String =
            applicationPackageName
    ): Int {

        return check(
            packageName
        )
            .certificates
            .size
    }

    /**
     * Determines whether multiple active signers exist.
     */
    fun hasMultipleActiveSigners(
        packageName: String =
            applicationPackageName
    ): Boolean {

        return check(
            packageName
        )
            .hasMultipleSigners
    }

    // =========================================================================
    // Fingerprint Calculation
    // =========================================================================

    /**
     * Calculates a certificate fingerprint.
     */
    private fun calculateFingerprint(
        data: ByteArray,
        algorithm: SignatureHashAlgorithm
    ): String {

        val digest =
            MessageDigest.getInstance(
                algorithm.jcaName
            )

        return formatFingerprint(
            digest.digest(
                data
            )
        )
    }

    /**
     * Calculates SHA-256 fingerprint for arbitrary certificate bytes.
     */
    fun calculateSha256(
        certificateBytes: ByteArray
    ): String {

        return calculateFingerprint(
            data =
                certificateBytes,
            algorithm =
                SignatureHashAlgorithm
                    .SHA_256
        )
    }

    /**
     * Calculates SHA-512 fingerprint for arbitrary certificate bytes.
     */
    fun calculateSha512(
        certificateBytes: ByteArray
    ): String {

        return calculateFingerprint(
            data =
                certificateBytes,
            algorithm =
                SignatureHashAlgorithm
                    .SHA_512
        )
    }

    /**
     * Formats fingerprint bytes using colon-separated hexadecimal notation.
     */
    private fun formatFingerprint(
        bytes: ByteArray
    ): String {

        return bytes.joinToString(":") {
            "%02X".format(
                it.toInt() and 0xFF
            )
        }
    }

    /**
     * Creates a deterministic combined fingerprint for multiple active
     * signing certificates.
     *
     * Sorting ensures certificate ordering does not alter the result.
     */
    private fun createCombinedFingerprint(
        fingerprints: List<String>
    ): String? {

        if (
            fingerprints.isEmpty()
        ) {

            return null
        }

        val material =
            fingerprints
                .map {
                    normalizeFingerprint(
                        it
                    )
                }
                .sorted()
                .joinToString("|")

        return calculateSha256(
            material.toByteArray(
                Charsets.UTF_8
            )
        )
    }

    // =========================================================================
    // Fingerprint Utilities
    // =========================================================================

    /**
     * Normalizes colon-separated, hyphen-separated, or plain hexadecimal
     * fingerprints.
     */
    fun normalizeFingerprint(
        fingerprint: String
    ): String {

        return fingerprint
            .trim()
            .replace(
                ":",
                ""
            )
            .replace(
                "-",
                ""
            )
            .replace(
                " ",
                ""
            )
            .uppercase()
    }

    /**
     * Validates a hexadecimal fingerprint length.
     */
    private fun isValidFingerprint(
        fingerprint: String,
        expectedLength: Int
    ): Boolean {

        val normalized =
            normalizeFingerprint(
                fingerprint
            )

        if (
            normalized.length !=
            expectedLength
        ) {

            return false
        }

        return normalized.all {
            it in '0'..'9' ||
                    it in 'A'..'F'
        }
    }

    /**
     * Performs constant-time fingerprint comparison.
     */
    private fun secureEquals(
        first: String,
        second: String
    ): Boolean {

        val firstNormalized =
            normalizeFingerprint(
                first
            )

        val secondNormalized =
            normalizeFingerprint(
                second
            )

        if (
            firstNormalized.length !=
            secondNormalized.length
        ) {

            return false
        }

        var difference =
            0

        for (
            index in
                firstNormalized.indices
        ) {

            difference =
                difference or
                        (
                            firstNormalized[index].code xor
                                    secondNormalized[index].code
                            )
        }

        return difference == 0
    }

    // =========================================================================
    // Report Creation
    // =========================================================================

    /**
     * Creates a failed signature-integrity report.
     */
    private fun createFailureReport(
        packageName: String,
        reason: String
    ): SignatureIntegrityReport {

        return SignatureIntegrityReport.failure(
            packageName =
                packageName,
            reason =
                reason
        )
    }
}

// =============================================================================
// Internal Signing Information
// =============================================================================

/**
 * Internal representation of Android signing information.
 */
private data class SigningInformation(

    val signatures:
        List<Signature>,

    val historicalSignatures:
        List<Signature>,

    val hasMultipleSigners: Boolean
) {

    companion object {

        fun empty():
                SigningInformation {

            return SigningInformation(

                signatures =
                    emptyList(),

                historicalSignatures =
                    emptyList(),

                hasMultipleSigners =
                    false
            )
        }
    }
}

// =============================================================================
// Main Report
// =============================================================================

/**
 * Complete signature-integrity report.
 */
data class SignatureIntegrityReport(

    /**
     * Inspected Android package.
     */
    val packageName: String,

    /**
     * Active signing certificates.
     */
    val certificates:
        List<SignatureCertificateInfo>,

    /**
     * Active SHA-256 certificate fingerprints.
     */
    val activeSha256Fingerprints:
        List<String>,

    /**
     * Active SHA-512 certificate fingerprints.
     */
    val activeSha512Fingerprints:
        List<String>,

    /**
     * Previous signing certificates exposed through Android signing history.
     */
    val historicalSha256Fingerprints:
        List<String>,

    /**
     * Whether multiple active signers are present.
     */
    val hasMultipleSigners: Boolean,

    /**
     * Whether Android exposed signing history.
     */
    val signingHistoryAvailable: Boolean,

    /**
     * Deterministic combined fingerprint for all active signers.
     */
    val combinedSha256Fingerprint: String?,

    /**
     * Security findings generated during inspection.
     */
    val findings:
        List<SignatureIntegrityFinding>,

    /**
     * Highest detected severity.
     */
    val severity:
        SignatureIntegritySeverity,

    /**
     * Inspection timestamp.
     */
    val checkedAtMillis: Long
) {

    companion object {

        /**
         * Creates a failed signature-integrity report.
         */
        fun failure(
            packageName: String,
            reason: String
        ): SignatureIntegrityReport {

            val finding =
                SignatureIntegrityFinding(

                    type =
                        SignatureIntegrityFindingType
                            .SIGNATURE_INSPECTION_FAILED,

                    severity =
                        SignatureIntegritySeverity
                            .CRITICAL,

                    message =
                        reason
                )

            return SignatureIntegrityReport(

                packageName =
                    packageName,

                certificates =
                    emptyList(),

                activeSha256Fingerprints =
                    emptyList(),

                activeSha512Fingerprints =
                    emptyList(),

                historicalSha256Fingerprints =
                    emptyList(),

                hasMultipleSigners =
                    false,

                signingHistoryAvailable =
                    false,

                combinedSha256Fingerprint =
                    null,

                findings =
                    listOf(
                        finding
                    ),

                severity =
                    SignatureIntegritySeverity
                        .CRITICAL,

                checkedAtMillis =
                    System.currentTimeMillis()
            )
        }
    }
}

// =============================================================================
// Certificate Information
// =============================================================================

/**
 * Information about one application signing certificate.
 */
data class SignatureCertificateInfo(

    val index: Int,

    val certificateSize: Int,

    val sha256Fingerprint: String,

    val sha512Fingerprint: String
)

// =============================================================================
// Hash Algorithms
// =============================================================================

/**
 * Supported certificate fingerprint algorithms.
 */
enum class SignatureHashAlgorithm(
    val jcaName: String
) {

    SHA_256(
        jcaName =
            "SHA-256"
    ),

    SHA_512(
        jcaName =
            "SHA-512"
    )
}

// =============================================================================
// Severity
// =============================================================================

/**
 * Signature-integrity severity.
 */
enum class SignatureIntegritySeverity(
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

// =============================================================================
// Findings
// =============================================================================

/**
 * Signature-integrity finding.
 */
data class SignatureIntegrityFinding(

    val type:
        SignatureIntegrityFindingType,

    val severity:
        SignatureIntegritySeverity,

    val message: String
)

/**
 * Signature-integrity finding categories.
 */
enum class SignatureIntegrityFindingType {

    SIGNATURE_CERTIFICATE_MISSING,

    SIGNATURE_INSPECTION_FAILED,

    MULTIPLE_ACTIVE_SIGNERS
}
