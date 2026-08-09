package com.sentrix.security.antitamper

import android.content.Context
import java.security.MessageDigest

/**
 * AntiTamperManager
 *
 * Central coordinator for SentriX application anti-tampering checks.
 *
 * Responsibilities:
 * - Coordinate application integrity checks.
 * - Coordinate signature/certificate checks.
 * - Coordinate APK/package integrity checks.
 * - Coordinate suspicious runtime/environment checks.
 * - Aggregate tamper evidence.
 * - Produce an overall anti-tamper assessment.
 *
 * This manager intentionally does NOT:
 * - modify the application
 * - terminate the application
 * - perform destructive countermeasures
 * - make assumptions from a single indicator
 *
 * Architecture:
 *
 * AntiTamperManager
 *        |
 *        +-- SignatureChecker
 *        +-- PackageIntegrityChecker
 *        +-- ApkIntegrityChecker
 *        +-- RuntimeTamperChecker
 *        +-- DebuggerTamperChecker
 *        +-- HookDetectionChecker
 *        |
 *        +-- AntiTamperValidator
 *        |
 *        +-- AntiTamperResult
 *
 * IMPORTANT:
 *
 * Anti-tamper detection is heuristic and should be combined with
 * server-side verification and Android platform attestation where
 * appropriate.
 */
class AntiTamperManager(
    private val context: Context
) {

    /**
     * Application package name.
     */
    private val packageName: String =
        context.packageName

    /**
     * Lazy access to the Android PackageManager.
     */
    private val packageManager =
        context.packageManager

    /**
     * Performs the complete anti-tamper assessment.
     *
     * This method is intentionally synchronous so that the manager
     * remains independent from Android Service/Coroutine lifecycle.
     *
     * Higher layers should execute it on an appropriate background
     * dispatcher.
     */
    fun performTamperCheck(): AntiTamperResult {

        val evidence = mutableListOf<AntiTamperEvidence>()

        var checksPerformed = 0
        var checksSuccessful = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * 1. Application package information
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            val packageInfo =
                packageManager.getPackageInfo(
                    packageName,
                    0
                )

            checksSuccessful++

            evidence += collectPackageEvidence(
                packageInfo
            )

        } catch (_: SecurityException) {

            checksPerformed++
            checksFailed++

            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.CHECK_FAILURE,
                source = "PackageManager",
                description =
                    "Package information access was denied.",
                severity = AntiTamperSeverity.MEDIUM,
                confidence = 0.50
            )

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.CHECK_FAILURE,
                source = "PackageManager",
                description =
                    "Package information could not be retrieved.",
                severity = AntiTamperSeverity.MEDIUM,
                confidence = 0.50
            )
        }

        /**
         * ---------------------------------------------------------
         * 2. Application signature/certificate information
         * ---------------------------------------------------------
         *
         * Signature extraction is kept as evidence collection here.
         * A dedicated AntiTamperSignatureChecker can later perform
         * the authoritative certificate comparison.
         */
        try {

            checksPerformed++

            val signatureEvidence =
                collectSignatureEvidence()

            evidence += signatureEvidence

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.CHECK_FAILURE,
                source = "Signature",
                description =
                    "Application signature information could not be inspected.",
                severity = AntiTamperSeverity.MEDIUM,
                confidence = 0.50
            )
        }

        /**
         * ---------------------------------------------------------
         * 3. Application source path
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            val applicationInfo =
                context.applicationInfo

            val sourceDir =
                applicationInfo.sourceDir

            if (sourceDir.isNullOrBlank()) {

                evidence += AntiTamperEvidence(
                    type = AntiTamperEvidenceType.APPLICATION_SOURCE,
                    source = "ApplicationInfo.sourceDir",
                    description =
                        "Application source path is unavailable.",
                    severity = AntiTamperSeverity.MEDIUM,
                    confidence = 0.60
                )

            } else {

                evidence += AntiTamperEvidence(
                    type = AntiTamperEvidenceType.APPLICATION_SOURCE,
                    source = "ApplicationInfo.sourceDir",
                    description =
                        "Application source path was successfully identified.",
                    severity = AntiTamperSeverity.INFO,
                    confidence = 1.0,
                    value = sourceDir
                )
            }

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.CHECK_FAILURE,
                source = "ApplicationSource",
                description =
                    "Application source information could not be inspected.",
                severity = AntiTamperSeverity.MEDIUM,
                confidence = 0.50
            )
        }

        /**
         * ---------------------------------------------------------
         * 4. Debuggable application check
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            val applicationInfo =
                context.applicationInfo

            val isDebuggable =
                (applicationInfo.flags and
                        android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

            if (isDebuggable) {

                evidence += AntiTamperEvidence(
                    type = AntiTamperEvidenceType.DEBUGGABLE_BUILD,
                    source = "ApplicationInfo.flags",
                    description =
                        "The installed application is marked as debuggable.",
                    severity = AntiTamperSeverity.MEDIUM,
                    confidence = 1.0,
                    value = "debuggable=true"
                )

            } else {

                evidence += AntiTamperEvidence(
                    type = AntiTamperEvidenceType.DEBUGGABLE_BUILD,
                    source = "ApplicationInfo.flags",
                    description =
                        "The installed application is not marked as debuggable.",
                    severity = AntiTamperSeverity.INFO,
                    confidence = 1.0,
                    value = "debuggable=false"
                )
            }

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.CHECK_FAILURE,
                source = "ApplicationFlags",
                description =
                    "Application debug configuration could not be inspected.",
                severity = AntiTamperSeverity.LOW,
                confidence = 0.50
            )
        }

        /**
         * ---------------------------------------------------------
         * 5. Package installation/source information
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            val applicationInfo =
                context.applicationInfo

            val sourceDir =
                applicationInfo.sourceDir

            val baseName =
                sourceDir.substringAfterLast('/')

            /**
             * This is contextual evidence only.
             *
             * The existence of an APK in a particular path does not
             * prove tampering.
             */
            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.PACKAGE_LOCATION,
                source = "ApplicationInfo.sourceDir",
                description =
                    "Application package location was identified.",
                severity = AntiTamperSeverity.INFO,
                confidence = 1.0,
                value = baseName
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.CHECK_FAILURE,
                source = "PackageLocation",
                description =
                    "Application package location could not be inspected.",
                severity = AntiTamperSeverity.LOW,
                confidence = 0.50
            )
        }

        /**
         * ---------------------------------------------------------
         * Calculate overall assessment
         * ---------------------------------------------------------
         */
        val riskScore =
            calculateRiskScore(evidence)

        val status =
            determineStatus(
                evidence = evidence,
                riskScore = riskScore,
                checksFailed = checksFailed
            )

        val confidence =
            calculateConfidence(
                evidence = evidence,
                checksPerformed = checksPerformed,
                checksFailed = checksFailed
            )

        return AntiTamperResult(
            status = status,
            riskScore = riskScore,
            confidence = confidence,
            evidence = evidence,
            checkSummary = AntiTamperCheckSummary(
                checksPerformed = checksPerformed,
                checksSuccessful = checksSuccessful,
                checksFailed = checksFailed
            ),
            packageName = packageName,
            detectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Collects package metadata as anti-tamper evidence.
     */
    private fun collectPackageEvidence(
        packageInfo: android.content.pm.PackageInfo
    ): List<AntiTamperEvidence> {

        val evidence =
            mutableListOf<AntiTamperEvidence>()

        evidence += AntiTamperEvidence(
            type = AntiTamperEvidenceType.PACKAGE_NAME,
            source = "PackageInfo.packageName",
            description =
                "Installed package identifier.",
            severity = AntiTamperSeverity.INFO,
            confidence = 1.0,
            value = packageInfo.packageName
        )

        evidence += AntiTamperEvidence(
            type = AntiTamperEvidenceType.VERSION_NAME,
            source = "PackageInfo.versionName",
            description =
                "Installed application version.",
            severity = AntiTamperSeverity.INFO,
            confidence = 1.0,
            value = packageInfo.versionName
        )

        return evidence
    }

    /**
     * Collects certificate/signature-related metadata.
     *
     * This implementation intentionally records certificate digest
     * information rather than trusting package metadata alone.
     */
    @Suppress("DEPRECATION")
    private fun collectSignatureEvidence():
            List<AntiTamperEvidence> {

        val evidence =
            mutableListOf<AntiTamperEvidence>()

        try {

            val packageInfo =
                if (
                    android.os.Build.VERSION.SDK_INT >=
                    android.os.Build.VERSION_CODES.P
                ) {

                    packageManager.getPackageInfo(
                        packageName,
                        android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
                    )

                } else {

                    packageManager.getPackageInfo(
                        packageName,
                        android.content.pm.PackageManager.GET_SIGNATURES
                    )
                }

            if (
                android.os.Build.VERSION.SDK_INT >=
                android.os.Build.VERSION_CODES.P
            ) {

                val signingInfo =
                    packageInfo.signingInfo

                val signatures =
                    if (
                        signingInfo.hasMultipleSigners()
                    ) {
                        signingInfo.apkContentsSigners
                    } else {
                        signingInfo.signingCertificateHistory
                    }

                signatures.forEach { signature ->

                    val digest =
                        sha256(
                            signature.toByteArray()
                        )

                    evidence += AntiTamperEvidence(
                        type = AntiTamperEvidenceType.SIGNATURE_DIGEST,
                        source = "SigningCertificate",
                        description =
                            "SHA-256 digest of the application signing certificate.",
                        severity = AntiTamperSeverity.INFO,
                        confidence = 1.0,
                        value = digest
                    )
                }

            } else {

                packageInfo.signatures?.forEach { signature ->

                    val digest =
                        sha256(
                            signature.toByteArray()
                        )

                    evidence += AntiTamperEvidence(
                        type = AntiTamperEvidenceType.SIGNATURE_DIGEST,
                        source = "Signature",
                        description =
                            "SHA-256 digest of the application signing certificate.",
                        severity = AntiTamperSeverity.INFO,
                        confidence = 1.0,
                        value = digest
                    )
                }
            }

        } catch (_: Exception) {

            evidence += AntiTamperEvidence(
                type = AntiTamperEvidenceType.CHECK_FAILURE,
                source = "SigningCertificate",
                description =
                    "Signing certificate information could not be collected.",
                severity = AntiTamperSeverity.MEDIUM,
                confidence = 0.50
            )
        }

        return evidence
    }

    /**
     * Calculates SHA-256 for certificate/signature bytes.
     */
    private fun sha256(
        data: ByteArray
    ): String {

        val digest =
            MessageDigest.getInstance("SHA-256")
                .digest(data)

        return digest.joinToString("") { byte ->
            "%02X".format(byte)
        }
    }

    /**
     * Calculates a normalized anti-tamper risk score.
     *
     * Score range:
     *
     * 0-29   = LOW
     * 30-59  = MEDIUM
     * 60-79  = HIGH
     * 80-100 = CRITICAL
     */
    private fun calculateRiskScore(
        evidence: List<AntiTamperEvidence>
    ): Int {

        var score = 0

        evidence.forEach { item ->

            score += when (item.severity) {

                AntiTamperSeverity.INFO ->
                    0

                AntiTamperSeverity.LOW ->
                    10

                AntiTamperSeverity.MEDIUM ->
                    20

                AntiTamperSeverity.HIGH ->
                    35

                AntiTamperSeverity.CRITICAL ->
                    50
            }
        }

        return score.coerceIn(
            0,
            100
        )
    }

    /**
     * Determines the overall anti-tamper state.
     *
     * A single medium-level indicator is deliberately insufficient
     * to declare application tampering.
     */
    private fun determineStatus(
        evidence: List<AntiTamperEvidence>,
        riskScore: Int,
        checksFailed: Int
    ): AntiTamperStatus {

        val criticalEvidence =
            evidence.any {
                it.severity == AntiTamperSeverity.CRITICAL
            }

        val highEvidenceCount =
            evidence.count {
                it.severity == AntiTamperSeverity.HIGH
            }

        return when {

            criticalEvidence ->
                AntiTamperStatus.TAMPER_DETECTED

            highEvidenceCount >= 2 ->
                AntiTamperStatus.HIGH_RISK

            riskScore >= 60 ->
                AntiTamperStatus.SUSPICIOUS

            checksFailed > 0 &&
                    evidence.isEmpty() ->
                AntiTamperStatus.CHECK_FAILED

            riskScore > 0 ->
                AntiTamperStatus.POTENTIAL_TAMPERING

            else ->
                AntiTamperStatus.NO_TAMPERING_DETECTED
        }
    }

    /**
     * Calculates confidence in the assessment.
     */
    private fun calculateConfidence(
        evidence: List<AntiTamperEvidence>,
        checksPerformed: Int,
        checksFailed: Int
    ): Double {

        if (checksPerformed <= 0) {
            return 0.0
        }

        val completionRatio =
            (
                (checksPerformed - checksFailed)
                    .toDouble() /
                    checksPerformed.toDouble()
            ).coerceIn(
                0.0,
                1.0
            )

        if (evidence.isEmpty()) {
            return completionRatio
        }

        val evidenceConfidence =
            evidence
                .map { it.confidence }
                .average()
                .coerceIn(
                    0.0,
                    1.0
                )

        return (
            completionRatio * 0.6 +
                    evidenceConfidence * 0.4
            ).coerceIn(
                0.0,
                1.0
            )
    }

    /**
     * Returns true when the current application appears
     * potentially tampered.
     */
    fun isTamperingDetected(): Boolean {

        return performTamperCheck()
            .status
            .isTamperingDetected()
    }

    /**
     * Returns only the risk score.
     */
    fun getRiskScore(): Int {

        return performTamperCheck()
            .riskScore
    }

    /**
     * Returns all collected tamper evidence.
     */
    fun collectEvidence(): List<AntiTamperEvidence> {

        return performTamperCheck()
            .evidence
    }
}

/**
 * Complete anti-tamper result.
 */
data class AntiTamperResult(

    /**
     * Final anti-tamper classification.
     */
    val status: AntiTamperStatus,

    /**
     * Normalized risk score from 0 to 100.
     */
    val riskScore: Int,

    /**
     * Confidence from 0.0 to 1.0.
     */
    val confidence: Double,

    /**
     * Evidence collected during the assessment.
     */
    val evidence: List<AntiTamperEvidence>,

    /**
     * Summary of performed checks.
     */
    val checkSummary: AntiTamperCheckSummary,

    /**
     * Application package name.
     */
    val packageName: String,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long
) {

    /**
     * Returns true when the result indicates potential tampering.
     */
    val isTamperingDetected: Boolean
        get() = status.isTamperingDetected()

    /**
     * Returns true when no tampering indicators were detected.
     */
    val isClean: Boolean
        get() =
            status ==
                    AntiTamperStatus.NO_TAMPERING_DETECTED

    /**
     * Returns the highest severity observed.
     */
    val highestSeverity: AntiTamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: AntiTamperSeverity.INFO

    /**
     * Returns evidence that requires attention.
     */
    fun getSignificantEvidence():
            List<AntiTamperEvidence> {

        return evidence.filter {
            it.severity == AntiTamperSeverity.MEDIUM ||
                    it.severity == AntiTamperSeverity.HIGH ||
                    it.severity == AntiTamperSeverity.CRITICAL
        }
    }

    /**
     * Converts severity to a sortable weight.
     */
    private fun severityWeight(
        severity: AntiTamperSeverity
    ): Int {

        return when (severity) {

            AntiTamperSeverity.INFO -> 0

            AntiTamperSeverity.LOW -> 1

            AntiTamperSeverity.MEDIUM -> 2

            AntiTamperSeverity.HIGH -> 3

            AntiTamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Anti-tamper status.
 */
enum class AntiTamperStatus {

    /**
     * No significant tampering evidence was observed.
     */
    NO_TAMPERING_DETECTED,

    /**
     * A weak or isolated indicator was observed.
     */
    POTENTIAL_TAMPERING,

    /**
     * Multiple suspicious indicators were observed.
     */
    SUSPICIOUS,

    /**
     * Strong evidence indicates possible application tampering.
     */
    HIGH_RISK,

    /**
     * Tampering was detected with high confidence.
     */
    TAMPER_DETECTED,

    /**
     * Required checks could not be completed.
     */
    CHECK_FAILED;

    /**
     * Returns whether this state represents a tampering concern.
     */
    fun isTamperingDetected(): Boolean {

        return this == POTENTIAL_TAMPERING ||
                this == SUSPICIOUS ||
                this == HIGH_RISK ||
                this == TAMPER_DETECTED
    }
}

/**
 * Individual anti-tamper evidence.
 */
data class AntiTamperEvidence(

    /**
     * Evidence category.
     */
    val type: AntiTamperEvidenceType,

    /**
     * Component that produced the evidence.
     */
    val source: String,

    /**
     * Human-readable description.
     */
    val description: String,

    /**
     * Optional observed value.
     *
     * Sensitive values should not be exposed to UI unnecessarily.
     */
    val value: String? = null,

    /**
     * Security severity.
     */
    val severity: AntiTamperSeverity,

    /**
     * Confidence in the observation.
     *
     * This is NOT the probability that tampering occurred.
     */
    val confidence: Double
)

/**
 * Anti-tamper evidence categories.
 */
enum class AntiTamperEvidenceType {

    /**
     * Package name evidence.
     */
    PACKAGE_NAME,

    /**
     * Application version evidence.
     */
    VERSION_NAME,

    /**
     * Application signing certificate digest.
     */
    SIGNATURE_DIGEST,

    /**
     * Application source location.
     */
    APPLICATION_SOURCE,

    /**
     * Package installation location.
     */
    PACKAGE_LOCATION,

    /**
     * Application marked as debuggable.
     */
    DEBUGGABLE_BUILD,

    /**
     * Check could not be completed.
     */
    CHECK_FAILURE
}

/**
 * Severity of anti-tamper evidence.
 */
enum class AntiTamperSeverity {

    /**
     * Informational evidence.
     */
    INFO,

    /**
     * Weak indication.
     */
    LOW,

    /**
     * Moderate indication.
     */
    MEDIUM,

    /**
     * Strong indication.
     */
    HIGH,

    /**
     * Critical indication.
     */
    CRITICAL
}

/**
 * Summary of anti-tamper checks.
 */
data class AntiTamperCheckSummary(

    /**
     * Number of checks attempted.
     */
    val checksPerformed: Int,

    /**
     * Number of successful checks.
     */
    val checksSuccessful: Int,

    /**
     * Number of failed checks.
     */
    val checksFailed: Int
) {

    /**
     * Percentage of successfully completed checks.
     */
    val completionPercentage: Int
        get() {

            if (checksPerformed <= 0) {
                return 0
            }

            return (
                checksSuccessful.toDouble() /
                        checksPerformed.toDouble() *
                        100.0
                ).toInt()
                .coerceIn(0, 100)
        }

    /**
     * True when all attempted checks completed successfully.
     */
    val allChecksSuccessful: Boolean
        get() =
            checksPerformed > 0 &&
                    checksFailed == 0
}
