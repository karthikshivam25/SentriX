package com.sentrix.security.integrity

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * SentriX Integrity Checker
 *
 * Performs low-level application integrity checks.
 *
 * Responsibilities:
 *
 * - Inspect installed application metadata.
 * - Calculate APK SHA-256 hashes.
 * - Calculate signing-certificate fingerprints.
 * - Detect package metadata changes.
 * - Compare current state against an expected baseline.
 * - Detect basic runtime integrity indicators.
 * - Produce individual integrity findings.
 *
 * This class is intentionally focused on CHECKING.
 *
 * IntegrityManager is responsible for:
 *
 * - Orchestration
 * - Policy
 * - Risk aggregation
 * - Security decisions
 * - Coordination with other SentriX security modules
 *
 * This class does NOT:
 *
 * - Perform root detection.
 * - Perform certificate trust validation.
 * - Perform certificate pinning.
 * - Replace Play Integrity.
 * - Replace Android Verified Boot.
 * - Guarantee that the device is uncompromised.
 *
 * Architecture:
 *
 *       IntegrityChecker
 *              │
 *       ┌──────┼──────────┐
 *       ▼      ▼          ▼
 *      APK   Signature   Runtime
 *      Hash   Hash       Checks
 *       │      │          │
 *       └──────┼──────────┘
 *              ▼
 *       Integrity Findings
 */
class IntegrityChecker(
    context: Context
) {

    /**
     * Application context is used so that this component never accidentally
     * retains an Activity or another short-lived Context.
     */
    private val applicationContext =
        context.applicationContext

    // =========================================================================
    // Main Check
    // =========================================================================

    /**
     * Performs a complete integrity inspection of the current application.
     */
    fun check():
            IntegrityCheckReport {

        return check(
            packageName =
                applicationContext.packageName
        )
    }

    /**
     * Performs an integrity inspection for a specific installed package.
     *
     * The package must be visible to the application according to the
     * application's Android package-visibility configuration.
     */
    fun check(
        packageName: String
    ): IntegrityCheckReport {

        val normalizedPackage =
            packageName.trim()

        if (
            normalizedPackage.isBlank()
        ) {

            return IntegrityCheckReport.failure(
                packageName = packageName,
                reason =
                    "Package name must not be blank."
            )
        }

        val packageInfo =
            getPackageInfo(
                normalizedPackage
            )
                ?: return IntegrityCheckReport.failure(
                    packageName =
                        normalizedPackage,
                    reason =
                        "Package information could not be retrieved."
                )

        val findings =
            mutableListOf<IntegrityFinding>()

        // ---------------------------------------------------------------------
        // Package metadata
        // ---------------------------------------------------------------------

        val packageMetadata =
            inspectPackageMetadata(
                packageInfo
            )

        findings +=
            packageMetadata.findings

        // ---------------------------------------------------------------------
        // APK integrity
        // ---------------------------------------------------------------------

        val apkInspection =
            inspectApk(
                packageInfo
            )

        findings +=
            apkInspection.findings

        // ---------------------------------------------------------------------
        // Signature integrity
        // ---------------------------------------------------------------------

        val signatureInspection =
            inspectSignatures(
                packageInfo
            )

        findings +=
            signatureInspection.findings

        // ---------------------------------------------------------------------
        // Runtime integrity
        // ---------------------------------------------------------------------

        val runtimeInspection =
            inspectRuntime()

        findings +=
            runtimeInspection.findings

        // ---------------------------------------------------------------------
        // Overall severity
        // ---------------------------------------------------------------------

        val severity =
            calculateSeverity(
                findings
            )

        return IntegrityCheckReport(

            packageName =
                normalizedPackage,

            packageFingerprint =
                createPackageFingerprint(
                    packageInfo
                ),

            apkFingerprint =
                apkInspection.sha256,

            signatureFingerprint =
                signatureInspection.combinedFingerprint,

            packageMetadata =
                packageMetadata.metadata,

            findings =
                findings.distinct(),

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
     * Retrieves PackageInfo using the appropriate Android API.
     */
    private fun getPackageInfo(
        packageName: String
    ): PackageInfo? {

        return try {

            val packageManager =
                applicationContext.packageManager

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

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Package Metadata Inspection
    // =========================================================================

    /**
     * Inspects application/package metadata for consistency.
     */
    private fun inspectPackageMetadata(
        packageInfo: PackageInfo
    ): PackageMetadataInspection {

        val findings =
            mutableListOf<IntegrityFinding>()

        val applicationInfo =
            packageInfo.applicationInfo

        if (
            applicationInfo == null
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .PACKAGE_METADATA_UNAVAILABLE,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Application metadata is unavailable."
                )

            return PackageMetadataInspection(
                metadata = null,
                findings = findings
            )
        }

        val packageName =
            packageInfo.packageName

        val versionCode =
            getVersionCode(
                packageInfo
            )

        val versionName =
            packageInfo.versionName
                ?: ""

        val sourcePath =
            applicationInfo.sourceDir
                ?: ""

        if (
            packageName.isBlank()
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .INVALID_PACKAGE_NAME,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Package name is empty."
                )
        }

        if (
            sourcePath.isBlank()
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .APK_PATH_UNAVAILABLE,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Installed APK source path is unavailable."
                )
        }

        if (
            applicationInfo.flags and
            ApplicationInfo.FLAG_DEBUGGABLE != 0
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .DEBUGGABLE_APPLICATION,

                    severity =
                        IntegritySeverity
                            .MEDIUM,

                    description =
                        "Application is marked as debuggable."
                )
        }

        val metadata =
            PackageIntegrityMetadata(

                packageName =
                    packageName,

                versionCode =
                    versionCode,

                versionName =
                    versionName,

                sourcePath =
                    sourcePath,

                targetSdk =
                    applicationInfo.targetSdkVersion,

                minSdk =
                    applicationInfo.minSdkVersion
            )

        return PackageMetadataInspection(
            metadata =
                metadata,
            findings =
                findings
        )
    }

    /**
     * Returns the version code using the appropriate Android API.
     */
    private fun getVersionCode(
        packageInfo: PackageInfo
    ): Long {

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.P
        ) {

            packageInfo.longVersionCode

        } else {

            @Suppress("DEPRECATION")
            packageInfo.versionCode.toLong()
        }
    }

    // =========================================================================
    // APK Integrity
    // =========================================================================

    /**
     * Inspects the installed APK.
     */
    private fun inspectApk(
        packageInfo: PackageInfo
    ): ApkIntegrityInspection {

        val findings =
            mutableListOf<IntegrityFinding>()

        val applicationInfo =
            packageInfo.applicationInfo

        if (
            applicationInfo == null
        ) {

            return ApkIntegrityInspection(
                sha256 = null,
                findings =
                    listOf(
                        IntegrityFinding(

                            type =
                                IntegrityFindingType
                                    .APK_METADATA_UNAVAILABLE,

                            severity =
                                IntegritySeverity
                                    .HIGH,

                            description =
                                "Application information is unavailable."
                        )
                    )
            )
        }

        val apkPath =
            applicationInfo.sourceDir

        if (
            apkPath.isNullOrBlank()
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .APK_PATH_UNAVAILABLE,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Installed APK path is unavailable."
                )

            return ApkIntegrityInspection(
                sha256 = null,
                findings = findings
            )
        }

        val apkFile =
            File(
                apkPath
            )

        if (
            !apkFile.exists()
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .APK_NOT_FOUND,

                    severity =
                        IntegritySeverity
                            .CRITICAL,

                    description =
                        "Installed APK file could not be found."
                )

            return ApkIntegrityInspection(
                sha256 = null,
                findings = findings
            )
        }

        if (
            !apkFile.isFile
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .APK_NOT_REGULAR_FILE,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Application source path does not reference a regular file."
                )

            return ApkIntegrityInspection(
                sha256 = null,
                findings = findings
            )
        }

        if (
            !apkFile.canRead()
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .APK_NOT_READABLE,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Installed APK cannot be read."
                )

            return ApkIntegrityInspection(
                sha256 = null,
                findings = findings
            )
        }

        val hash =
            calculateSha256(
                apkFile
            )

        if (
            hash == null
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .APK_HASH_FAILED,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "SHA-256 calculation for the installed APK failed."
                )
        }

        return ApkIntegrityInspection(
            sha256 =
                hash,
            findings =
                findings
        )
    }

    /**
     * Calculates SHA-256 for an APK/file.
     *
     * The file is processed in chunks to avoid loading a complete APK
     * into memory.
     */
    fun calculateSha256(
        file: File
    ): String? {

        if (
            !file.exists() ||
            !file.isFile ||
            !file.canRead()
        ) {

            return null
        }

        return try {

            val digest =
                MessageDigest.getInstance(
                    "SHA-256"
                )

            FileInputStream(
                file
            ).buffered().use { input ->

                val buffer =
                    ByteArray(
                        8192
                    )

                while (
                    true
                ) {

                    val count =
                        input.read(
                            buffer
                        )

                    if (
                        count <= 0
                    ) {

                        break
                    }

                    digest.update(
                        buffer,
                        0,
                        count
                    )
                }
            }

            digest.digest()
                .joinToString(":") {
                    "%02X".format(
                        it.toInt() and 0xFF
                    )
                }

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Signature Integrity
    // =========================================================================

    /**
     * Inspects application signing certificates.
     */
    private fun inspectSignatures(
        packageInfo: PackageInfo
    ): SignatureIntegrityInspection {

        val findings =
            mutableListOf<IntegrityFinding>()

        val signatures =
            getApplicationSignatures(
                packageInfo
            )

        if (
            signatures.isNullOrEmpty()
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .SIGNATURE_UNAVAILABLE,

                    severity =
                        IntegritySeverity
                            .CRITICAL,

                    description =
                        "No application signing certificate could be retrieved."
                )

            return SignatureIntegrityInspection(
                fingerprints =
                    emptyList(),
                combinedFingerprint =
                    null,
                findings =
                    findings
            )
        }

        val fingerprints =
            signatures
                .map {
                    sha256(
                        it
                    )
                }
                .sorted()

        /*
         * Multiple signatures are represented as a deterministic combined
         * fingerprint. This prevents ordering differences from producing
         * different integrity results.
         */
        val combined =
            sha256(
                fingerprints
                    .joinToString("|")
                    .toByteArray(
                        Charsets.UTF_8
                    )
            )

        return SignatureIntegrityInspection(

            fingerprints =
                fingerprints,

            combinedFingerprint =
                combined,

            findings =
                findings
        )
    }

    /**
     * Retrieves application signing certificates.
     */
    private fun getApplicationSignatures(
        packageInfo: PackageInfo
    ): List<ByteArray>? {

        return try {

            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.P
            ) {

                val signingInfo =
                    packageInfo.signingInfo
                        ?: return null

                val signatures =
                    if (
                        signingInfo.hasMultipleSigners()
                    ) {

                        signingInfo
                            .apkContentsSigners

                    } else {

                        /*
                         * The signing certificate history is useful for
                         * legitimate signing-key rotation.
                         */
                        signingInfo
                            .signingCertificateHistory
                    }

                signatures
                    ?.map {
                        it.toByteArray()
                    }

            } else {

                @Suppress("DEPRECATION")
                packageInfo.signatures
                    ?.map {
                        it.toByteArray()
                    }
            }

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Returns signing certificate fingerprints for a package.
     */
    fun getSignatureFingerprints(
        packageName: String =
            applicationContext.packageName
    ): List<String> {

        val packageInfo =
            getPackageInfo(
                packageName
            )
                ?: return emptyList()

        return getApplicationSignatures(
            packageInfo
        )
            ?.map {
                sha256(
                    it
                )
            }
            ?.distinct()
            ?: emptyList()
    }

    // =========================================================================
    // Runtime Integrity
    // =========================================================================

    /**
     * Performs lightweight runtime integrity checks.
     *
     * These checks are indicators only. They should not be interpreted as
     * definitive evidence that the device is compromised.
     */
    private fun inspectRuntime():
            RuntimeIntegrityInspection {

        val findings =
            mutableListOf<IntegrityFinding>()

        val indicators =
            mutableListOf<RuntimeIntegrityIndicator>()

        // ---------------------------------------------------------------------
        // Debugger
        // ---------------------------------------------------------------------

        if (
            Debug.isDebuggerConnected()
        ) {

            val indicator =
                RuntimeIntegrityIndicator(

                    type =
                        RuntimeIntegrityIndicatorType
                            .DEBUGGER_CONNECTED,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "A debugger is connected to the application process."
                )

            indicators +=
                indicator

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .DEBUGGER_CONNECTED,

                    severity =
                        indicator.severity,

                    description =
                        indicator.description
                )
        }

        // ---------------------------------------------------------------------
        // Waiting for debugger
        // ---------------------------------------------------------------------

        if (
            Debug.waitingForDebugger()
        ) {

            val indicator =
                RuntimeIntegrityIndicator(

                    type =
                        RuntimeIntegrityIndicatorType
                            .WAITING_FOR_DEBUGGER,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "The application is waiting for a debugger."
                )

            indicators +=
                indicator

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .WAITING_FOR_DEBUGGER,

                    severity =
                        indicator.severity,

                    description =
                        indicator.description
                )
        }

        // ---------------------------------------------------------------------
        // Debuggable flag
        // ---------------------------------------------------------------------

        val applicationInfo =
            applicationContext
                .applicationInfo

        if (
            applicationInfo.flags and
            ApplicationInfo.FLAG_DEBUGGABLE != 0
        ) {

            val indicator =
                RuntimeIntegrityIndicator(

                    type =
                        RuntimeIntegrityIndicatorType
                            .DEBUGGABLE_APPLICATION,

                    severity =
                        IntegritySeverity
                            .MEDIUM,

                    description =
                        "The application is marked as debuggable."
                )

            indicators +=
                indicator

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .DEBUGGABLE_APPLICATION,

                    severity =
                        indicator.severity,

                    description =
                        indicator.description
                )
        }

        // ---------------------------------------------------------------------
        // Emulator heuristic
        // ---------------------------------------------------------------------

        if (
            isLikelyEmulator()
        ) {

            val indicator =
                RuntimeIntegrityIndicator(

                    type =
                        RuntimeIntegrityIndicatorType
                            .LIKELY_EMULATOR,

                    severity =
                        IntegritySeverity
                            .LOW,

                    description =
                        "The runtime environment contains emulator-like characteristics."
                )

            indicators +=
                indicator

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .LIKELY_EMULATOR,

                    severity =
                        indicator.severity,

                    description =
                        indicator.description
                )
        }

        return RuntimeIntegrityInspection(
            indicators =
                indicators,
            findings =
                findings
        )
    }

    /**
     * Heuristic emulator detection.
     *
     * This deliberately produces an indicator rather than a definitive
     * compromise result because modern emulator environments can resemble
     * physical devices.
     */
    private fun isLikelyEmulator(): Boolean {

        val fingerprint =
            Build.FINGERPRINT.lowercase()

        val model =
            Build.MODEL.lowercase()

        val manufacturer =
            Build.MANUFACTURER.lowercase()

        val brand =
            Build.BRAND.lowercase()

        val product =
            Build.PRODUCT.lowercase()

        return fingerprint.contains(
            "generic"
        ) ||
                fingerprint.contains(
                    "emulator"
                ) ||
                fingerprint.contains(
                    "test-keys"
                ) ||
                model.contains(
                    "emulator"
                ) ||
                model.contains(
                    "android sdk"
                ) ||
                manufacturer.contains(
                    "genymotion"
                ) ||
                brand.startsWith(
                    "generic"
                ) ||
                product.contains(
                    "sdk"
                )
    }

    // =========================================================================
    // Baseline Comparison
    // =========================================================================

    /**
     * Compares a current report against a trusted baseline.
     */
    fun compareWithBaseline(
        report: IntegrityCheckReport,
        baseline: IntegrityBaseline
    ): IntegrityBaselineComparison {

        val violations =
            mutableListOf<IntegrityFinding>()

        // ---------------------------------------------------------------------
        // Package identity
        // ---------------------------------------------------------------------

        if (
            report.packageFingerprint !=
            baseline.packageFingerprint
        ) {

            violations +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .PACKAGE_FINGERPRINT_MISMATCH,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Installed package identity differs from the trusted baseline."
                )
        }

        // ---------------------------------------------------------------------
        // APK hash
        // ---------------------------------------------------------------------

        if (
            baseline.apkFingerprint != null &&
            report.apkFingerprint !=
            baseline.apkFingerprint
        ) {

            violations +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .APK_FINGERPRINT_MISMATCH,

                    severity =
                        IntegritySeverity
                            .CRITICAL,

                    description =
                        "Installed APK hash differs from the trusted baseline."
                )
        }

        // ---------------------------------------------------------------------
        // Signing certificate
        // ---------------------------------------------------------------------

        if (
            baseline.signatureFingerprint != null &&
            report.signatureFingerprint !=
            baseline.signatureFingerprint
        ) {

            violations +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .SIGNATURE_FINGERPRINT_MISMATCH,

                    severity =
                        IntegritySeverity
                            .CRITICAL,

                    description =
                        "Application signing identity differs from the trusted baseline."
                )
        }

        return if (
            violations.isEmpty()
        ) {

            IntegrityBaselineComparison
                .Match

        } else {

            IntegrityBaselineComparison
                .Mismatch(
                    violations
                )
        }
    }

    // =========================================================================
    // Package Fingerprint
    // =========================================================================

    /**
     * Creates a deterministic package fingerprint from application metadata.
     *
     * This is an application identity fingerprint and should not be confused
     * with the APK cryptographic hash.
     */
    fun createPackageFingerprint(
        packageInfo: PackageInfo
    ): String {

        val versionCode =
            getVersionCode(
                packageInfo
            )

        val material =
            buildString {

                append(
                    packageInfo.packageName
                )

                append("|")

                append(
                    versionCode
                )

                append("|")

                append(
                    packageInfo.versionName
                        ?: ""
                )

                append("|")

                append(
                    packageInfo.applicationInfo
                        ?.sourceDir
                        ?: ""
                )
            }

        return sha256(
            material.toByteArray(
                Charsets.UTF_8
            )
        )
    }

    // =========================================================================
    // Severity
    // =========================================================================

    /**
     * Calculates the highest severity represented by the findings.
     */
    private fun calculateSeverity(
        findings:
            List<IntegrityFinding>
    ): IntegritySeverity {

        return findings
            .maxByOrNull {
                it.severity.priority
            }
            ?.severity
            ?: IntegritySeverity
                .LOW
    }

    // =========================================================================
    // Hash Helpers
    // =========================================================================

    /**
     * Calculates SHA-256 over byte data.
     */
    private fun sha256(
        data: ByteArray
    ): String {

        val digest =
            MessageDigest.getInstance(
                "SHA-256"
            )

        return digest
            .digest(
                data
            )
            .joinToString(":") {
                "%02X".format(
                    it.toInt() and 0xFF
                )
            }
    }
}

// =============================================================================
// Data Models
// =============================================================================

/**
 * Complete result produced by IntegrityChecker.
 */
data class IntegrityCheckReport(

    val packageName: String,

    /**
     * Application/package identity fingerprint.
     */
    val packageFingerprint: String?,

    /**
     * SHA-256 fingerprint of the installed APK.
     */
    val apkFingerprint: String?,

    /**
     * Combined SHA-256 fingerprint of application signing certificates.
     */
    val signatureFingerprint: String?,

    /**
     * Package metadata snapshot.
     */
    val packageMetadata:
        PackageIntegrityMetadata?,

    /**
     * Individual integrity findings.
     */
    val findings:
        List<IntegrityFinding>,

    /**
     * Highest detected severity.
     */
    val severity:
        IntegritySeverity,

    /**
     * Time of inspection.
     */
    val checkedAtMillis: Long
) {

    companion object {

        /**
         * Creates a failed inspection report.
         */
        fun failure(
            packageName: String,
            reason: String
        ): IntegrityCheckReport {

            return IntegrityCheckReport(

                packageName =
                    packageName,

                packageFingerprint =
                    null,

                apkFingerprint =
                    null,

                signatureFingerprint =
                    null,

                packageMetadata =
                    null,

                findings =
                    listOf(
                        IntegrityFinding(

                            type =
                                IntegrityFindingType
                                    .INSPECTION_FAILURE,

                            severity =
                                IntegritySeverity
                                    .CRITICAL,

                            description =
                                reason
                        )
                    ),

                severity =
                    IntegritySeverity
                        .CRITICAL,

                checkedAtMillis =
                    System.currentTimeMillis()
            )
        }
    }
}

/**
 * Package metadata captured during integrity inspection.
 */
data class PackageIntegrityMetadata(

    val packageName: String,

    val versionCode: Long,

    val versionName: String,

    val sourcePath: String,

    val targetSdk: Int,

    val minSdk: Int
)

/**
 * Individual integrity finding.
 */
data class IntegrityFinding(

    val type:
        IntegrityFindingType,

    val severity:
        IntegritySeverity,

    val description: String
)

/**
 * Severity used by integrity findings.
 */
enum class IntegritySeverity(
    val priority: Int
) {

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
 * Integrity finding categories.
 */
enum class IntegrityFindingType {

    PACKAGE_METADATA_UNAVAILABLE,

    INVALID_PACKAGE_NAME,

    APK_PATH_UNAVAILABLE,

    APK_METADATA_UNAVAILABLE,

    APK_NOT_FOUND,

    APK_NOT_REGULAR_FILE,

    APK_NOT_READABLE,

    APK_HASH_FAILED,

    SIGNATURE_UNAVAILABLE,

    DEBUGGABLE_APPLICATION,

    DEBUGGER_CONNECTED,

    WAITING_FOR_DEBUGGER,

    LIKELY_EMULATOR,

    PACKAGE_FINGERPRINT_MISMATCH,

    APK_FINGERPRINT_MISMATCH,

    SIGNATURE_FINGERPRINT_MISMATCH,

    INSPECTION_FAILURE
}

/**
 * Runtime integrity indicator.
 *
 * These are signals and not definitive proof of compromise.
 */
data class RuntimeIntegrityIndicator(

    val type:
        RuntimeIntegrityIndicatorType,

    val severity:
        IntegritySeverity,

    val description: String
)

/**
 * Runtime integrity signal categories.
 */
enum class RuntimeIntegrityIndicatorType {

    DEBUGGER_CONNECTED,

    WAITING_FOR_DEBUGGER,

    DEBUGGABLE_APPLICATION,

    LIKELY_EMULATOR
}

/**
 * Internal APK inspection result.
 */
private data class ApkIntegrityInspection(

    val sha256: String?,

    val findings:
        List<IntegrityFinding>
)

/**
 * Internal signature inspection result.
 */
private data class SignatureIntegrityInspection(

    val fingerprints:
        List<String>,

    val combinedFingerprint: String?,

    val findings:
        List<IntegrityFinding>
)

/**
 * Internal package metadata inspection result.
 */
private data class PackageMetadataInspection(

    val metadata:
        PackageIntegrityMetadata?,

    val findings:
        List<IntegrityFinding>
)

/**
 * Internal runtime inspection result.
 */
private data class RuntimeIntegrityInspection(

    val indicators:
        List<RuntimeIntegrityIndicator>,

    val findings:
        List<IntegrityFinding>
)

/**
 * Trusted integrity baseline.
 *
 * This model is also compatible with the baseline concept used by
 * IntegrityManager.
 */
data class IntegrityBaseline(

    val packageName: String,

    val packageFingerprint: String,

    val signatureFingerprint: String?,

    val apkFingerprint: String?,

    val createdAtMillis: Long
)

/**
 * Result of comparing a current integrity report against a baseline.
 */
sealed class IntegrityBaselineComparison {

    /**
     * Current application matches the baseline.
     */
    data object Match :
        IntegrityBaselineComparison()

    /**
     * Current application differs from the baseline.
     */
    data class Mismatch(
        val findings:
            List<IntegrityFinding>
    ) : IntegrityBaselineComparison()

    /**
     * No baseline is available.
     */
    data object BaselineMissing :
        IntegrityBaselineComparison()

    /**
     * Current application could not be inspected.
     */
    data object UnableToInspect :
        IntegrityBaselineComparison()
}
