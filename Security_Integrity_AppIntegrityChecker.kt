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
 * SentriX Application Integrity Checker
 *
 * Performs application-specific integrity verification for the installed
 * Android application.
 *
 * This component focuses exclusively on the application package itself.
 *
 * Responsibilities:
 *
 * - Verify the expected package name.
 * - Inspect installed application metadata.
 * - Verify APK existence and accessibility.
 * - Calculate the installed APK SHA-256 fingerprint.
 * - Inspect application signing certificates.
 * - Calculate signing certificate fingerprints.
 * - Detect unexpected version changes.
 * - Detect debuggable application builds.
 * - Detect basic application runtime integrity indicators.
 * - Compare the current application state with a trusted baseline.
 *
 * Relationship with other SentriX components:
 *
 *     AppIntegrityChecker
 *             │
 *             ├── Package identity
 *             ├── APK integrity
 *             ├── Signature integrity
 *             ├── Version integrity
 *             └── Runtime application state
 *                       │
 *                       ▼
 *                AppIntegrityReport
 *                       │
 *                       ▼
 *              IntegrityValidator
 *                       │
 *                       ▼
 *                IntegrityManager
 *
 * Important:
 *
 * A successful application-integrity check does NOT prove that the
 * Android device itself is secure.
 *
 * Device-level security is handled by other SentriX components such as:
 *
 * - Root detection
 * - Anti-tamper
 * - Device trust
 * - Malware detection
 * - Runtime protection
 * - Play Integrity integration
 */
class AppIntegrityChecker(
    context: Context
) {

    /**
     * Always use the application context so this component cannot
     * accidentally retain an Activity or other short-lived Context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Android package manager used for application inspection.
     */
    private val packageManager =
        applicationContext.packageManager

    /**
     * Expected package name for the running SentriX application.
     */
    private val expectedPackageName =
        applicationContext.packageName

    // =========================================================================
    // Main Application Integrity Check
    // =========================================================================

    /**
     * Performs a complete integrity inspection of the current application.
     */
    fun check():
            AppIntegrityReport {

        return check(
            expectedPackageName
        )
    }

    /**
     * Performs application integrity inspection against an expected
     * package name.
     */
    fun check(
        packageName: String
    ): AppIntegrityReport {

        val normalizedPackage =
            packageName.trim()

        if (
            normalizedPackage.isBlank()
        ) {

            return AppIntegrityReport.failure(
                packageName =
                    packageName,
                reason =
                    "Application package name is empty."
            )
        }

        val packageInfo =
            getPackageInfo(
                normalizedPackage
            )
                ?: return AppIntegrityReport.failure(
                    packageName =
                        normalizedPackage,
                    reason =
                        "Application package information could not be retrieved."
                )

        val packageIdentity =
            inspectPackageIdentity(
                packageInfo =
                    packageInfo,
                expectedPackageName =
                    normalizedPackage
            )

        val apkIntegrity =
            inspectApkIntegrity(
                packageInfo
            )

        val signatureIntegrity =
            inspectSignatureIntegrity(
                packageInfo
            )

        val versionIntegrity =
            inspectVersionIntegrity(
                packageInfo
            )

        val runtimeIntegrity =
            inspectRuntimeIntegrity(
                packageInfo
            )

        val findings =
            (
                packageIdentity.findings +
                        apkIntegrity.findings +
                        signatureIntegrity.findings +
                        versionIntegrity.findings +
                        runtimeIntegrity.findings
                ).distinct()

        val severity =
            findings
                .maxByOrNull {
                    it.severity.priority
                }
                ?.severity
                ?: IntegritySeverity.LOW

        return AppIntegrityReport(

            packageName =
                normalizedPackage,

            packageIdentity =
                packageIdentity,

            apkIntegrity =
                apkIntegrity,

            signatureIntegrity =
                signatureIntegrity,

            versionIntegrity =
                versionIntegrity,

            runtimeIntegrity =
                runtimeIntegrity,

            findings =
                findings,

            severity =
                severity,

            checkedAtMillis =
                System.currentTimeMillis()
        )
    }

    // =========================================================================
    // Package Identity
    // =========================================================================

    /**
     * Validates the Android package identity.
     */
    private fun inspectPackageIdentity(
        packageInfo: PackageInfo,
        expectedPackageName: String
    ): PackageIdentityResult {

        val findings =
            mutableListOf<IntegrityFinding>()

        val actualPackageName =
            packageInfo.packageName

        if (
            actualPackageName !=
            expectedPackageName
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .PACKAGE_FINGERPRINT_MISMATCH,

                    severity =
                        IntegritySeverity
                            .CRITICAL,

                    description =
                        "Installed package name does not match the expected " +
                                "SentriX application identity."
                )
        }

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

            return PackageIdentityResult(
                packageName =
                    actualPackageName,
                isExpectedPackage =
                    false,
                sourcePath =
                    null,
                findings =
                    findings
            )
        }

        val sourcePath =
            applicationInfo.sourceDir

        if (
            sourcePath.isNullOrBlank()
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
                        "Installed application APK path is unavailable."
                )
        }

        return PackageIdentityResult(

            packageName =
                actualPackageName,

            isExpectedPackage =
                actualPackageName ==
                        expectedPackageName,

            sourcePath =
                sourcePath,

            findings =
                findings
        )
    }

    // =========================================================================
    // APK Integrity
    // =========================================================================

    /**
     * Inspects the installed APK.
     */
    private fun inspectApkIntegrity(
        packageInfo: PackageInfo
    ): AppApkIntegrityResult {

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
                            .APK_METADATA_UNAVAILABLE,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "Application information is unavailable."
                )

            return AppApkIntegrityResult(
                apkPath =
                    null,
                apkSize =
                    null,
                apkSha256 =
                    null,
                exists =
                    false,
                readable =
                    false,
                findings =
                    findings
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
                        "The installed APK path is unavailable."
                )

            return AppApkIntegrityResult(
                apkPath =
                    null,
                apkSize =
                    null,
                apkSha256 =
                    null,
                exists =
                    false,
                readable =
                    false,
                findings =
                    findings
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
                        "The installed application APK could not be found."
                )

            return AppApkIntegrityResult(
                apkPath =
                    apkPath,
                apkSize =
                    null,
                apkSha256 =
                    null,
                exists =
                    false,
                readable =
                    false,
                findings =
                    findings
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
                        "The application source path is not a regular file."
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
                        "The installed APK cannot be read."
                )
        }

        val hash =
            if (
                apkFile.isFile &&
                apkFile.canRead()
            ) {

                calculateSha256(
                    apkFile
                )

            } else {

                null
            }

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
                        "Unable to calculate the SHA-256 fingerprint " +
                                "of the installed APK."
                )
        }

        return AppApkIntegrityResult(

            apkPath =
                apkPath,

            apkSize =
                apkFile.length(),

            apkSha256 =
                hash,

            exists =
                apkFile.exists(),

            readable =
                apkFile.canRead(),

            findings =
                findings
        )
    }

    /**
     * Calculates a streaming SHA-256 hash.
     *
     * The complete APK is never loaded into memory.
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
            )
                .buffered()
                .use { input ->

                    val buffer =
                        ByteArray(
                            16 * 1024
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

            formatFingerprint(
                digest.digest()
            )

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
     * Inspects the application's signing identity.
     *
     * Android signing-key rotation is taken into account by reading
     * signingCertificateHistory where appropriate.
     */
    private fun inspectSignatureIntegrity(
        packageInfo: PackageInfo
    ): AppSignatureIntegrityResult {

        val findings =
            mutableListOf<IntegrityFinding>()

        val signatures =
            getApplicationSignatures(
                packageInfo
            )

        if (
            signatures.isEmpty()
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

            return AppSignatureIntegrityResult(
                fingerprints =
                    emptyList(),
                combinedFingerprint =
                    null,
                signatureCount =
                    0,
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
                .distinct()
                .sorted()

        val combinedFingerprint =
            sha256(
                fingerprints
                    .joinToString("|")
                    .toByteArray(
                        Charsets.UTF_8
                    )
            )

        return AppSignatureIntegrityResult(

            fingerprints =
                fingerprints,

            combinedFingerprint =
                combinedFingerprint,

            signatureCount =
                signatures.size,

            findings =
                findings
        )
    }

    /**
     * Retrieves application signing certificate bytes.
     */
    private fun getApplicationSignatures(
        packageInfo: PackageInfo
    ): List<ByteArray> {

        return try {

            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.P
            ) {

                val signingInfo =
                    packageInfo.signingInfo
                        ?: return emptyList()

                val signatures =
                    if (
                        signingInfo.hasMultipleSigners()
                    ) {

                        signingInfo.apkContentsSigners

                    } else {

                        signingInfo.signingCertificateHistory
                    }

                signatures
                    ?.map {
                        it.toByteArray()
                    }
                    ?: emptyList()

            } else {

                @Suppress("DEPRECATION")
                packageInfo.signatures
                    ?.map {
                        it.toByteArray()
                    }
                    ?: emptyList()
            }

        } catch (
            _: Exception
        ) {

            emptyList()
        }
    }

    /**
     * Returns signing certificate fingerprints for the application.
     */
    fun getSigningCertificateFingerprints():
            List<String> {

        val packageInfo =
            getPackageInfo(
                expectedPackageName
            )
                ?: return emptyList()

        return getApplicationSignatures(
            packageInfo
        )
            .map {
                sha256(
                    it
                )
            }
            .distinct()
            .sorted()
    }

    // =========================================================================
    // Version Integrity
    // =========================================================================

    /**
     * Inspects application version information.
     */
    private fun inspectVersionIntegrity(
        packageInfo: PackageInfo
    ): AppVersionIntegrityResult {

        val findings =
            mutableListOf<IntegrityFinding>()

        val versionCode =
            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.P
            ) {

                packageInfo.longVersionCode

            } else {

                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            }

        val versionName =
            packageInfo.versionName
                ?: ""

        if (
            versionCode < 0L
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .INSPECTION_FAILURE,

                    severity =
                        IntegritySeverity
                            .MEDIUM,

                    description =
                        "Application version code is invalid."
                )
        }

        if (
            versionName.isBlank()
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .INSPECTION_FAILURE,

                    severity =
                        IntegritySeverity
                            .LOW,

                    description =
                        "Application version name is unavailable."
                )
        }

        return AppVersionIntegrityResult(

            versionCode =
                versionCode,

            versionName =
                versionName,

            findings =
                findings
        )
    }

    // =========================================================================
    // Runtime Application Integrity
    // =========================================================================

    /**
     * Performs application-level runtime integrity checks.
     *
     * These are signals and should not independently be treated as proof
     * of device compromise.
     */
    private fun inspectRuntimeIntegrity(
        packageInfo: PackageInfo
    ): AppRuntimeIntegrityResult {

        val findings =
            mutableListOf<IntegrityFinding>()

        val indicators =
            mutableListOf<
                    AppRuntimeIntegrityIndicator
                    >()

        val applicationInfo =
            packageInfo.applicationInfo

        // ---------------------------------------------------------------------
        // Debuggable build
        // ---------------------------------------------------------------------

        if (
            applicationInfo != null &&
            applicationInfo.flags and
            ApplicationInfo.FLAG_DEBUGGABLE != 0
        ) {

            indicators +=
                AppRuntimeIntegrityIndicator(

                    type =
                        AppRuntimeIntegrityIndicatorType
                            .DEBUGGABLE_BUILD,

                    severity =
                        IntegritySeverity
                            .MEDIUM,

                    description =
                        "The installed application is marked as debuggable."
                )

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .DEBUGGABLE_APPLICATION,

                    severity =
                        IntegritySeverity
                            .MEDIUM,

                    description =
                        "The installed application is marked as debuggable."
                )
        }

        // ---------------------------------------------------------------------
        // Debugger connected
        // ---------------------------------------------------------------------

        if (
            Debug.isDebuggerConnected()
        ) {

            indicators +=
                AppRuntimeIntegrityIndicator(

                    type =
                        AppRuntimeIntegrityIndicatorType
                            .DEBUGGER_CONNECTED,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "A debugger is connected to the application process."
                )

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .DEBUGGER_CONNECTED,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "A debugger is connected to the application process."
                )
        }

        // ---------------------------------------------------------------------
        // Waiting for debugger
        // ---------------------------------------------------------------------

        if (
            Debug.waitingForDebugger()
        ) {

            indicators +=
                AppRuntimeIntegrityIndicator(

                    type =
                        AppRuntimeIntegrityIndicatorType
                            .WAITING_FOR_DEBUGGER,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "The application is waiting for a debugger."
                )

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .WAITING_FOR_DEBUGGER,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "The application is waiting for a debugger."
                )
        }

        return AppRuntimeIntegrityResult(

            indicators =
                indicators,

            findings =
                findings
        )
    }

    // =========================================================================
    // Baseline Comparison
    // =========================================================================

    /**
     * Compares an application integrity report with a trusted baseline.
     */
    fun compareWithBaseline(
        report: AppIntegrityReport,
        baseline: IntegrityBaseline
    ): AppIntegrityBaselineComparison {

        val findings =
            mutableListOf<IntegrityFinding>()

        // ---------------------------------------------------------------------
        // Package identity
        // ---------------------------------------------------------------------

        if (
            report.packageName !=
            baseline.packageName
        ) {

            findings +=
                IntegrityFinding(

                    type =
                        IntegrityFindingType
                            .PACKAGE_FINGERPRINT_MISMATCH,

                    severity =
                        IntegritySeverity
                            .CRITICAL,

                    description =
                        "Application package name does not match the trusted baseline."
                )
        }

        // ---------------------------------------------------------------------
        // APK fingerprint
        // ---------------------------------------------------------------------

        if (
            baseline.apkFingerprint != null
        ) {

            val currentApkFingerprint =
                report.apkIntegrity
                    .apkSha256

            if (
                currentApkFingerprint == null
            ) {

                findings +=
                    IntegrityFinding(

                        type =
                            IntegrityFindingType
                                .APK_HASH_FAILED,

                        severity =
                            IntegritySeverity
                                .CRITICAL,

                        description =
                            "Current APK fingerprint is unavailable."
                    )

            } else if (
                !constantTimeFingerprintEquals(
                    currentApkFingerprint,
                    baseline.apkFingerprint
                )
            ) {

                findings +=
                    IntegrityFinding(

                        type =
                            IntegrityFindingType
                                .APK_FINGERPRINT_MISMATCH,

                        severity =
                            IntegritySeverity
                                .CRITICAL,

                        description =
                            "Current APK fingerprint differs from the trusted baseline."
                    )
            }
        }

        // ---------------------------------------------------------------------
        // Signature fingerprint
        // ---------------------------------------------------------------------

        if (
            baseline.signatureFingerprint != null
        ) {

            val currentSignature =
                report.signatureIntegrity
                    .combinedFingerprint

            if (
                currentSignature == null
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
                            "Current signing fingerprint is unavailable."
                    )

            } else if (
                !constantTimeFingerprintEquals(
                    currentSignature,
                    baseline.signatureFingerprint
                )
            ) {

                findings +=
                    IntegrityFinding(

                        type =
                            IntegrityFindingType
                                .SIGNATURE_FINGERPRINT_MISMATCH,

                        severity =
                            IntegritySeverity
                                .CRITICAL,

                        description =
                            "Current signing fingerprint differs from the trusted baseline."
                    )
            }
        }

        return if (
            findings.isEmpty()
        ) {

            AppIntegrityBaselineComparison
                .Match

        } else {

            AppIntegrityBaselineComparison
                .Mismatch(
                    findings
                )
        }
    }

    // =========================================================================
    // Current Application State
    // =========================================================================

    /**
     * Returns the currently installed application's APK SHA-256.
     */
    fun getCurrentApkFingerprint():
            String? {

        val packageInfo =
            getPackageInfo(
                expectedPackageName
            )
                ?: return null

        val sourcePath =
            packageInfo
                .applicationInfo
                ?.sourceDir
                ?: return null

        return calculateSha256(
            File(
                sourcePath
            )
        )
    }

    /**
     * Returns the currently installed application version code.
     */
    fun getCurrentVersionCode(): Long? {

        val packageInfo =
            getPackageInfo(
                expectedPackageName
            )
                ?: return null

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

    /**
     * Returns the currently installed application version name.
     */
    fun getCurrentVersionName(): String? {

        return getPackageInfo(
            expectedPackageName
        )
            ?.versionName
    }

    /**
     * Determines whether the installed application is a debuggable build.
     */
    fun isDebuggableBuild(): Boolean {

        val applicationInfo =
            applicationContext.applicationInfo

        return applicationInfo.flags and
                ApplicationInfo.FLAG_DEBUGGABLE != 0
    }

    /**
     * Determines whether a debugger is currently connected.
     */
    fun isDebuggerConnected(): Boolean {

        return Debug.isDebuggerConnected()
    }

    /**
     * Determines whether the application is waiting for a debugger.
     */
    fun isWaitingForDebugger(): Boolean {

        return Debug.waitingForDebugger()
    }

    // =========================================================================
    // Hash Utilities
    // =========================================================================

    /**
     * Calculates SHA-256 for arbitrary byte data.
     */
    private fun sha256(
        data: ByteArray
    ): String {

        val digest =
            MessageDigest.getInstance(
                "SHA-256"
            )

        return formatFingerprint(
            digest.digest(
                data
            )
        )
    }

    /**
     * Formats a hash as:
     *
     * AA:BB:CC:DD...
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
     * Performs constant-time comparison of two fingerprints.
     */
    private fun constantTimeFingerprintEquals(
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

        var result =
            0

        for (
            index in
                firstNormalized.indices
        ) {

            result =
                result or
                        (
                            firstNormalized[index].code xor
                                    secondNormalized[index].code
                            )
        }

        return result == 0
    }

    /**
     * Normalizes a fingerprint for comparison.
     */
    private fun normalizeFingerprint(
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
            .uppercase()
    }

    // =========================================================================
    // Package Information
    // =========================================================================

    /**
     * Retrieves package information using the Android-version-appropriate API.
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

        } catch (
            _: Exception
        ) {

            null
        }
    }
}

// =============================================================================
// Application Integrity Models
// =============================================================================

/**
 * Complete application integrity report.
 */
data class AppIntegrityReport(

    /**
     * Android package name.
     */
    val packageName: String,

    /**
     * Package identity assessment.
     */
    val packageIdentity:
        PackageIdentityResult,

    /**
     * APK integrity assessment.
     */
    val apkIntegrity:
        AppApkIntegrityResult,

    /**
     * Signing identity assessment.
     */
    val signatureIntegrity:
        AppSignatureIntegrityResult,

    /**
     * Application version assessment.
     */
    val versionIntegrity:
        AppVersionIntegrityResult,

    /**
     * Runtime application integrity assessment.
     */
    val runtimeIntegrity:
        AppRuntimeIntegrityResult,

    /**
     * All findings generated by the checker.
     */
    val findings:
        List<IntegrityFinding>,

    /**
     * Highest severity detected.
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
         * Creates a failed application-integrity report.
         */
        fun failure(
            packageName: String,
            reason: String
        ): AppIntegrityReport {

            val finding =
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

            return AppIntegrityReport(

                packageName =
                    packageName,

                packageIdentity =
                    PackageIdentityResult(
                        packageName =
                            packageName,
                        isExpectedPackage =
                            false,
                        sourcePath =
                            null,
                        findings =
                            listOf(
                                finding
                            )
                    ),

                apkIntegrity =
                    AppApkIntegrityResult(
                        apkPath =
                            null,
                        apkSize =
                            null,
                        apkSha256 =
                            null,
                        exists =
                            false,
                        readable =
                            false,
                        findings =
                            listOf(
                                finding
                            )
                    ),

                signatureIntegrity =
                    AppSignatureIntegrityResult(
                        fingerprints =
                            emptyList(),
                        combinedFingerprint =
                            null,
                        signatureCount =
                            0,
                        findings =
                            listOf(
                                finding
                            )
                    ),

                versionIntegrity =
                    AppVersionIntegrityResult(
                        versionCode =
                            -1L,
                        versionName =
                            "",
                        findings =
                            listOf(
                                finding
                            )
                    ),

                runtimeIntegrity =
                    AppRuntimeIntegrityResult(
                        indicators =
                            emptyList(),
                        findings =
                            listOf(
                                finding
                            )
                    ),

                findings =
                    listOf(
                        finding
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
 * Package identity result.
 */
data class PackageIdentityResult(

    val packageName: String,

    val isExpectedPackage: Boolean,

    val sourcePath: String?,

    val findings:
        List<IntegrityFinding>
)

/**
 * APK integrity result.
 */
data class AppApkIntegrityResult(

    val apkPath: String?,

    val apkSize: Long?,

    val apkSha256: String?,

    val exists: Boolean,

    val readable: Boolean,

    val findings:
        List<IntegrityFinding>
)

/**
 * Signing certificate integrity result.
 */
data class AppSignatureIntegrityResult(

    val fingerprints:
        List<String>,

    val combinedFingerprint: String?,

    val signatureCount: Int,

    val findings:
        List<IntegrityFinding>
)

/**
 * Application version integrity result.
 */
data class AppVersionIntegrityResult(

    val versionCode: Long,

    val versionName: String,

    val findings:
        List<IntegrityFinding>
)

/**
 * Application runtime integrity result.
 */
data class AppRuntimeIntegrityResult(

    val indicators:
        List<AppRuntimeIntegrityIndicator>,

    val findings:
        List<IntegrityFinding>
)

/**
 * Runtime application integrity indicator.
 */
data class AppRuntimeIntegrityIndicator(

    val type:
        AppRuntimeIntegrityIndicatorType,

    val severity:
        IntegritySeverity,

    val description: String
)

/**
 * Application runtime integrity indicator categories.
 */
enum class AppRuntimeIntegrityIndicatorType {

    DEBUGGABLE_BUILD,

    DEBUGGER_CONNECTED,

    WAITING_FOR_DEBUGGER
}

/**
 * Result of comparing an application report against a trusted baseline.
 */
sealed class AppIntegrityBaselineComparison {

    /**
     * Current application matches the trusted baseline.
     */
    data object Match :
        AppIntegrityBaselineComparison()

    /**
     * Current application differs from the trusted baseline.
     */
    data class Mismatch(
        val findings:
            List<IntegrityFinding>
    ) : AppIntegrityBaselineComparison()

    /**
     * Baseline comparison could not be performed because the baseline
     * itself was unavailable.
     */
    data object BaselineMissing :
        AppIntegrityBaselineComparison()
}
