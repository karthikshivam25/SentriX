package com.sentrix.security.antitamper

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * AppTamperDetector
 *
 * Detects indicators that the installed SentriX application may
 * have been modified, repackaged, replaced, or installed in an
 * unexpected configuration.
 *
 * Responsibilities:
 *
 * - Validate the current application package identity.
 * - Inspect APK/source paths.
 * - Inspect application version information.
 * - Collect signing certificate fingerprints.
 * - Inspect application flags.
 * - Inspect APK file metadata.
 * - Compare current package information against trusted
 *   configuration when supplied.
 *
 * This class does NOT:
 *
 * - modify the application
 * - delete files
 * - terminate the process
 * - execute arbitrary shell commands
 * - perform final risk scoring
 * - make the final tampering verdict
 *
 * Architecture:
 *
 * AntiTamperManager
 *        ↓
 * AppTamperDetector
 *        ↓
 * AppTamperResult
 *        ↓
 * AntiTamperEvidenceCollector
 *        ↓
 * AntiTamperValidator
 */
class AppTamperDetector(
    private val context: Context,
    private val trustedConfiguration: AppTamperConfiguration =
        AppTamperConfiguration()
) {

    /**
     * Android package manager.
     */
    private val packageManager: PackageManager =
        context.packageManager

    /**
     * Package identifier of the running application.
     */
    private val currentPackageName: String =
        context.packageName

    /**
     * Application metadata.
     */
    private val applicationInfo: ApplicationInfo =
        context.applicationInfo

    /**
     * Performs the complete application-level tamper check.
     *
     * @return structured application tamper result.
     */
    fun detect(): AppTamperResult {

        val evidence =
            mutableListOf<AppTamperEvidence>()

        var checksPerformed = 0
        var checksSuccessful = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * 1. Package identity
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            checkPackageIdentity(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += failureEvidence(
                source = "PackageIdentity"
            )
        }

        /**
         * ---------------------------------------------------------
         * 2. Package metadata
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            val packageInfo =
                getCurrentPackageInfo()

            collectPackageMetadata(
                packageInfo = packageInfo,
                evidence = evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += failureEvidence(
                source = "PackageMetadata"
            )
        }

        /**
         * ---------------------------------------------------------
         * 3. Signing certificate
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectSigningCertificateEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += failureEvidence(
                source = "SigningCertificate"
            )
        }

        /**
         * ---------------------------------------------------------
         * 4. APK/source integrity metadata
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApkSourceEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += failureEvidence(
                source = "ApkSource"
            )
        }

        /**
         * ---------------------------------------------------------
         * 5. Application configuration
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApplicationFlagEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += failureEvidence(
                source = "ApplicationFlags"
            )
        }

        /**
         * ---------------------------------------------------------
         * 6. APK metadata
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApkMetadataEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += failureEvidence(
                source = "ApkMetadata"
            )
        }

        return AppTamperResult(
            packageName = currentPackageName,
            evidence = evidence,
            checksPerformed = checksPerformed,
            checksSuccessful = checksSuccessful,
            checksFailed = checksFailed,
            detectionCompleted = checksFailed == 0,
            detectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Checks whether the running package name matches the
     * trusted package identifier, when configured.
     */
    private fun checkPackageIdentity(
        evidence: MutableList<AppTamperEvidence>
    ) {

        val expectedPackage =
            trustedConfiguration.expectedPackageName

        if (expectedPackage.isNullOrBlank()) {

            evidence += AppTamperEvidence(
                type = AppTamperEvidenceType.PACKAGE_IDENTITY,
                source = "Context.packageName",
                description =
                    "Current application package identity was collected.",
                value = currentPackageName,
                severity = AppTamperSeverity.INFO,
                confidence = 1.0
            )

            return
        }

        val matches =
            currentPackageName == expectedPackage

        evidence += AppTamperEvidence(
            type =
                if (matches) {
                    AppTamperEvidenceType.PACKAGE_IDENTITY
                } else {
                    AppTamperEvidenceType.PACKAGE_IDENTITY_MISMATCH
                },
            source = "Context.packageName",
            description =
                if (matches) {
                    "Application package matches the trusted package identifier."
                } else {
                    "Application package differs from the trusted package identifier."
                },
            value = currentPackageName,
            expectedValue = expectedPackage,
            severity =
                if (matches) {
                    AppTamperSeverity.INFO
                } else {
                    AppTamperSeverity.CRITICAL
                },
            confidence = 1.0
        )
    }

    /**
     * Collects package version and installation metadata.
     */
    private fun collectPackageMetadata(
        packageInfo: PackageInfo,
        evidence: MutableList<AppTamperEvidence>
    ) {

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.VERSION_NAME,
            source = "PackageInfo.versionName",
            description =
                "Currently installed application version.",
            value = packageInfo.versionName,
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )

        val versionCode =
            getVersionCode(packageInfo)

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.VERSION_CODE,
            source = "PackageInfo.versionCode",
            description =
                "Currently installed application version code.",
            value = versionCode.toString(),
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Optional trusted-version comparison.
         */
        val expectedVersionCode =
            trustedConfiguration.expectedVersionCode

        if (expectedVersionCode != null) {

            val matches =
                versionCode == expectedVersionCode

            evidence += AppTamperEvidence(
                type =
                    if (matches) {
                        AppTamperEvidenceType.VERSION_MATCH
                    } else {
                        AppTamperEvidenceType.VERSION_MISMATCH
                    },
                source = "PackageInfo.longVersionCode",
                description =
                    if (matches) {
                        "Installed version matches the trusted version."
                    } else {
                        "Installed version differs from the trusted version."
                    },
                value = versionCode.toString(),
                expectedValue =
                    expectedVersionCode.toString(),
                severity =
                    if (matches) {
                        AppTamperSeverity.INFO
                    } else {
                        AppTamperSeverity.HIGH
                    },
                confidence = 1.0
            )
        }

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.FIRST_INSTALL_TIME,
            source = "PackageInfo.firstInstallTime",
            description =
                "Application first-install timestamp.",
            value =
                packageInfo.firstInstallTime.toString(),
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.LAST_UPDATE_TIME,
            source = "PackageInfo.lastUpdateTime",
            description =
                "Application last-update timestamp.",
            value =
                packageInfo.lastUpdateTime.toString(),
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Collects signing certificate SHA-256 fingerprints.
     *
     * When a trusted fingerprint is configured, the current
     * certificate is compared against it.
     */
    @Suppress("DEPRECATION")
    private fun collectSigningCertificateEvidence(
        evidence: MutableList<AppTamperEvidence>
    ) {

        val packageInfo =
            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.P
            ) {

                packageManager.getPackageInfo(
                    currentPackageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )

            } else {

                packageManager.getPackageInfo(
                    currentPackageName,
                    PackageManager.GET_SIGNATURES
                )
            }

        val fingerprints =
            mutableListOf<String>()

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.P
        ) {

            val signingInfo =
                packageInfo.signingInfo

            if (signingInfo == null) {

                evidence += AppTamperEvidence(
                    type = AppTamperEvidenceType.SIGNATURE_UNAVAILABLE,
                    source = "PackageInfo.signingInfo",
                    description =
                        "Application signing information is unavailable.",
                    severity = AppTamperSeverity.MEDIUM,
                    confidence = 0.60
                )

                return
            }

            val signatures =
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }

            signatures.forEach { signature ->

                fingerprints +=
                    calculateSha256(
                        signature.toByteArray()
                    )
            }

        } else {

            packageInfo.signatures
                ?.forEach { signature ->

                    fingerprints +=
                        calculateSha256(
                            signature.toByteArray()
                        )
                }
        }

        if (fingerprints.isEmpty()) {

            evidence += AppTamperEvidence(
                type = AppTamperEvidenceType.SIGNATURE_UNAVAILABLE,
                source = "SigningCertificate",
                description =
                    "No signing certificate could be obtained.",
                severity = AppTamperSeverity.MEDIUM,
                confidence = 0.60
            )

            return
        }

        fingerprints.forEach { fingerprint ->

            evidence += AppTamperEvidence(
                type = AppTamperEvidenceType.SIGNATURE_FINGERPRINT,
                source = "SigningCertificate",
                description =
                    "SHA-256 fingerprint of an application signing certificate.",
                value = fingerprint,
                severity = AppTamperSeverity.INFO,
                confidence = 1.0
            )
        }

        /**
         * Trusted certificate comparison.
         */
        val trustedFingerprints =
            trustedConfiguration
                .trustedCertificateSha256
                .map {
                    normalizeFingerprint(it)
                }
                .toSet()

        if (trustedFingerprints.isNotEmpty()) {

            val matched =
                fingerprints.any {
                    normalizeFingerprint(it) in
                            trustedFingerprints
                }

            evidence += AppTamperEvidence(
                type =
                    if (matched) {
                        AppTamperEvidenceType.SIGNATURE_MATCH
                    } else {
                        AppTamperEvidenceType.SIGNATURE_MISMATCH
                    },
                source = "TrustedCertificate",
                description =
                    if (matched) {
                        "Application signing certificate matches trusted configuration."
                    } else {
                        "Application signing certificate does not match trusted configuration."
                    },
                value =
                    fingerprints.joinToString(","),
                expectedValue =
                    trustedFingerprints.joinToString(","),
                severity =
                    if (matched) {
                        AppTamperSeverity.INFO
                    } else {
                        AppTamperSeverity.CRITICAL
                    },
                confidence = 1.0
            )
        }
    }

    /**
     * Collects APK source information.
     */
    private fun collectApkSourceEvidence(
        evidence: MutableList<AppTamperEvidence>
    ) {

        val sourceDir =
            applicationInfo.sourceDir

        if (sourceDir.isNullOrBlank()) {

            evidence += AppTamperEvidence(
                type = AppTamperEvidenceType.APK_SOURCE_UNAVAILABLE,
                source = "ApplicationInfo.sourceDir",
                description =
                    "The application APK source location is unavailable.",
                severity = AppTamperSeverity.HIGH,
                confidence = 0.70
            )

            return
        }

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.APK_SOURCE,
            source = "ApplicationInfo.sourceDir",
            description =
                "Application APK source location.",
            value = sourceDir,
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )

        val apkFile =
            File(sourceDir)

        if (!apkFile.exists()) {

            evidence += AppTamperEvidence(
                type = AppTamperEvidenceType.APK_NOT_FOUND,
                source = sourceDir,
                description =
                    "The application APK could not be found at the reported location.",
                severity = AppTamperSeverity.CRITICAL,
                confidence = 0.90
            )

            return
        }

        /**
         * APK writability is a strong environmental signal,
         * but not absolute proof of tampering.
         */
        try {

            if (apkFile.canWrite()) {

                evidence += AppTamperEvidence(
                    type = AppTamperEvidenceType.APK_WRITABLE,
                    source = sourceDir,
                    description =
                        "The installed APK file appears writable.",
                    value = "true",
                    severity = AppTamperSeverity.HIGH,
                    confidence = 0.80
                )
            }

        } catch (_: SecurityException) {

            evidence += AppTamperEvidence(
                type = AppTamperEvidenceType.APK_ACCESS_DENIED,
                source = sourceDir,
                description =
                    "Access to the installed APK was denied.",
                severity = AppTamperSeverity.LOW,
                confidence = 0.50
            )
        }
    }

    /**
     * Collects application flags relevant to integrity analysis.
     */
    private fun collectApplicationFlagEvidence(
        evidence: MutableList<AppTamperEvidence>
    ) {

        val isDebuggable =
            (
                applicationInfo.flags and
                        ApplicationInfo.FLAG_DEBUGGABLE
                ) != 0

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.DEBUGGABLE_APPLICATION,
            source = "ApplicationInfo.flags",
            description =
                if (isDebuggable) {
                    "Application is marked as debuggable."
                } else {
                    "Application is not marked as debuggable."
                },
            value = isDebuggable.toString(),
            severity =
                if (isDebuggable) {
                    AppTamperSeverity.MEDIUM
                } else {
                    AppTamperSeverity.INFO
                },
            confidence = 1.0
        )

        val isSystemApplication =
            (
                applicationInfo.flags and
                        ApplicationInfo.FLAG_SYSTEM
                ) != 0

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.SYSTEM_APPLICATION,
            source = "ApplicationInfo.flags",
            description =
                if (isSystemApplication) {
                    "Application is marked as a system application."
                } else {
                    "Application is not marked as a system application."
                },
            value = isSystemApplication.toString(),
            severity =
                if (isSystemApplication) {
                    AppTamperSeverity.LOW
                } else {
                    AppTamperSeverity.INFO
                },
            confidence = 1.0
        )

        val isUpdatedSystemApplication =
            (
                applicationInfo.flags and
                        ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                ) != 0

        evidence += AppTamperEvidence(
            type =
                AppTamperEvidenceType.UPDATED_SYSTEM_APPLICATION,
            source = "ApplicationInfo.flags",
            description =
                "Whether Android reports the application as an updated system application.",
            value =
                isUpdatedSystemApplication.toString(),
            severity =
                if (isUpdatedSystemApplication) {
                    AppTamperSeverity.LOW
                } else {
                    AppTamperSeverity.INFO
                },
            confidence = 1.0
        )
    }

    /**
     * Collects APK file metadata.
     *
     * Full content hashing belongs to AntiTamperApkChecker.
     */
    private fun collectApkMetadataEvidence(
        evidence: MutableList<AppTamperEvidence>
    ) {

        val sourceDir =
            applicationInfo.sourceDir
                ?: return

        val apkFile =
            File(sourceDir)

        if (!apkFile.exists()) {
            return
        }

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.APK_SIZE,
            source = sourceDir,
            description =
                "Installed APK file size.",
            value = apkFile.length().toString(),
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.APK_LAST_MODIFIED,
            source = sourceDir,
            description =
                "Installed APK last-modified timestamp.",
            value =
                apkFile.lastModified().toString(),
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )

        evidence += AppTamperEvidence(
            type = AppTamperEvidenceType.APK_READABLE,
            source = sourceDir,
            description =
                "Whether the installed APK can be read.",
            value =
                apkFile.canRead().toString(),
            severity = AppTamperSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Returns current PackageInfo using the appropriate API for
     * the Android version.
     */
    @Suppress("DEPRECATION")
    private fun getCurrentPackageInfo():
            PackageInfo {

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.TIRAMISU
        ) {

            packageManager.getPackageInfo(
                currentPackageName,
                PackageManager.PackageInfoFlags.of(0)
            )

        } else {

            packageManager.getPackageInfo(
                currentPackageName,
                0
            )
        }
    }

    /**
     * Returns the package version code across Android versions.
     */
    @Suppress("DEPRECATION")
    private fun getVersionCode(
        packageInfo: PackageInfo
    ): Long {

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.P
        ) {

            packageInfo.longVersionCode

        } else {

            packageInfo.versionCode.toLong()
        }
    }

    /**
     * Calculates SHA-256 digest.
     */
    private fun calculateSha256(
        value: ByteArray
    ): String {

        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(value)

        return digest.joinToString("") {
            "%02X".format(it)
        }
    }

    /**
     * Normalizes certificate fingerprints for comparison.
     */
    private fun normalizeFingerprint(
        fingerprint: String
    ): String {

        return fingerprint
            .replace(":", "")
            .replace(" ", "")
            .trim()
            .uppercase()
    }

    /**
     * Creates standardized failure evidence.
     */
    private fun failureEvidence(
        source: String
    ): AppTamperEvidence {

        return AppTamperEvidence(
            type = AppTamperEvidenceType.CHECK_FAILURE,
            source = source,
            description =
                "Application tamper check could not be completed.",
            severity = AppTamperSeverity.MEDIUM,
            confidence = 0.50
        )
    }

    /**
     * Returns true if a strong application-level tamper indicator
     * exists.
     */
    fun hasStrongEvidence(): Boolean {

        return detect()
            .evidence
            .any {
                it.severity == AppTamperSeverity.HIGH ||
                        it.severity == AppTamperSeverity.CRITICAL
            }
    }

    /**
     * Returns only significant application tamper evidence.
     */
    fun getSignificantEvidence():
            List<AppTamperEvidence> {

        return detect()
            .evidence
            .filter {
                it.severity == AppTamperSeverity.MEDIUM ||
                        it.severity == AppTamperSeverity.HIGH ||
                        it.severity == AppTamperSeverity.CRITICAL
            }
    }

    /**
     * Performs a direct package identity validation.
     */
    fun isPackageIdentityValid(): Boolean {

        val expected =
            trustedConfiguration.expectedPackageName
                ?: return true

        return currentPackageName == expected
    }

    /**
     * Returns the currently installed application package name.
     */
    fun getCurrentPackageName(): String {

        return currentPackageName
    }
}

/**
 * Trusted configuration used by AppTamperDetector.
 *
 * In production, these values should preferably come from a
 * protected build configuration or another trusted configuration
 * mechanism rather than user-editable preferences.
 */
data class AppTamperConfiguration(

    /**
     * Expected production package name.
     *
     * Example:
     *
     * com.sentrix
     */
    val expectedPackageName: String? = null,

    /**
     * Expected release version code.
     */
    val expectedVersionCode: Long? = null,

    /**
     * Trusted SHA-256 signing certificate fingerprints.
     *
     * Multiple fingerprints are supported for legitimate signing
     * key rotation scenarios.
     */
    val trustedCertificateSha256: Set<String> =
        emptySet()
)

/**
 * Complete result of application-level tamper detection.
 */
data class AppTamperResult(

    /**
     * Current package name.
     */
    val packageName: String,

    /**
     * Collected application tamper evidence.
     */
    val evidence: List<AppTamperEvidence>,

    /**
     * Number of checks performed.
     */
    val checksPerformed: Int,

    /**
     * Number of successfully completed checks.
     */
    val checksSuccessful: Int,

    /**
     * Number of failed checks.
     */
    val checksFailed: Int,

    /**
     * Whether all checks completed.
     */
    val detectionCompleted: Boolean,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long
) {

    /**
     * Whether significant evidence exists.
     */
    val hasEvidence: Boolean
        get() = evidence.any {
            it.severity != AppTamperSeverity.INFO
        }

    /**
     * Whether strong evidence exists.
     */
    val hasStrongEvidence: Boolean
        get() = evidence.any {
            it.severity == AppTamperSeverity.HIGH ||
                    it.severity == AppTamperSeverity.CRITICAL
        }

    /**
     * Returns highest observed severity.
     */
    val highestSeverity: AppTamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: AppTamperSeverity.INFO

    /**
     * Returns completion percentage.
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
                )
                .toInt()
                .coerceIn(0, 100)
        }

    private fun severityWeight(
        severity: AppTamperSeverity
    ): Int {

        return when (severity) {

            AppTamperSeverity.INFO -> 0
            AppTamperSeverity.LOW -> 1
            AppTamperSeverity.MEDIUM -> 2
            AppTamperSeverity.HIGH -> 3
            AppTamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Individual application tamper evidence.
 */
data class AppTamperEvidence(

    /**
     * Evidence type.
     */
    val type: AppTamperEvidenceType,

    /**
     * Source/API that generated the evidence.
     */
    val source: String,

    /**
     * Human-readable description.
     */
    val description: String,

    /**
     * Observed value.
     */
    val value: String? = null,

    /**
     * Expected value, when a trusted comparison is available.
     */
    val expectedValue: String? = null,

    /**
     * Security significance.
     */
    val severity: AppTamperSeverity,

    /**
     * Confidence in the observation.
     *
     * This is not the probability that tampering occurred.
     */
    val confidence: Double
)

/**
 * Application-level tamper evidence categories.
 */
enum class AppTamperEvidenceType {

    /**
     * Current package identity.
     */
    PACKAGE_IDENTITY,

    /**
     * Package identity differs from trusted configuration.
     */
    PACKAGE_IDENTITY_MISMATCH,

    /**
     * Installed application version.
     */
    VERSION_NAME,

    /**
     * Installed version code.
     */
    VERSION_CODE,

    /**
     * Version matches trusted configuration.
     */
    VERSION_MATCH,

    /**
     * Version differs from trusted configuration.
     */
    VERSION_MISMATCH,

    /**
     * First installation timestamp.
     */
    FIRST_INSTALL_TIME,

    /**
     * Last update timestamp.
     */
    LAST_UPDATE_TIME,

    /**
     * Signing certificate fingerprint.
     */
    SIGNATURE_FINGERPRINT,

    /**
     * Signing certificate matches trusted configuration.
     */
    SIGNATURE_MATCH,

    /**
     * Signing certificate does not match trusted configuration.
     */
    SIGNATURE_MISMATCH,

    /**
     * Signing information unavailable.
     */
    SIGNATURE_UNAVAILABLE,

    /**
     * Application APK source path.
     */
    APK_SOURCE,

    /**
     * APK source information unavailable.
     */
    APK_SOURCE_UNAVAILABLE,

    /**
     * APK does not exist at the expected source path.
     */
    APK_NOT_FOUND,

    /**
     * APK appears writable.
     */
    APK_WRITABLE,

    /**
     * APK access denied.
     */
    APK_ACCESS_DENIED,

    /**
     * APK can be read.
     */
    APK_READABLE,

    /**
     * APK file size.
     */
    APK_SIZE,

    /**
     * APK modification timestamp.
     */
    APK_LAST_MODIFIED,

    /**
     * Application is debuggable.
     */
    DEBUGGABLE_APPLICATION,

    /**
     * Application is marked as a system application.
     */
    SYSTEM_APPLICATION,

    /**
     * Application is an updated system application.
     */
    UPDATED_SYSTEM_APPLICATION,

    /**
     * A check failed.
     */
    CHECK_FAILURE
}

/**
 * Severity of application tamper evidence.
 */
enum class AppTamperSeverity {

    /**
     * Normal information.
     */
    INFO,

    /**
     * Weak indicator.
     */
    LOW,

    /**
     * Moderate indicator.
     */
    MEDIUM,

    /**
     * Strong indicator.
     */
    HIGH,

    /**
     * Critical indicator.
     */
    CRITICAL
}
