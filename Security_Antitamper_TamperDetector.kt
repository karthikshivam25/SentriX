package com.sentrix.security.antitamper

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File
import java.security.MessageDigest

/**
 * TamperDetector
 *
 * Detects technical indicators that the SentriX application may have
 * been modified, repackaged, instrumented, or executed in an
 * unexpected runtime environment.
 *
 * Responsibilities:
 *
 * - Inspect application package metadata.
 * - Inspect application source information.
 * - Inspect signing certificate information.
 * - Inspect debuggable configuration.
 * - Inspect runtime debugger state.
 * - Inspect APK/source file metadata.
 * - Generate structured tamper evidence.
 *
 * This class does NOT:
 *
 * - modify application files
 * - terminate the application
 * - perform destructive countermeasures
 * - execute arbitrary commands
 * - make the final tampering verdict
 * - calculate the global SentriX security score
 *
 * Architecture:
 *
 * AntiTamperService
 *        ↓
 * AntiTamperManager
 *        ↓
 * TamperDetector
 *        ↓
 * AntiTamperEvidence
 *        ↓
 * AntiTamperValidator
 */
class TamperDetector(
    private val context: Context
) {

    /**
     * Android PackageManager.
     */
    private val packageManager: PackageManager =
        context.packageManager

    /**
     * Current application package name.
     */
    private val packageName: String =
        context.packageName

    /**
     * Current application metadata.
     */
    private val applicationInfo: ApplicationInfo =
        context.applicationInfo

    /**
     * Performs the complete tamper-indicator scan.
     *
     * @return TamperDetectionResult containing all discovered
     * tampering indicators.
     */
    fun detect(): TamperDetectionResult {

        val evidence =
            mutableListOf<TamperEvidence>()

        var checksPerformed = 0
        var checksSuccessful = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * Package metadata
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectPackageMetadata(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += createCheckFailureEvidence(
                source = "PackageMetadata"
            )
        }

        /**
         * ---------------------------------------------------------
         * Signing certificate
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectSigningEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += createCheckFailureEvidence(
                source = "SigningCertificate"
            )
        }

        /**
         * ---------------------------------------------------------
         * Application source
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApplicationSourceEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += createCheckFailureEvidence(
                source = "ApplicationSource"
            )
        }

        /**
         * ---------------------------------------------------------
         * Debug/runtime state
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectRuntimeEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += createCheckFailureEvidence(
                source = "Runtime"
            )
        }

        /**
         * ---------------------------------------------------------
         * APK file metadata
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApkFileEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksPerformed++
            checksFailed++

            evidence += createCheckFailureEvidence(
                source = "ApkFile"
            )
        }

        return TamperDetectionResult(
            evidence = evidence,
            checksPerformed = checksPerformed,
            checksSuccessful = checksSuccessful,
            checksFailed = checksFailed,
            detectionCompleted = checksFailed == 0,
            detectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Collects package metadata.
     */
    private fun collectPackageMetadata(
        evidence: MutableList<TamperEvidence>
    ) {

        val packageInfo =
            getPackageInfo()

        /**
         * Package name.
         */
        evidence += TamperEvidence(
            type = TamperEvidenceType.PACKAGE_NAME,
            source = "PackageInfo.packageName",
            description =
                "Current application package identifier.",
            value = packageInfo.packageName,
            severity = TamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Version name.
         */
        evidence += TamperEvidence(
            type = TamperEvidenceType.VERSION_NAME,
            source = "PackageInfo.versionName",
            description =
                "Installed application version.",
            value = packageInfo.versionName,
            severity = TamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Version code.
         */
        val versionCode =
            getVersionCode(packageInfo)

        evidence += TamperEvidence(
            type = TamperEvidenceType.VERSION_CODE,
            source = "PackageInfo.versionCode",
            description =
                "Installed application version code.",
            value = versionCode.toString(),
            severity = TamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * First installation time.
         */
        evidence += TamperEvidence(
            type = TamperEvidenceType.INSTALL_TIME,
            source = "PackageInfo.firstInstallTime",
            description =
                "Application installation timestamp.",
            value =
                packageInfo.firstInstallTime.toString(),
            severity = TamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Last update time.
         */
        evidence += TamperEvidence(
            type = TamperEvidenceType.UPDATE_TIME,
            source = "PackageInfo.lastUpdateTime",
            description =
                "Application last-update timestamp.",
            value =
                packageInfo.lastUpdateTime.toString(),
            severity = TamperSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Collects signing certificate evidence.
     *
     * The certificate digest is useful for later comparison against
     * a trusted release certificate configured by SentriX.
     *
     * This detector only collects the digest.
     * The trusted comparison belongs in AntiTamperSignatureChecker.
     */
    @Suppress("DEPRECATION")
    private fun collectSigningEvidence(
        evidence: MutableList<TamperEvidence>
    ) {

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

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.P
        ) {

            val signingInfo =
                packageInfo.signingInfo

            if (signingInfo == null) {

                evidence += TamperEvidence(
                    type = TamperEvidenceType.SIGNATURE_UNAVAILABLE,
                    source = "SigningInfo",
                    description =
                        "Application signing information is unavailable.",
                    severity = TamperSeverity.MEDIUM,
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

            if (signatures.isEmpty()) {

                evidence += TamperEvidence(
                    type = TamperEvidenceType.SIGNATURE_UNAVAILABLE,
                    source = "SigningInfo",
                    description =
                        "No application signing certificates were observed.",
                    severity = TamperSeverity.MEDIUM,
                    confidence = 0.60
                )

                return
            }

            signatures.forEach { signature ->

                val digest =
                    calculateSha256(
                        signature.toByteArray()
                    )

                evidence += TamperEvidence(
                    type = TamperEvidenceType.SIGNATURE_DIGEST,
                    source = "SigningCertificate",
                    description =
                        "SHA-256 digest of the application signing certificate.",
                    value = digest,
                    severity = TamperSeverity.INFO,
                    confidence = 1.0
                )
            }

        } else {

            val signatures =
                packageInfo.signatures

            if (signatures.isNullOrEmpty()) {

                evidence += TamperEvidence(
                    type = TamperEvidenceType.SIGNATURE_UNAVAILABLE,
                    source = "PackageInfo.signatures",
                    description =
                        "Application signing information is unavailable.",
                    severity = TamperSeverity.MEDIUM,
                    confidence = 0.60
                )

                return
            }

            signatures.forEach { signature ->

                val digest =
                    calculateSha256(
                        signature.toByteArray()
                    )

                evidence += TamperEvidence(
                    type = TamperEvidenceType.SIGNATURE_DIGEST,
                    source = "Signature",
                    description =
                        "SHA-256 digest of the application signing certificate.",
                    value = digest,
                    severity = TamperSeverity.INFO,
                    confidence = 1.0
                )
            }
        }
    }

    /**
     * Collects application source-path evidence.
     */
    private fun collectApplicationSourceEvidence(
        evidence: MutableList<TamperEvidence>
    ) {

        val sourceDir =
            applicationInfo.sourceDir

        if (sourceDir.isNullOrBlank()) {

            evidence += TamperEvidence(
                type = TamperEvidenceType.SOURCE_UNAVAILABLE,
                source = "ApplicationInfo.sourceDir",
                description =
                    "Application source location could not be determined.",
                severity = TamperSeverity.MEDIUM,
                confidence = 0.60
            )

            return
        }

        evidence += TamperEvidence(
            type = TamperEvidenceType.APPLICATION_SOURCE,
            source = "ApplicationInfo.sourceDir",
            description =
                "Application APK source location.",
            value = sourceDir,
            severity = TamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Check whether the application source file exists.
         */
        val apkFile =
            File(sourceDir)

        try {

            if (!apkFile.exists()) {

                evidence += TamperEvidence(
                    type = TamperEvidenceType.APK_MISSING,
                    source = sourceDir,
                    description =
                        "Application APK source file could not be found.",
                    severity = TamperSeverity.HIGH,
                    confidence = 0.90
                )

                return
            }

            /**
             * APK readability.
             */
            evidence += TamperEvidence(
                type = TamperEvidenceType.APK_READABLE,
                source = sourceDir,
                description =
                    "Application APK is readable.",
                value =
                    apkFile.canRead().toString(),
                severity = TamperSeverity.INFO,
                confidence = 1.0
            )

            /**
             * APK writability.
             *
             * Writability is treated as a signal rather than proof
             * of tampering because installation environments vary.
             */
            if (apkFile.canWrite()) {

                evidence += TamperEvidence(
                    type = TamperEvidenceType.APK_WRITABLE,
                    source = sourceDir,
                    description =
                        "Application APK location appears writable.",
                    value = "true",
                    severity = TamperSeverity.HIGH,
                    confidence = 0.80
                )
            }

        } catch (_: SecurityException) {

            evidence += TamperEvidence(
                type = TamperEvidenceType.APK_ACCESS_DENIED,
                source = sourceDir,
                description =
                    "Access to the application APK was denied.",
                severity = TamperSeverity.LOW,
                confidence = 0.60
            )
        }
    }

    /**
     * Collects runtime/debugger evidence.
     */
    private fun collectRuntimeEvidence(
        evidence: MutableList<TamperEvidence>
    ) {

        /**
         * Debugger attached.
         */
        val debuggerConnected =
            Debug.isDebuggerConnected()

        if (debuggerConnected) {

            evidence += TamperEvidence(
                type = TamperEvidenceType.DEBUGGER_CONNECTED,
                source = "Debug.isDebuggerConnected()",
                description =
                    "A debugger is attached to the application process.",
                value = "true",
                severity = TamperSeverity.MEDIUM,
                confidence = 1.0
            )
        }

        /**
         * Application debuggable flag.
         */
        val isDebuggable =
            (
                applicationInfo.flags and
                        ApplicationInfo.FLAG_DEBUGGABLE
                ) != 0

        if (isDebuggable) {

            evidence += TamperEvidence(
                type = TamperEvidenceType.DEBUGGABLE_BUILD,
                source = "ApplicationInfo.flags",
                description =
                    "The application is marked as debuggable.",
                value = "true",
                severity = TamperSeverity.MEDIUM,
                confidence = 1.0
            )
        }

        /**
         * Application process ID.
         *
         * Contextual information only.
         */
        evidence += TamperEvidence(
            type = TamperEvidenceType.PROCESS_ID,
            source = "android.os.Process.myPid()",
            description =
                "Current application process identifier.",
            value =
                android.os.Process.myPid().toString(),
            severity = TamperSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Collects APK-level metadata.
     *
     * This does not calculate a full APK integrity hash.
     * That responsibility belongs to AntiTamperApkChecker.
     */
    private fun collectApkFileEvidence(
        evidence: MutableList<TamperEvidence>
    ) {

        val sourceDir =
            applicationInfo.sourceDir
                ?: return

        val apkFile =
            File(sourceDir)

        try {

            if (!apkFile.exists()) {
                return
            }

            evidence += TamperEvidence(
                type = TamperEvidenceType.APK_SIZE,
                source = sourceDir,
                description =
                    "Installed APK file size.",
                value =
                    apkFile.length().toString(),
                severity = TamperSeverity.INFO,
                confidence = 1.0
            )

            evidence += TamperEvidence(
                type = TamperEvidenceType.APK_LAST_MODIFIED,
                source = sourceDir,
                description =
                    "Installed APK last-modified timestamp.",
                value =
                    apkFile.lastModified().toString(),
                severity = TamperSeverity.INFO,
                confidence = 1.0
            )

        } catch (_: SecurityException) {

            evidence += TamperEvidence(
                type = TamperEvidenceType.APK_METADATA_UNAVAILABLE,
                source = sourceDir,
                description =
                    "APK metadata could not be inspected.",
                severity = TamperSeverity.LOW,
                confidence = 0.50
            )
        }
    }

    /**
     * Retrieves current package information.
     */
    @Suppress("DEPRECATION")
    private fun getPackageInfo():
            android.content.pm.PackageInfo {

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.TIRAMISU
        ) {

            packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(0)
            )

        } else {

            packageManager.getPackageInfo(
                packageName,
                0
            )
        }
    }

    /**
     * Retrieves the package version code across API levels.
     */
    @Suppress("DEPRECATION")
    private fun getVersionCode(
        packageInfo: android.content.pm.PackageInfo
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
     * Calculates SHA-256 for certificate/signature bytes.
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
     * Creates standardized evidence for a failed check.
     */
    private fun createCheckFailureEvidence(
        source: String
    ): TamperEvidence {

        return TamperEvidence(
            type = TamperEvidenceType.CHECK_FAILURE,
            source = source,
            description =
                "The tamper check could not be completed.",
            severity = TamperSeverity.MEDIUM,
            confidence = 0.50
        )
    }

    /**
     * Returns true when strong tampering indicators were found.
     *
     * This is still an evidence-level decision and should not be
     * confused with the final AntiTamperStatus.
     */
    fun hasStrongTamperEvidence(): Boolean {

        return detect()
            .evidence
            .any {
                it.severity == TamperSeverity.HIGH ||
                        it.severity == TamperSeverity.CRITICAL
            }
    }

    /**
     * Returns only significant tamper evidence.
     */
    fun getSignificantEvidence():
            List<TamperEvidence> {

        return detect()
            .evidence
            .filter {
                it.severity == TamperSeverity.MEDIUM ||
                        it.severity == TamperSeverity.HIGH ||
                        it.severity == TamperSeverity.CRITICAL
            }
    }
}

/**
 * Complete result produced by TamperDetector.
 */
data class TamperDetectionResult(

    /**
     * Evidence collected during detection.
     */
    val evidence: List<TamperEvidence>,

    /**
     * Number of checks attempted.
     */
    val checksPerformed: Int,

    /**
     * Number of checks completed successfully.
     */
    val checksSuccessful: Int,

    /**
     * Number of checks that failed.
     */
    val checksFailed: Int,

    /**
     * Indicates whether every check completed.
     */
    val detectionCompleted: Boolean,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long
) {

    /**
     * Indicates whether evidence of tampering exists.
     */
    val hasEvidence: Boolean
        get() = evidence.isNotEmpty()

    /**
     * Indicates whether strong tampering evidence exists.
     */
    val hasStrongEvidence: Boolean
        get() = evidence.any {
            it.severity == TamperSeverity.HIGH ||
                    it.severity == TamperSeverity.CRITICAL
        }

    /**
     * Returns the strongest observed severity.
     */
    val highestSeverity: TamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: TamperSeverity.INFO

    /**
     * Returns the completion percentage.
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
     * Converts severity into a sortable weight.
     */
    private fun severityWeight(
        severity: TamperSeverity
    ): Int {

        return when (severity) {

            TamperSeverity.INFO -> 0
            TamperSeverity.LOW -> 1
            TamperSeverity.MEDIUM -> 2
            TamperSeverity.HIGH -> 3
            TamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Individual tamper evidence.
 */
data class TamperEvidence(

    /**
     * Evidence category.
     */
    val type: TamperEvidenceType,

    /**
     * Component/API that generated the evidence.
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
     * Evidence severity.
     */
    val severity: TamperSeverity,

    /**
     * Confidence in the observation.
     *
     * This is NOT the probability that tampering occurred.
     */
    val confidence: Double
)

/**
 * Categories of tamper evidence.
 */
enum class TamperEvidenceType {

    /**
     * Application package name.
     */
    PACKAGE_NAME,

    /**
     * Application version name.
     */
    VERSION_NAME,

    /**
     * Application version code.
     */
    VERSION_CODE,

    /**
     * Application installation timestamp.
     */
    INSTALL_TIME,

    /**
     * Application update timestamp.
     */
    UPDATE_TIME,

    /**
     * Application signing certificate digest.
     */
    SIGNATURE_DIGEST,

    /**
     * Signing information unavailable.
     */
    SIGNATURE_UNAVAILABLE,

    /**
     * Application APK source location.
     */
    APPLICATION_SOURCE,

    /**
     * APK source could not be accessed.
     */
    SOURCE_UNAVAILABLE,

    /**
     * APK file does not exist at the reported location.
     */
    APK_MISSING,

    /**
     * APK readability state.
     */
    APK_READABLE,

    /**
     * APK appears writable.
     */
    APK_WRITABLE,

    /**
     * APK size.
     */
    APK_SIZE,

    /**
     * APK modification timestamp.
     */
    APK_LAST_MODIFIED,

    /**
     * APK metadata unavailable.
     */
    APK_METADATA_UNAVAILABLE,

    /**
     * Access to APK denied.
     */
    APK_ACCESS_DENIED,

    /**
     * Application is marked debuggable.
     */
    DEBUGGABLE_BUILD,

    /**
     * Debugger attached.
     */
    DEBUGGER_CONNECTED,

    /**
     * Current process ID.
     */
    PROCESS_ID,

    /**
     * A check failed.
     */
    CHECK_FAILURE
}

/**
 * Severity assigned to tamper evidence.
 */
enum class TamperSeverity {

    /**
     * Normal informational observation.
     */
    INFO,

    /**
     * Weak tampering signal.
     */
    LOW,

    /**
     * Moderate tampering signal.
     */
    MEDIUM,

    /**
     * Strong tampering signal.
     */
    HIGH,

    /**
     * Critical tampering signal.
     */
    CRITICAL
}
