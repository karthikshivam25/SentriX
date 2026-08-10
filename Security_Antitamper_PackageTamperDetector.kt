package com.sentrix.security.antitamper

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * PackageTamperDetector
 *
 * Detects potential tampering involving the installed Android
 * application package.
 *
 * Responsibilities:
 *
 * - Validate package identity.
 * - Inspect package metadata.
 * - Inspect application version information.
 * - Inspect APK and split-APK locations.
 * - Detect unexpected package/source configuration.
 * - Inspect installation/update metadata.
 * - Produce structured package-integrity evidence.
 *
 * This class intentionally does NOT perform:
 *
 * - signing certificate validation
 * - DEX/code hashing
 * - resource hashing
 * - runtime hook detection
 * - debugger detection
 * - destructive countermeasures
 *
 * Those responsibilities belong to dedicated SentriX components.
 *
 * Architecture:
 *
 * AntiTamperManager
 *        ↓
 * PackageTamperDetector
 *        ↓
 * PackageTamperResult
 *        ↓
 * AntiTamperEvidenceCollector
 *        ↓
 * AntiTamperValidator
 *
 * IMPORTANT:
 *
 * Package metadata alone cannot prove that an application has been
 * maliciously modified. Package-level observations should be
 * correlated with signature, APK, code, and resource integrity.
 */
class PackageTamperDetector(
    private val context: Context,
    private val configuration: PackageTamperConfiguration =
        PackageTamperConfiguration()
) {

    /**
     * Android PackageManager.
     */
    private val packageManager: PackageManager =
        context.packageManager

    /**
     * Package identifier of the current application.
     */
    private val packageName: String =
        context.packageName

    /**
     * Android application metadata.
     */
    private val applicationInfo: ApplicationInfo =
        context.applicationInfo

    /**
     * Performs the complete package-level tamper assessment.
     */
    fun detect(): PackageTamperResult {

        val evidence =
            mutableListOf<PackageTamperEvidence>()

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
                getPackageInfo()

            collectPackageMetadata(
                packageInfo = packageInfo,
                evidence = evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "PackageMetadata"
            )
        }

        /**
         * ---------------------------------------------------------
         * 3. APK source paths
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApkPathEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "ApkPaths"
            )
        }

        /**
         * ---------------------------------------------------------
         * 4. Application flags
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApplicationFlags(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "ApplicationFlags"
            )
        }

        /**
         * ---------------------------------------------------------
         * 5. Installation metadata
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectInstallationMetadata(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "InstallationMetadata"
            )
        }

        /**
         * ---------------------------------------------------------
         * 6. Split APK consistency
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectSplitApkEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "SplitApk"
            )
        }

        /**
         * ---------------------------------------------------------
         * Determine final detector state
         * ---------------------------------------------------------
         */
        val status =
            determineStatus(
                evidence = evidence,
                checksFailed = checksFailed
            )

        return PackageTamperResult(
            packageName = packageName,
            status = status,
            evidence = evidence,
            checksPerformed = checksPerformed,
            checksSuccessful = checksSuccessful,
            checksFailed = checksFailed,
            detectionCompleted =
                checksFailed == 0,
            detectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Validates the current application package name.
     */
    private fun checkPackageIdentity(
        evidence: MutableList<PackageTamperEvidence>
    ) {

        val expectedPackage =
            configuration.expectedPackageName

        if (expectedPackage.isNullOrBlank()) {

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.PACKAGE_IDENTITY,
                source = "Context.packageName",
                description =
                    "Current application package identifier.",
                value = packageName,
                severity = PackageTamperSeverity.INFO,
                confidence = 1.0
            )

            return
        }

        val matches =
            packageName == expectedPackage

        evidence += PackageTamperEvidence(
            type =
                if (matches) {
                    PackageTamperEvidenceType.PACKAGE_IDENTITY
                } else {
                    PackageTamperEvidenceType.PACKAGE_IDENTITY_MISMATCH
                },
            source = "Context.packageName",
            description =
                if (matches) {
                    "Package identifier matches trusted configuration."
                } else {
                    "Package identifier differs from trusted configuration."
                },
            value = packageName,
            expectedValue = expectedPackage,
            severity =
                if (matches) {
                    PackageTamperSeverity.INFO
                } else {
                    PackageTamperSeverity.CRITICAL
                },
            confidence = 1.0
        )
    }

    /**
     * Collects standard PackageInfo metadata.
     */
    private fun collectPackageMetadata(
        packageInfo: PackageInfo,
        evidence: MutableList<PackageTamperEvidence>
    ) {

        /**
         * Package name.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.PACKAGE_NAME,
            source = "PackageInfo.packageName",
            description =
                "Package name reported by PackageManager.",
            value = packageInfo.packageName,
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Version name.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.VERSION_NAME,
            source = "PackageInfo.versionName",
            description =
                "Installed application version name.",
            value = packageInfo.versionName,
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Version code.
         */
        val versionCode =
            getVersionCode(
                packageInfo
            )

        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.VERSION_CODE,
            source = "PackageInfo.versionCode",
            description =
                "Installed application version code.",
            value = versionCode.toString(),
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Expected version comparison.
         */
        val expectedVersionCode =
            configuration.expectedVersionCode

        if (expectedVersionCode != null) {

            val matches =
                versionCode ==
                        expectedVersionCode

            evidence += PackageTamperEvidence(
                type =
                    if (matches) {
                        PackageTamperEvidenceType.VERSION_MATCH
                    } else {
                        PackageTamperEvidenceType.VERSION_MISMATCH
                    },
                source = "PackageInfo.versionCode",
                description =
                    if (matches) {
                        "Installed version code matches trusted configuration."
                    } else {
                        "Installed version code differs from trusted configuration."
                    },
                value = versionCode.toString(),
                expectedValue =
                    expectedVersionCode.toString(),
                severity =
                    if (matches) {
                        PackageTamperSeverity.INFO
                    } else {
                        PackageTamperSeverity.HIGH
                    },
                confidence = 1.0
            )
        }

        /**
         * First installation timestamp.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.FIRST_INSTALL_TIME,
            source = "PackageInfo.firstInstallTime",
            description =
                "Application first-install timestamp.",
            value =
                packageInfo.firstInstallTime.toString(),
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Last update timestamp.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.LAST_UPDATE_TIME,
            source = "PackageInfo.lastUpdateTime",
            description =
                "Application last-update timestamp.",
            value =
                packageInfo.lastUpdateTime.toString(),
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * UID assigned to the application.
         *
         * This is contextual evidence rather than direct proof
         * of tampering.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.APPLICATION_UID,
            source = "ApplicationInfo.uid",
            description =
                "UID assigned to the installed application.",
            value =
                applicationInfo.uid.toString(),
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Inspects base APK and split APK locations.
     */
    private fun collectApkPathEvidence(
        evidence: MutableList<PackageTamperEvidence>
    ) {

        val sourceDir =
            applicationInfo.sourceDir

        if (sourceDir.isNullOrBlank()) {

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.APK_SOURCE_UNAVAILABLE,
                source = "ApplicationInfo.sourceDir",
                description =
                    "Base APK source path is unavailable.",
                severity = PackageTamperSeverity.HIGH,
                confidence = 0.70
            )

        } else {

            inspectApkPath(
                path = sourceDir,
                isBaseApk = true,
                evidence = evidence
            )
        }

        applicationInfo.splitSourceDirs
            ?.forEach { splitPath ->

                inspectApkPath(
                    path = splitPath,
                    isBaseApk = false,
                    evidence = evidence
                )
            }
    }

    /**
     * Inspects an individual APK path.
     */
    private fun inspectApkPath(
        path: String,
        isBaseApk: Boolean,
        evidence: MutableList<PackageTamperEvidence>
    ) {

        val file =
            File(path)

        val type =
            if (isBaseApk) {
                PackageTamperEvidenceType.BASE_APK_PATH
            } else {
                PackageTamperEvidenceType.SPLIT_APK_PATH
            }

        evidence += PackageTamperEvidence(
            type = type,
            source = "ApplicationInfo",
            description =
                if (isBaseApk) {
                    "Base APK source location."
                } else {
                    "Split APK source location."
                },
            value = path,
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        if (!file.exists()) {

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.APK_MISSING,
                source = "File.exists",
                description =
                    "Reported APK file does not exist.",
                value = path,
                severity = PackageTamperSeverity.HIGH,
                confidence = 0.90
            )

            return
        }

        if (!file.isFile) {

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.APK_NOT_REGULAR_FILE,
                source = "File.isFile",
                description =
                    "Reported APK path is not a regular file.",
                value = path,
                severity = PackageTamperSeverity.MEDIUM,
                confidence = 0.80
            )

            return
        }

        /**
         * APK readability.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.APK_READABLE,
            source = "File.canRead",
            description =
                "Whether the APK can be read.",
            value =
                file.canRead().toString(),
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * APK writability.
         *
         * This is an environmental indicator and should not alone
         * establish tampering.
         */
        try {

            if (file.canWrite()) {

                evidence += PackageTamperEvidence(
                    type =
                        PackageTamperEvidenceType.APK_WRITABLE,
                    source = "File.canWrite",
                    description =
                        "APK file appears writable.",
                    value = "true",
                    severity = PackageTamperSeverity.HIGH,
                    confidence = 0.80
                )
            }

        } catch (_: SecurityException) {

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.APK_ACCESS_DENIED,
                source = "File.canWrite",
                description =
                    "APK writability could not be determined.",
                value = path,
                severity = PackageTamperSeverity.LOW,
                confidence = 0.50
            )
        }

        /**
         * APK file size.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.APK_SIZE,
            source = "File.length",
            description =
                "APK file size.",
            value =
                file.length().toString(),
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Collects application flags.
     */
    private fun collectApplicationFlags(
        evidence: MutableList<PackageTamperEvidence>
    ) {

        val flags =
            applicationInfo.flags

        /**
         * Debuggable application.
         */
        val debuggable =
            (
                flags and
                        ApplicationInfo.FLAG_DEBUGGABLE
                ) != 0

        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.DEBUGGABLE_APPLICATION,
            source = "ApplicationInfo.flags",
            description =
                if (debuggable) {
                    "Application is marked as debuggable."
                } else {
                    "Application is not marked as debuggable."
                },
            value =
                debuggable.toString(),
            severity =
                if (debuggable) {
                    PackageTamperSeverity.MEDIUM
                } else {
                    PackageTamperSeverity.INFO
                },
            confidence = 1.0
        )

        /**
         * System application.
         */
        val systemApplication =
            (
                flags and
                        ApplicationInfo.FLAG_SYSTEM
                ) != 0

        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.SYSTEM_APPLICATION,
            source = "ApplicationInfo.flags",
            description =
                if (systemApplication) {
                    "Application is marked as a system application."
                } else {
                    "Application is not marked as a system application."
                },
            value =
                systemApplication.toString(),
            severity =
                if (systemApplication) {
                    PackageTamperSeverity.LOW
                } else {
                    PackageTamperSeverity.INFO
                },
            confidence = 1.0
        )

        /**
         * Updated system application.
         */
        val updatedSystemApplication =
            (
                flags and
                        ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                ) != 0

        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.UPDATED_SYSTEM_APPLICATION,
            source = "ApplicationInfo.flags",
            description =
                "Whether the application is reported as an updated system application.",
            value =
                updatedSystemApplication.toString(),
            severity =
                if (updatedSystemApplication) {
                    PackageTamperSeverity.LOW
                } else {
                    PackageTamperSeverity.INFO
                },
            confidence = 1.0
        )
    }

    /**
     * Collects installation-related metadata.
     */
    private fun collectInstallationMetadata(
        evidence: MutableList<PackageTamperEvidence>
    ) {

        val packageInfo =
            getPackageInfo()

        /**
         * Installation/update timestamps are contextual signals.
         */
        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.INSTALLATION_METADATA,
            source = "PackageInfo",
            description =
                "Installation metadata collected from Android PackageManager.",
            value =
                "firstInstall=${packageInfo.firstInstallTime};" +
                        "lastUpdate=${packageInfo.lastUpdateTime}",
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Compare package update timestamp against installation
         * timestamp.
         *
         * This is not itself a tamper indicator; it merely records
         * an expected lifecycle relationship.
         */
        if (
            packageInfo.lastUpdateTime <
            packageInfo.firstInstallTime
        ) {

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.INVALID_INSTALL_TIMELINE,
                source = "PackageInfo",
                description =
                    "Package update timestamp predates installation timestamp.",
                value =
                    "firstInstall=${packageInfo.firstInstallTime};" +
                            "lastUpdate=${packageInfo.lastUpdateTime}",
                severity = PackageTamperSeverity.MEDIUM,
                confidence = 0.90
            )
        }
    }

    /**
     * Inspects split APK metadata.
     */
    private fun collectSplitApkEvidence(
        evidence: MutableList<PackageTamperEvidence>
    ) {

        val splitNames =
            applicationInfo.splitNames

        val splitPaths =
            applicationInfo.splitSourceDirs

        val splitCount =
            splitPaths?.size ?: 0

        evidence += PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.SPLIT_APK_COUNT,
            source = "ApplicationInfo",
            description =
                "Number of split APKs associated with the application.",
            value =
                splitCount.toString(),
            severity = PackageTamperSeverity.INFO,
            confidence = 1.0
        )

        if (splitCount == 0) {
            return
        }

        /**
         * Validate that split names and paths have compatible
         * cardinality when both are supplied.
         */
        if (
            splitNames != null &&
            splitNames.size != splitCount
        ) {

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.SPLIT_METADATA_MISMATCH,
                source = "ApplicationInfo",
                description =
                    "Split APK names and source paths have inconsistent counts.",
                value =
                    "names=${splitNames.size};paths=$splitCount",
                severity = PackageTamperSeverity.MEDIUM,
                confidence = 0.90
            )
        }

        splitPaths?.forEachIndexed { index, path ->

            val file =
                File(path)

            if (!file.exists()) {

                evidence += PackageTamperEvidence(
                    type =
                        PackageTamperEvidenceType.SPLIT_APK_MISSING,
                    source = "ApplicationInfo.splitSourceDirs",
                    description =
                        "A reported split APK could not be found.",
                    value = path,
                    severity = PackageTamperSeverity.HIGH,
                    confidence = 0.90
                )

                return@forEachIndexed
            }

            if (!file.isFile) {

                evidence += PackageTamperEvidence(
                    type =
                        PackageTamperEvidenceType.SPLIT_APK_INVALID,
                    source = "ApplicationInfo.splitSourceDirs",
                    description =
                        "A reported split APK path is not a regular file.",
                    value = path,
                    severity = PackageTamperSeverity.MEDIUM,
                    confidence = 0.80
                )
            }

            evidence += PackageTamperEvidence(
                type =
                    PackageTamperEvidenceType.SPLIT_APK_METADATA,
                source = "ApplicationInfo.splitSourceDirs",
                description =
                    "Split APK metadata.",
                value =
                    "index=$index;name=" +
                            (splitNames?.getOrNull(index)
                                ?: "unknown") +
                            ";path=$path",
                severity = PackageTamperSeverity.INFO,
                confidence = 1.0
            )
        }
    }

    /**
     * Retrieves current PackageInfo.
     */
    @Suppress("DEPRECATION")
    private fun getPackageInfo():
            PackageInfo {

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
     * Gets the version code in an API-compatible way.
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
     * Creates standardized check-failure evidence.
     */
    private fun failureEvidence(
        source: String
    ): PackageTamperEvidence {

        return PackageTamperEvidence(
            type =
                PackageTamperEvidenceType.CHECK_FAILURE,
            source = source,
            description =
                "Package tamper check could not be completed.",
            severity = PackageTamperSeverity.MEDIUM,
            confidence = 0.50
        )
    }

    /**
     * Determines overall package-tamper state.
     */
    private fun determineStatus(
        evidence: List<PackageTamperEvidence>,
        checksFailed: Int
    ): PackageTamperStatus {

        /**
         * Strong identity mismatch.
         */
        if (
            evidence.any {
                it.type ==
                        PackageTamperEvidenceType.PACKAGE_IDENTITY_MISMATCH
            }
        ) {

            return PackageTamperStatus.PACKAGE_TAMPER_DETECTED
        }

        /**
         * Strong version mismatch can indicate an unexpected
         * package replacement when a trusted version is explicitly
         * configured.
         */
        if (
            evidence.any {
                it.type ==
                        PackageTamperEvidenceType.VERSION_MISMATCH
            }
        ) {

            return PackageTamperStatus.SUSPICIOUS
        }

        /**
         * Missing APK or split APK.
         */
        if (
            evidence.any {
                it.type ==
                        PackageTamperEvidenceType.APK_MISSING ||
                        it.type ==
                        PackageTamperEvidenceType.SPLIT_APK_MISSING
            }
        ) {

            return PackageTamperStatus.SUSPICIOUS
        }

        /**
         * Other strong environmental indicators.
         */
        if (
            evidence.any {
                it.severity ==
                        PackageTamperSeverity.HIGH ||
                        it.severity ==
                        PackageTamperSeverity.CRITICAL
            }
        ) {

            return PackageTamperStatus.SUSPICIOUS
        }

        if (checksFailed > 0) {
            return PackageTamperStatus.CHECK_INCOMPLETE
        }

        return PackageTamperStatus.NO_PACKAGE_TAMPER_DETECTED
    }

    /**
     * Returns true if package-level tampering was detected.
     */
    fun isPackageTampered(): Boolean {

        return detect().status ==
                PackageTamperStatus.PACKAGE_TAMPER_DETECTED
    }

    /**
     * Returns true when suspicious package evidence exists.
     */
    fun isSuspicious(): Boolean {

        val status =
            detect().status

        return status ==
                PackageTamperStatus.SUSPICIOUS
    }

    /**
     * Returns the current package name.
     */
    fun getCurrentPackageName(): String {

        return packageName
    }

    /**
     * Returns the current version code.
     */
    fun getCurrentVersionCode(): Long {

        return getVersionCode(
            getPackageInfo()
        )
    }

    /**
     * Returns all collected package evidence.
     */
    fun getEvidence():
            List<PackageTamperEvidence> {

        return detect().evidence
    }

    /**
     * Returns only significant evidence.
     */
    fun getSignificantEvidence():
            List<PackageTamperEvidence> {

        return detect()
            .evidence
            .filter {
                it.severity == PackageTamperSeverity.MEDIUM ||
                        it.severity == PackageTamperSeverity.HIGH ||
                        it.severity == PackageTamperSeverity.CRITICAL
            }
    }
}

/**
 * Trusted package configuration.
 *
 * All fields are optional so that the detector can still operate
 * as an observation-only component when trusted values have not
 * yet been provisioned.
 */
data class PackageTamperConfiguration(

    /**
     * Expected production package name.
     *
     * Example:
     *
     * com.sentrix
     */
    val expectedPackageName: String? = null,

    /**
     * Expected production version code.
     */
    val expectedVersionCode: Long? = null
)

/**
 * Complete package-tamper result.
 */
data class PackageTamperResult(

    /**
     * Package being inspected.
     */
    val packageName: String,

    /**
     * Overall package-integrity state.
     */
    val status: PackageTamperStatus,

    /**
     * Collected evidence.
     */
    val evidence: List<PackageTamperEvidence>,

    /**
     * Number of checks performed.
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
     * Whether all checks completed successfully.
     */
    val detectionCompleted: Boolean,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long
) {

    /**
     * True when package tampering is strongly identified.
     */
    val isTampered: Boolean
        get() =
            status ==
                    PackageTamperStatus.PACKAGE_TAMPER_DETECTED

    /**
     * True when suspicious package evidence exists.
     */
    val isSuspicious: Boolean
        get() =
            status ==
                    PackageTamperStatus.SUSPICIOUS

    /**
     * Highest observed evidence severity.
     */
    val highestSeverity:
            PackageTamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: PackageTamperSeverity.INFO

    /**
     * Returns significant evidence.
     */
    fun getSignificantEvidence():
            List<PackageTamperEvidence> {

        return evidence.filter {
            it.severity == PackageTamperSeverity.MEDIUM ||
                    it.severity == PackageTamperSeverity.HIGH ||
                    it.severity == PackageTamperSeverity.CRITICAL
        }
    }

    private fun severityWeight(
        severity: PackageTamperSeverity
    ): Int {

        return when (severity) {

            PackageTamperSeverity.INFO -> 0
            PackageTamperSeverity.LOW -> 1
            PackageTamperSeverity.MEDIUM -> 2
            PackageTamperSeverity.HIGH -> 3
            PackageTamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Package-tamper evidence.
 */
data class PackageTamperEvidence(

    /**
     * Evidence category.
     */
    val type: PackageTamperEvidenceType,

    /**
     * Source of the evidence.
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
     * Trusted expected value.
     */
    val expectedValue: String? = null,

    /**
     * Evidence severity.
     */
    val severity: PackageTamperSeverity,

    /**
     * Confidence in the observation.
     */
    val confidence: Double
)

/**
 * Package-integrity evidence categories.
 */
enum class PackageTamperEvidenceType {

    /**
     * Current package identity.
     */
    PACKAGE_IDENTITY,

    /**
     * Package identity mismatch.
     */
    PACKAGE_IDENTITY_MISMATCH,

    /**
     * Package name from PackageManager.
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
     * Application UID.
     */
    APPLICATION_UID,

    /**
     * Base APK source path.
     */
    BASE_APK_PATH,

    /**
     * Split APK source path.
     */
    SPLIT_APK_PATH,

    /**
     * APK source unavailable.
     */
    APK_SOURCE_UNAVAILABLE,

    /**
     * APK missing.
     */
    APK_MISSING,

    /**
     * APK is not a regular file.
     */
    APK_NOT_REGULAR_FILE,

    /**
     * APK is readable.
     */
    APK_READABLE,

    /**
     * APK appears writable.
     */
    APK_WRITABLE,

    /**
     * APK access state could not be determined.
     */
    APK_ACCESS_DENIED,

    /**
     * APK size.
     */
    APK_SIZE,

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
     * Installation metadata.
     */
    INSTALLATION_METADATA,

    /**
     * Installation/update timeline is inconsistent.
     */
    INVALID_INSTALL_TIMELINE,

    /**
     * Number of split APKs.
     */
    SPLIT_APK_COUNT,

    /**
     * Split metadata inconsistency.
     */
    SPLIT_METADATA_MISMATCH,

    /**
     * Split APK missing.
     */
    SPLIT_APK_MISSING,

    /**
     * Split APK invalid.
     */
    SPLIT_APK_INVALID,

    /**
     * Split APK metadata.
     */
    SPLIT_APK_METADATA,

    /**
     * Generic check failure.
     */
    CHECK_FAILURE
}

/**
 * Package-tamper evidence severity.
 */
enum class PackageTamperSeverity {

    /**
     * Informational.
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

/**
 * Overall package-tamper status.
 */
enum class PackageTamperStatus {

    /**
     * No significant package tampering detected.
     */
    NO_PACKAGE_TAMPER_DETECTED,

    /**
     * Suspicious package-level evidence exists.
     */
    SUSPICIOUS,

    /**
     * Strong package identity tampering detected.
     */
    PACKAGE_TAMPER_DETECTED,

    /**
     * Assessment could not fully complete.
     */
    CHECK_INCOMPLETE
}
