package com.sentrix.security.rootdetection

import android.content.Context
import android.os.Build
import java.io.File

/**
 * RootEvidenceCollector
 *
 * Collects detailed technical evidence that can be used by the
 * SentriX root-detection pipeline.
 *
 * This class is intentionally focused on EVIDENCE COLLECTION.
 *
 * It does NOT:
 * - decide whether the device is rooted
 * - calculate the final risk score
 * - generate the final security report
 * - display UI
 *
 * Those responsibilities belong to higher-level components such as:
 *
 * RootDetectionManager
 * RootDetectionValidator
 * RootDetectionReportGenerator
 *
 * Architecture:
 *
 * RootDetectionService
 *        ↓
 * RootDetectionManager
 *        ↓
 * RootChecker
 *        ↓
 * RootEvidenceCollector
 *        ↓
 * ┌─────────────────────────────┐
 * │ Filesystem evidence         │
 * │ Package evidence            │
 * │ Build evidence              │
 * │ System-property evidence   │
 * │ Mount evidence              │
 * │ Environment evidence       │
 * └─────────────────────────────┘
 *
 * IMPORTANT:
 *
 * Local root detection is heuristic.
 * Evidence collected here must be interpreted together rather
 * than treated as definitive proof of device compromise.
 */
class RootEvidenceCollector(
    private val context: Context
) {

    /**
     * Known root-related binary locations.
     */
    private val rootBinaryPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/su/bin/daemonsu",
        "/system/bin/.ext/su",
        "/system/xbin/daemonsu",
        "/vendor/bin/su",
        "/vendor/xbin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su"
    )

    /**
     * Known root-management package identifiers.
     *
     * Package visibility restrictions may affect these checks
     * on modern Android versions.
     */
    private val rootManagementPackages = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.yellowes.su"
    )

    /**
     * Android system properties that can provide useful
     * root/development-environment evidence.
     */
    private val monitoredProperties = listOf(
        "ro.debuggable",
        "ro.secure",
        "ro.build.tags",
        "ro.build.type",
        "ro.build.selinux"
    )

    /**
     * Protected filesystem paths whose write state can provide
     * useful evidence.
     */
    private val protectedPaths = listOf(
        "/system",
        "/system/bin",
        "/system/xbin",
        "/vendor",
        "/product",
        "/system_root"
    )

    /**
     * Collects the complete evidence set.
     *
     * @return RootEvidence containing all collected evidence.
     */
    fun collectEvidence(): RootEvidence {

        val evidence = mutableListOf<RootEvidenceItem>()

        collectBinaryEvidence(evidence)

        collectPackageEvidence(evidence)

        collectBuildEvidence(evidence)

        collectSystemPropertyEvidence(evidence)

        collectFilesystemEvidence(evidence)

        collectMountEvidence(evidence)

        return RootEvidence(
            items = evidence,
            deviceModel = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            androidVersion = Build.VERSION.RELEASE,
            sdkVersion = Build.VERSION.SDK_INT,
            buildFingerprint = Build.FINGERPRINT,
            collectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Collects evidence related to root binaries.
     */
    private fun collectBinaryEvidence(
        evidence: MutableList<RootEvidenceItem>
    ) {

        rootBinaryPaths.forEach { path ->

            if (fileExists(path)) {

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.ROOT_BINARY,
                    source = path,
                    value = "exists",
                    description =
                        "Potential root-related binary exists at $path.",
                    severity = RootEvidenceSeverity.HIGH,
                    confidence = 0.90
                )
            }
        }
    }

    /**
     * Collects evidence related to installed root-management
     * applications.
     */
    private fun collectPackageEvidence(
        evidence: MutableList<RootEvidenceItem>
    ) {

        val packageManager = context.packageManager

        rootManagementPackages.forEach { packageName ->

            try {

                packageManager.getPackageInfo(
                    packageName,
                    0
                )

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.ROOT_PACKAGE,
                    source = packageName,
                    value = "installed",
                    description =
                        "Known root-management package detected.",
                    severity = RootEvidenceSeverity.HIGH,
                    confidence = 0.85
                )

            } catch (_: Exception) {
                // Package not found or inaccessible.
                //
                // Absence of a package is not recorded as evidence.
            }
        }
    }

    /**
     * Collects Android build-related evidence.
     *
     * Test-keys are recorded as evidence but should not independently
     * classify a device as rooted.
     */
    private fun collectBuildEvidence(
        evidence: MutableList<RootEvidenceItem>
    ) {

        val buildTags = Build.TAGS

        if (!buildTags.isNullOrBlank()) {

            evidence += RootEvidenceItem(
                type = RootEvidenceType.BUILD_TAGS,
                source = "Build.TAGS",
                value = buildTags,
                description =
                    "Android build tags collected for integrity analysis.",
                severity = RootEvidenceSeverity.INFO,
                confidence = 1.0
            )

            if (
                buildTags.contains(
                    "test-keys",
                    ignoreCase = true
                )
            ) {

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.TEST_KEYS,
                    source = "Build.TAGS",
                    value = "test-keys",
                    description =
                        "Android build contains test-keys.",
                    severity = RootEvidenceSeverity.MEDIUM,
                    confidence = 0.70
                )
            }
        }

        /**
         * Build type provides additional context.
         */
        val buildType = Build.TYPE

        if (!buildType.isNullOrBlank()) {

            evidence += RootEvidenceItem(
                type = RootEvidenceType.BUILD_TYPE,
                source = "Build.TYPE",
                value = buildType,
                description =
                    "Android build type collected.",
                severity = RootEvidenceSeverity.INFO,
                confidence = 1.0
            )

            if (
                buildType.equals(
                    "eng",
                    ignoreCase = true
                ) ||
                buildType.equals(
                    "userdebug",
                    ignoreCase = true
                )
            ) {

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.DEBUG_BUILD,
                    source = "Build.TYPE",
                    value = buildType,
                    description =
                        "Device is running a non-standard production build type.",
                    severity = RootEvidenceSeverity.MEDIUM,
                    confidence = 0.65
                )
            }
        }
    }

    /**
     * Collects selected Android system properties.
     */
    private fun collectSystemPropertyEvidence(
        evidence: MutableList<RootEvidenceItem>
    ) {

        monitoredProperties.forEach { propertyName ->

            val value = readSystemProperty(propertyName)

            if (value != null) {

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.SYSTEM_PROPERTY,
                    source = propertyName,
                    value = value,
                    description =
                        "Android system property collected.",
                    severity = determinePropertySeverity(
                        propertyName,
                        value
                    ),
                    confidence = determinePropertyConfidence(
                        propertyName,
                        value
                    )
                )
            }
        }

        /**
         * Explicit suspicious-property evidence.
         */
        val debuggable = readSystemProperty(
            "ro.debuggable"
        )

        if (debuggable == "1") {

            evidence += RootEvidenceItem(
                type = RootEvidenceType.DANGEROUS_PROPERTY,
                source = "ro.debuggable",
                value = "1",
                description =
                    "Android reports a debuggable system configuration.",
                severity = RootEvidenceSeverity.MEDIUM,
                confidence = 0.65
            )
        }

        val secure = readSystemProperty(
            "ro.secure"
        )

        if (secure == "0") {

            evidence += RootEvidenceItem(
                type = RootEvidenceType.DANGEROUS_PROPERTY,
                source = "ro.secure",
                value = "0",
                description =
                    "Android reports a potentially insecure system property.",
                severity = RootEvidenceSeverity.MEDIUM,
                confidence = 0.75
            )
        }
    }

    /**
     * Determines the severity associated with a system property.
     */
    private fun determinePropertySeverity(
        propertyName: String,
        value: String
    ): RootEvidenceSeverity {

        return when {

            propertyName == "ro.debuggable" &&
                    value == "1" ->
                RootEvidenceSeverity.MEDIUM

            propertyName == "ro.secure" &&
                    value == "0" ->
                RootEvidenceSeverity.MEDIUM

            propertyName == "ro.build.tags" &&
                    value.contains(
                        "test-keys",
                        ignoreCase = true
                    ) ->
                RootEvidenceSeverity.MEDIUM

            else ->
                RootEvidenceSeverity.INFO
        }
    }

    /**
     * Determines confidence for a system-property observation.
     */
    private fun determinePropertyConfidence(
        propertyName: String,
        value: String
    ): Double {

        return when {

            propertyName == "ro.secure" &&
                    value == "0" ->
                0.75

            propertyName == "ro.debuggable" &&
                    value == "1" ->
                0.65

            else ->
                1.0
        }
    }

    /**
     * Collects filesystem permission evidence.
     */
    private fun collectFilesystemEvidence(
        evidence: MutableList<RootEvidenceItem>
    ) {

        protectedPaths.forEach { path ->

            val file = File(path)

            try {

                if (!file.exists()) {
                    return@forEach
                }

                val writable = file.canWrite()

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.PROTECTED_PATH,
                    source = path,
                    value = if (writable) {
                        "writable"
                    } else {
                        "not_writable"
                    },
                    description =
                        if (writable) {
                            "Protected Android path appears writable."
                        } else {
                            "Protected Android path exists and is not writable."
                        },
                    severity =
                        if (writable) {
                            RootEvidenceSeverity.HIGH
                        } else {
                            RootEvidenceSeverity.INFO
                        },
                    confidence =
                        if (writable) {
                            0.80
                        } else {
                            1.0
                        }
                )

            } catch (_: SecurityException) {

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.PROTECTED_PATH,
                    source = path,
                    value = "access_denied",
                    description =
                        "Access to protected Android path was denied.",
                    severity = RootEvidenceSeverity.INFO,
                    confidence = 0.90
                )

            } catch (_: Exception) {

                evidence += RootEvidenceItem(
                    type = RootEvidenceType.PROTECTED_PATH,
                    source = path,
                    value = "check_failed",
                    description =
                        "Protected path could not be evaluated.",
                    severity = RootEvidenceSeverity.INFO,
                    confidence = 0.50
                )
            }
        }
    }

    /**
     * Collects evidence from /proc/mounts.
     *
     * The purpose is to identify protected filesystems that appear
     * to be mounted with write access.
     */
    private fun collectMountEvidence(
        evidence: MutableList<RootEvidenceItem>
    ) {

        val mountsFile = File("/proc/mounts")

        try {

            if (
                !mountsFile.exists() ||
                !mountsFile.canRead()
            ) {
                return
            }

            mountsFile.useLines { lines ->

                lines.forEach { line ->

                    val normalized = line.lowercase()

                    val protectedMount =
                        normalized.contains(" /system ") ||
                        normalized.contains(" /vendor ") ||
                        normalized.contains(" /product ") ||
                        normalized.contains(" /system_root ")

                    if (!protectedMount) {
                        return@forEach
                    }

                    val writable =
                        normalized.contains(",rw") ||
                        normalized.contains(" rw,") ||
                        normalized.endsWith(",rw")

                    evidence += RootEvidenceItem(
                        type = RootEvidenceType.MOUNT_CONFIGURATION,
                        source = "proc/mounts",
                        value = line,
                        description =
                            if (writable) {
                                "Protected filesystem appears writable."
                            } else {
                                "Protected filesystem mount information collected."
                            },
                        severity =
                            if (writable) {
                                RootEvidenceSeverity.HIGH
                            } else {
                                RootEvidenceSeverity.INFO
                            },
                        confidence =
                            if (writable) {
                                0.80
                            } else {
                                1.0
                            }
                    )
                }
            }

        } catch (_: SecurityException) {

            evidence += RootEvidenceItem(
                type = RootEvidenceType.MOUNT_CONFIGURATION,
                source = "/proc/mounts",
                value = "access_denied",
                description =
                    "Mount information could not be accessed.",
                severity = RootEvidenceSeverity.INFO,
                confidence = 0.50
            )

        } catch (_: Exception) {

            evidence += RootEvidenceItem(
                type = RootEvidenceType.MOUNT_CONFIGURATION,
                source = "/proc/mounts",
                value = "check_failed",
                description =
                    "Mount configuration could not be evaluated.",
                severity = RootEvidenceSeverity.INFO,
                confidence = 0.50
            )
        }
    }

    /**
     * Safely determines whether a file exists.
     */
    private fun fileExists(
        path: String
    ): Boolean {

        return try {

            File(path).exists()

        } catch (_: SecurityException) {

            false

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Safely reads an Android system property.
     */
    private fun readSystemProperty(
        propertyName: String
    ): String? {

        return try {

            val process = Runtime.getRuntime().exec(
                arrayOf(
                    "/system/bin/getprop",
                    propertyName
                )
            )

            process.inputStream
                .bufferedReader()
                .use { reader ->
                    reader.readLine()?.trim()
                }

        } catch (_: SecurityException) {

            null

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Returns only high-severity evidence.
     *
     * Useful for the manager when it needs to quickly determine
     * whether strong local signals exist.
     */
    fun collectHighSeverityEvidence(): List<RootEvidenceItem> {

        return collectEvidence()
            .items
            .filter {
                it.severity == RootEvidenceSeverity.HIGH ||
                        it.severity == RootEvidenceSeverity.CRITICAL
            }
    }

    /**
     * Returns only medium-or-higher evidence.
     */
    fun collectSignificantEvidence(): List<RootEvidenceItem> {

        return collectEvidence()
            .items
            .filter {
                it.severity == RootEvidenceSeverity.MEDIUM ||
                        it.severity == RootEvidenceSeverity.HIGH ||
                        it.severity == RootEvidenceSeverity.CRITICAL
            }
    }

    /**
     * Returns true if strong evidence exists.
     *
     * This is intentionally named "evidence" rather than "rooted"
     * because the collector must not make the final security decision.
     */
    fun hasStrongEvidence(): Boolean {

        return collectHighSeverityEvidence().isNotEmpty()
    }
}

/**
 * Complete collection of root-detection evidence.
 */
data class RootEvidence(

    /**
     * Individual evidence items.
     */
    val items: List<RootEvidenceItem>,

    /**
     * Device model.
     */
    val deviceModel: String,

    /**
     * Device manufacturer.
     */
    val manufacturer: String,

    /**
     * Android release version.
     */
    val androidVersion: String,

    /**
     * Android API level.
     */
    val sdkVersion: Int,

    /**
     * Full Android build fingerprint.
     *
     * This should generally remain internal to the security
     * pipeline and should not be exposed unnecessarily.
     */
    val buildFingerprint: String,

    /**
     * Epoch timestamp representing when evidence collection began.
     */
    val collectedAt: Long
)

/**
 * Represents a single piece of technical root-detection evidence.
 */
data class RootEvidenceItem(

    /**
     * Evidence category.
     */
    val type: RootEvidenceType,

    /**
     * Where the evidence originated.
     *
     * Examples:
     * - filesystem path
     * - package name
     * - system property
     * - /proc/mounts
     */
    val source: String,

    /**
     * Observed value.
     */
    val value: String,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Evidence severity.
     */
    val severity: RootEvidenceSeverity,

    /**
     * Confidence from 0.0 to 1.0.
     *
     * Confidence is NOT the same as root probability.
     */
    val confidence: Double
)

/**
 * Root evidence categories.
 */
enum class RootEvidenceType {

    /**
     * Potential root binary.
     */
    ROOT_BINARY,

    /**
     * Known root-management application.
     */
    ROOT_PACKAGE,

    /**
     * Android build tags.
     */
    BUILD_TAGS,

    /**
     * Android build type.
     */
    BUILD_TYPE,

    /**
     * Test-key evidence.
     */
    TEST_KEYS,

    /**
     * Non-production/debug build evidence.
     */
    DEBUG_BUILD,

    /**
     * Android system property.
     */
    SYSTEM_PROPERTY,

    /**
     * Suspicious system property.
     */
    DANGEROUS_PROPERTY,

    /**
     * Protected filesystem path.
     */
    PROTECTED_PATH,

    /**
     * Filesystem mount configuration.
     */
    MOUNT_CONFIGURATION
}

/**
 * Severity of collected evidence.
 */
enum class RootEvidenceSeverity {

    /**
     * Contextual information only.
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
     * Extremely strong indicator.
     */
    CRITICAL
}
