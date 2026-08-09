package com.sentrix.security.rootdetection

import android.content.Context
import android.os.Build
import java.io.File

/**
 * RootChecker
 *
 * Performs low-level checks for indicators that an Android device
 * may have root / elevated privileges.
 *
 * This class deliberately does NOT decide the final security state.
 * It only collects technical evidence.
 *
 * Architecture:
 *
 * RootDetectionService
 *          ↓
 * RootDetectionManager
 *          ↓
 * RootChecker
 *          ↓
 * ┌─────────────────────────────┐
 * │ Binary checks               │
 * │ Root package checks         │
 * │ System property checks      │
 * │ Build checks                │
 * │ Protected path checks       │
 * │ Mount checks                │
 * └─────────────────────────────┘
 *
 * IMPORTANT:
 * Root detection is heuristic. A positive indicator does not
 * necessarily prove that a device is rooted, and absence of
 * indicators does not guarantee that a device is secure.
 */
class RootChecker(
    private val context: Context
) {

    /**
     * Known locations where the `su` binary or related root
     * components may exist.
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
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su"
    )

    /**
     * Known root-management package names.
     *
     * These are indicators only. Package visibility restrictions
     * may affect package detection on newer Android versions.
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
     * Protected Android filesystem locations.
     */
    private val protectedPaths = listOf(
        "/system",
        "/system/bin",
        "/system/xbin",
        "/vendor",
        "/product"
    )

    /**
     * Checks all available root indicators.
     *
     * @return RootCheckReport containing every detected signal.
     */
    fun performChecks(): RootCheckReport {

        val indicators = mutableListOf<RootCheckIndicator>()

        if (checkForSuBinary()) {
            indicators += RootCheckIndicator(
                type = RootCheckType.SU_BINARY,
                description = "A possible su/root binary was detected.",
                severity = RootCheckSeverity.HIGH
            )
        }

        if (checkForRootPackages()) {
            indicators += RootCheckIndicator(
                type = RootCheckType.ROOT_PACKAGE,
                description = "A known root-management package was detected.",
                severity = RootCheckSeverity.HIGH
            )
        }

        if (checkForTestKeys()) {
            indicators += RootCheckIndicator(
                type = RootCheckType.TEST_KEYS,
                description = "The device build contains test-keys.",
                severity = RootCheckSeverity.MEDIUM
            )
        }

        if (checkForDangerousProperties()) {
            indicators += RootCheckIndicator(
                type = RootCheckType.DANGEROUS_PROPERTY,
                description = "Suspicious Android system properties were detected.",
                severity = RootCheckSeverity.MEDIUM
            )
        }

        if (checkProtectedPathsWritable()) {
            indicators += RootCheckIndicator(
                type = RootCheckType.WRITABLE_PROTECTED_PATH,
                description = "A protected Android path appears writable.",
                severity = RootCheckSeverity.HIGH
            )
        }

        if (checkSuspiciousMounts()) {
            indicators += RootCheckIndicator(
                type = RootCheckType.SUSPICIOUS_MOUNT,
                description = "A protected filesystem appears to be mounted writable.",
                severity = RootCheckSeverity.HIGH
            )
        }

        return RootCheckReport(
            indicators = indicators,
            checksPerformed = CHECK_COUNT,
            deviceModel = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            androidVersion = Build.VERSION.RELEASE,
            sdkVersion = Build.VERSION.SDK_INT
        )
    }

    /**
     * Checks for known `su` binary locations.
     *
     * File existence is treated only as evidence.
     */
    fun checkForSuBinary(): Boolean {

        return rootBinaryPaths.any { path ->
            fileExistsSafely(path)
        }
    }

    /**
     * Checks whether known root-management applications are installed.
     */
    fun checkForRootPackages(): Boolean {

        val packageManager = context.packageManager

        return rootManagementPackages.any { packageName ->

            try {

                packageManager.getPackageInfo(
                    packageName,
                    0
                )

                true

            } catch (_: Exception) {

                false
            }
        }
    }

    /**
     * Checks whether the Android build uses test-keys.
     *
     * Test-keys are not proof of root and therefore produce only
     * a medium-severity signal.
     */
    fun checkForTestKeys(): Boolean {

        return Build.TAGS
            ?.contains(
                "test-keys",
                ignoreCase = true
            )
            ?: false
    }

    /**
     * Checks suspicious Android system properties.
     *
     * Examples:
     *
     * ro.debuggable=1
     * ro.secure=0
     *
     * These values can occur in development or engineering builds,
     * so they should not independently classify a device as rooted.
     */
    fun checkForDangerousProperties(): Boolean {

        val debuggable = readSystemProperty(
            "ro.debuggable"
        )

        val secure = readSystemProperty(
            "ro.secure"
        )

        return debuggable == "1" || secure == "0"
    }

    /**
     * Checks whether protected Android directories report
     * themselves as writable.
     *
     * The result can vary between Android releases and OEM devices,
     * so this is treated as a heuristic.
     */
    fun checkProtectedPathsWritable(): Boolean {

        return protectedPaths.any { path ->

            try {

                val file = File(path)

                file.exists() && file.canWrite()

            } catch (_: SecurityException) {

                false

            } catch (_: Exception) {

                false
            }
        }
    }

    /**
     * Checks /proc/mounts for protected partitions that appear
     * to be mounted with read/write permissions.
     */
    fun checkSuspiciousMounts(): Boolean {

        return try {

            val mountsFile = File("/proc/mounts")

            if (!mountsFile.exists() || !mountsFile.canRead()) {
                return false
            }

            mountsFile.useLines { lines ->

                lines.any { line ->

                    isSuspiciousMountLine(line)
                }
            }

        } catch (_:SecurityException) {

            false

        } catch (_:Exception) {

            false
        }
    }

    /**
     * Determines whether a single /proc/mounts line represents
     * a potentially suspicious writable protected filesystem.
     */
    private fun isSuspiciousMountLine(
        line: String
    ): Boolean {

        val normalizedLine = line.lowercase()

        val protectedMount =

            normalizedLine.contains(" /system ") ||
            normalizedLine.contains(" /vendor ") ||
            normalizedLine.contains(" /product ") ||
            normalizedLine.contains(" /system_root ")

        val writableMount =

            normalizedLine.contains(",rw") ||
            normalizedLine.contains(" rw,") ||
            normalizedLine.endsWith(",rw")

        return protectedMount && writableMount
    }

    /**
     * Safely checks whether a file exists.
     */
    private fun fileExistsSafely(
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
     *
     * Failure to read a property is deliberately interpreted as
     * "no evidence", rather than as evidence of root.
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
     * Performs only the strongest local checks.
     *
     * Useful when SentriX needs a lightweight integrity check
     * instead of the complete detection process.
     */
    fun hasStrongRootIndicator(): Boolean {

        return checkForSuBinary() ||
                checkForRootPackages() ||
                checkProtectedPathsWritable() ||
                checkSuspiciousMounts()
    }

    /**
     * Returns true if any root indicator was found.
     */
    fun hasAnyRootIndicator(): Boolean {

        return performChecks()
            .indicators
            .isNotEmpty()
    }

    /**
     * Returns the number of detection signals currently found.
     */
    fun getIndicatorCount(): Int {

        return performChecks()
            .indicators
            .size
    }

    companion object {

        /**
         * Number of logical checks executed by performChecks().
         */
        private const val CHECK_COUNT = 6
    }
}

/**
 * Complete low-level root-check report.
 *
 * This object contains evidence collected by RootChecker.
 * It should not be confused with the final SentriX security report.
 */
data class RootCheckReport(

    /**
     * Individual indicators found during the scan.
     */
    val indicators: List<RootCheckIndicator>,

    /**
     * Number of logical checks performed.
     */
    val checksPerformed: Int,

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
     * Android SDK/API level.
     */
    val sdkVersion: Int
)

/**
 * Represents one piece of root-detection evidence.
 */
data class RootCheckIndicator(

    /**
     * Type of evidence.
     */
    val type: RootCheckType,

    /**
     * Human-readable description.
     */
    val description: String,

    /**
     * Severity assigned to the evidence.
     */
    val severity: RootCheckSeverity
)

/**
 * Root-check evidence categories.
 */
enum class RootCheckType {

    /**
     * Possible su binary detected.
     */
    SU_BINARY,

    /**
     * Known root-management package detected.
     */
    ROOT_PACKAGE,

    /**
     * Test-keys detected.
     */
    TEST_KEYS,

    /**
     * Suspicious Android property detected.
     */
    DANGEROUS_PROPERTY,

    /**
     * Protected filesystem path appears writable.
     */
    WRITABLE_PROTECTED_PATH,

    /**
     * Protected mount appears writable.
     */
    SUSPICIOUS_MOUNT
}

/**
 * Severity associated with root-check evidence.
 */
enum class RootCheckSeverity {

    /**
     * Informational signal.
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
     * Extremely strong signal.
     */
    CRITICAL
}
