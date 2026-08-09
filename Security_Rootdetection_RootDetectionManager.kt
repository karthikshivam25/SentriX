package com.sentrix.security.rootdetection

import android.content.Context
import android.os.Build
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * RootDetectionManager
 *
 * Enterprise-level coordinator responsible for detecting indicators
 * that an Android device may have elevated/root access.
 *
 * IMPORTANT:
 * Root detection is inherently heuristic.
 * No single local check should be treated as definitive proof of root.
 *
 * This manager therefore combines multiple independent indicators:
 *
 * 1. Known root-management applications
 * 2. Known root binaries
 * 3. Suspicious system properties
 * 4. Writable protected system locations
 * 5. Dangerous mount configuration
 * 6. Test-key / non-production build indicators
 *
 * The manager is intentionally kept independent from the UI layer.
 *
 * Architecture:
 *
 * UI
 *   ↓
 * UseCase
 *   ↓
 * RootDetectionManager
 *   ↓
 * Android system / filesystem checks
 *
 * Package:
 * com.sentrix.security.rootdetection
 */
class RootDetectionManager(
    private val context: Context
) {

    /**
     * Prevents repeated concurrent detection operations.
     *
     * AtomicBoolean is used instead of a normal Boolean because
     * security checks may potentially be triggered from multiple
     * threads.
     */
    private val detectionInProgress = AtomicBoolean(false)

    /**
     * Known locations where root-related binaries may exist.
     *
     * These are indicators only and should never independently
     * determine the final security state.
     */
    private val knownRootBinaryPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/su/bin",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU",
        "/system/xbin/daemonsu",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su"
    )

    /**
     * Known package names associated with root-management tools.
     *
     * Package presence is treated only as a signal because package
     * names can change and legitimate test environments may contain
     * development tools.
     */
    private val knownRootPackages = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.yellowes.su"
    )

    /**
     * Known dangerous system properties.
     *
     * These properties can provide useful signals in development,
     * engineering, or modified Android environments.
     */
    private val suspiciousProperties = listOf(
        "ro.debuggable" to "1",
        "ro.secure" to "0"
    )

    /**
     * Performs the complete root-detection process.
     *
     * @return RootDetectionResult containing:
     * - whether root indicators were found
     * - risk score
     * - individual detection signals
     * - device/build information
     */
    fun detectRoot(): RootDetectionResult {

        /**
         * Avoid unnecessarily running expensive checks concurrently.
         */
        if (!detectionInProgress.compareAndSet(false, true)) {
            return RootDetectionResult(
                isRootDetected = false,
                riskScore = 0,
                indicators = listOf(
                    RootDetectionIndicator(
                        type = RootIndicatorType.CHECK_IN_PROGRESS,
                        description = "Root detection is already running.",
                        severity = RootIndicatorSeverity.INFO
                    )
                ),
                buildTags = Build.TAGS,
                deviceModel = Build.MODEL,
                manufacturer = Build.MANUFACTURER
            )
        }

        return try {

            val indicators = mutableListOf<RootDetectionIndicator>()

            /**
             * Check for known root binaries.
             */
            if (hasKnownRootBinary()) {
                indicators += RootDetectionIndicator(
                    type = RootIndicatorType.ROOT_BINARY,
                    description = "A known root-related binary was found.",
                    severity = RootIndicatorSeverity.HIGH
                )
            }

            /**
             * Check for root-management packages.
             */
            if (hasKnownRootPackage()) {
                indicators += RootDetectionIndicator(
                    type = RootIndicatorType.ROOT_PACKAGE,
                    description = "A known root-management application was detected.",
                    severity = RootIndicatorSeverity.HIGH
                )
            }

            /**
             * Check Android build tags.
             *
             * Test-keys can indicate a non-production/custom build.
             * This is NOT proof of root.
             */
            if (hasTestKeys()) {
                indicators += RootDetectionIndicator(
                    type = RootIndicatorType.TEST_KEYS,
                    description = "The device appears to use test-keys.",
                    severity = RootIndicatorSeverity.MEDIUM
                )
            }

            /**
             * Check suspicious system properties.
             */
            indicators += detectSuspiciousProperties()

            /**
             * Check potentially writable protected locations.
             */
            if (hasWritableProtectedDirectory()) {
                indicators += RootDetectionIndicator(
                    type = RootIndicatorType.WRITABLE_SYSTEM,
                    description = "A protected system location appears writable.",
                    severity = RootIndicatorSeverity.HIGH
                )
            }

            /**
             * Check mount configuration for suspicious writable
             * system partitions.
             */
            if (hasSuspiciousMountConfiguration()) {
                indicators += RootDetectionIndicator(
                    type = RootIndicatorType.SUSPICIOUS_MOUNT,
                    description = "A protected Android partition appears writable.",
                    severity = RootIndicatorSeverity.HIGH
                )
            }

            /**
             * Calculate the overall risk score.
             */
            val riskScore = calculateRiskScore(indicators)

            /**
             * Root is considered detected when sufficiently strong
             * indicators are present.
             *
             * Medium-only signals should not automatically classify
             * the device as rooted.
             */
            val isRootDetected = indicators.any {
                it.severity == RootIndicatorSeverity.HIGH
            }

            RootDetectionResult(
                isRootDetected = isRootDetected,
                riskScore = riskScore,
                indicators = indicators,
                buildTags = Build.TAGS,
                deviceModel = Build.MODEL,
                manufacturer = Build.MANUFACTURER
            )

        } finally {
            detectionInProgress.set(false)
        }
    }

    /**
     * Checks whether known root binaries exist.
     *
     * File existence is used only as a signal.
     */
    private fun hasKnownRootBinary(): Boolean {

        return knownRootBinaryPaths.any { path ->
            try {
                File(path).exists()
            } catch (_: SecurityException) {
                false
            } catch (_: Exception) {
                false
            }
        }
    }

    /**
     * Checks whether a known root-management package is installed.
     *
     * Android package visibility restrictions can affect this check.
     * Therefore, failure to query a package does not mean the package
     * is absent.
     */
    private fun hasKnownRootPackage(): Boolean {

        val packageManager = context.packageManager

        return knownRootPackages.any { packageName ->

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
     * Test-keys may indicate an engineering/custom ROM.
     *
     * This is intentionally treated as a MEDIUM indicator because
     * test-keys alone do not prove that the device is rooted.
     */
    private fun hasTestKeys(): Boolean {

        return Build.TAGS?.contains("test-keys", ignoreCase = true) == true
    }

    /**
     * Reads selected Android system properties.
     *
     * Reflection is intentionally avoided where possible because
     * implementation details of Android system-property access may
     * vary between releases.
     *
     * In this implementation, the method safely attempts to invoke
     * the platform property mechanism and fails closed.
     */
    private fun detectSuspiciousProperties(): List<RootDetectionIndicator> {

        val indicators = mutableListOf<RootDetectionIndicator>()

        suspiciousProperties.forEach { (property, expectedValue) ->

            val actualValue = readSystemProperty(property)

            if (actualValue == expectedValue) {

                indicators += RootDetectionIndicator(
                    type = RootIndicatorType.SUSPICIOUS_PROPERTY,
                    description = "Suspicious system property detected: $property=$actualValue",
                    severity = RootIndicatorSeverity.MEDIUM
                )
            }
        }

        return indicators
    }

    /**
     * Safely reads an Android system property.
     *
     * This method intentionally does not expose property-access
     * exceptions to the application layer.
     */
    private fun readSystemProperty(property: String): String? {

        return try {

            val process = Runtime.getRuntime().exec(
                arrayOf(
                    "/system/bin/getprop",
                    property
                )
            )

            process.inputStream
                .bufferedReader()
                .use { reader ->
                    reader.readLine()?.trim()
                }

        } catch (_: Exception) {
            null
        }
    }

    /**
     * Attempts to determine whether protected Android directories
     * are writable.
     *
     * This is a heuristic check and may behave differently across
     * Android versions and OEM implementations.
     */
    private fun hasWritableProtectedDirectory(): Boolean {

        val protectedDirectories = listOf(
            File("/system"),
            File("/system/bin"),
            File("/system/xbin"),
            File("/vendor"),
            File("/product")
        )

        return protectedDirectories.any { directory ->

            try {
                directory.exists() && directory.canWrite()
            } catch (_: SecurityException) {
                false
            } catch (_: Exception) {
                false
            }
        }
    }

    /**
     * Checks /proc/mounts for suspicious writable system partitions.
     *
     * The check is intentionally conservative.
     */
    private fun hasSuspiciousMountConfiguration(): Boolean {

        return try {

            val mountsFile = File("/proc/mounts")

            if (!mountsFile.exists() || !mountsFile.canRead()) {
                return false
            }

            mountsFile.useLines { lines ->

                lines.any { line ->

                    val lowerLine = line.lowercase()

                    val protectedPartition =
                        lowerLine.contains(" /system ") ||
                        lowerLine.contains(" /vendor ") ||
                        lowerLine.contains(" /product ")

                    val writable =
                        lowerLine.contains(",rw") ||
                        lowerLine.contains(" rw,")

                    protectedPartition && writable
                }
            }

        } catch (_: SecurityException) {
            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Calculates a normalized root-risk score.
     *
     * Score range:
     *
     * 0 - 29   : LOW
     * 30 - 59  : MEDIUM
     * 60 - 79  : HIGH
     * 80 - 100 : CRITICAL
     */
    private fun calculateRiskScore(
        indicators: List<RootDetectionIndicator>
    ): Int {

        var score = 0

        indicators.forEach { indicator ->

            score += when (indicator.severity) {

                RootIndicatorSeverity.INFO -> 0

                RootIndicatorSeverity.LOW -> 10

                RootIndicatorSeverity.MEDIUM -> 25

                RootIndicatorSeverity.HIGH -> 40

                RootIndicatorSeverity.CRITICAL -> 60
            }
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Convenience method for consumers that only need a Boolean.
     */
    fun isDeviceRooted(): Boolean {
        return detectRoot().isRootDetected
    }

    /**
     * Returns only the calculated risk score.
     */
    fun getRootRiskScore(): Int {
        return detectRoot().riskScore
    }

    /**
     * Returns true when the manager is currently executing a
     * detection operation.
     */
    fun isDetectionInProgress(): Boolean {
        return detectionInProgress.get()
    }
}

/**
 * Complete result returned by RootDetectionManager.
 */
data class RootDetectionResult(

    /**
     * True when strong root indicators are detected.
     */
    val isRootDetected: Boolean,

    /**
     * Normalized risk score from 0 to 100.
     */
    val riskScore: Int,

    /**
     * Individual signals responsible for the result.
     */
    val indicators: List<RootDetectionIndicator>,

    /**
     * Android build tags.
     */
    val buildTags: String?,

    /**
     * Device model.
     */
    val deviceModel: String,

    /**
     * Device manufacturer.
     */
    val manufacturer: String
)

/**
 * Individual root-detection signal.
 */
data class RootDetectionIndicator(

    /**
     * Type of root indicator.
     */
    val type: RootIndicatorType,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Severity associated with the indicator.
     */
    val severity: RootIndicatorSeverity
)

/**
 * Root-detection signal categories.
 */
enum class RootIndicatorType {

    /**
     * A known root binary was found.
     */
    ROOT_BINARY,

    /**
     * A known root-management application was found.
     */
    ROOT_PACKAGE,

    /**
     * Device uses test-keys.
     */
    TEST_KEYS,

    /**
     * Suspicious Android system property detected.
     */
    SUSPICIOUS_PROPERTY,

    /**
     * Protected system location appears writable.
     */
    WRITABLE_SYSTEM,

    /**
     * Suspicious writable mount detected.
     */
    SUSPICIOUS_MOUNT,

    /**
     * Detection was already running.
     */
    CHECK_IN_PROGRESS
}

/**
 * Severity of an individual root indicator.
 */
enum class RootIndicatorSeverity {

    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
