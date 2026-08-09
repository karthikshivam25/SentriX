package com.sentrix.security.rootdetection

import android.os.Build

/**
 * RootPropertyChecker
 *
 * Analyzes Android system properties that can provide indicators
 * of a modified, debuggable, engineering, or potentially insecure
 * Android environment.
 *
 * Responsibilities:
 *
 * - Read selected Android system properties.
 * - Detect suspicious property configurations.
 * - Collect structured property evidence.
 * - Safely handle property-access failures.
 *
 * This class does NOT:
 *
 * - inspect root binaries
 * - inspect installed packages
 * - inspect mount points
 * - determine the final root verdict
 * - calculate the overall device risk score
 *
 * Architecture:
 *
 * RootDetectionManager
 *        ↓
 * RootChecker
 *        ↓
 * RootPropertyChecker
 *        ↓
 * Android system properties
 *
 * IMPORTANT:
 *
 * System properties are heuristic signals.
 * A suspicious property does not independently prove that a device
 * is rooted.
 */
class RootPropertyChecker {

    /**
     * Properties relevant to root/integrity analysis.
     */
    private val monitoredProperties = listOf(
        "ro.debuggable",
        "ro.secure",
        "ro.build.tags",
        "ro.build.type",
        "ro.build.selinux",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state"
    )

    /**
     * Known property values that may represent a development,
     * insecure, unlocked, or otherwise unusual environment.
     *
     * These are signals, not definitive root indicators.
     */
    private val suspiciousPropertyValues = mapOf(

        "ro.debuggable" to setOf(
            "1"
        ),

        "ro.secure" to setOf(
            "0"
        ),

        "ro.build.type" to setOf(
            "eng",
            "userdebug"
        ),

        "ro.build.tags" to setOf(
            "test-keys"
        ),

        "ro.boot.verifiedbootstate" to setOf(
            "orange"
        ),

        "ro.boot.flash.locked" to setOf(
            "0"
        ),

        "ro.boot.vbmeta.device_state" to setOf(
            "unlocked"
        )
    )

    /**
     * Performs a complete system-property scan.
     *
     * @return RootPropertyScanResult containing observed and
     * suspicious properties.
     */
    fun scan(): RootPropertyScanResult {

        val evidence = mutableListOf<RootPropertyEvidence>()

        monitoredProperties.forEach { propertyName ->

            val value = readProperty(propertyName)

            if (value != null) {

                val severity =
                    determineSeverity(
                        propertyName = propertyName,
                        value = value
                    )

                val confidence =
                    determineConfidence(
                        propertyName = propertyName,
                        value = value
                    )

                evidence += RootPropertyEvidence(
                    propertyName = propertyName,
                    value = value,
                    severity = severity,
                    confidence = confidence,
                    suspicious =
                        severity != RootPropertySeverity.INFO
                )
            }
        }

        return RootPropertyScanResult(
            properties = evidence,
            propertiesChecked = monitoredProperties.size,
            scanCompleted = true,
            scanTimestamp = System.currentTimeMillis(),
            androidVersion = Build.VERSION.RELEASE,
            sdkVersion = Build.VERSION.SDK_INT
        )
    }

    /**
     * Reads one Android system property.
     *
     * @param propertyName Property name to inspect.
     *
     * @return Property value or null if unavailable.
     */
    fun getProperty(
        propertyName: String
    ): String? {

        if (propertyName.isBlank()) {
            return null
        }

        return readProperty(propertyName)
    }

    /**
     * Checks whether a property has a specific value.
     */
    fun propertyEquals(
        propertyName: String,
        expectedValue: String
    ): Boolean {

        val actualValue =
            readProperty(propertyName)
                ?: return false

        return actualValue.equals(
            expectedValue,
            ignoreCase = true
        )
    }

    /**
     * Checks whether the device appears to be using a
     * debuggable Android configuration.
     */
    fun isDebuggableBuild(): Boolean {

        return propertyEquals(
            propertyName = "ro.debuggable",
            expectedValue = "1"
        )
    }

    /**
     * Checks whether the Android build appears to use test-keys.
     */
    fun usesTestKeys(): Boolean {

        val buildTags =
            readProperty("ro.build.tags")

        return buildTags
            ?.split(
                ",",
                " ",
                ";"
            )
            ?.any {
                it.equals(
                    "test-keys",
                    ignoreCase = true
                )
            }
            ?: false
    }

    /**
     * Checks whether the build type indicates an engineering
     * or user-debug build.
     *
     * These build types are not automatically malicious.
     */
    fun isNonProductionBuild(): Boolean {

        val buildType =
            readProperty("ro.build.type")
                ?.lowercase()
                ?: return false

        return buildType == "eng" ||
                buildType == "userdebug"
    }

    /**
     * Checks whether verified boot reports an unusual state.
     *
     * "orange" generally indicates an unlocked bootloader state.
     *
     * This is not equivalent to root.
     */
    fun hasUnusualVerifiedBootState(): Boolean {

        val state =
            readProperty(
                "ro.boot.verifiedbootstate"
            )?.lowercase()
                ?: return false

        return state == "orange"
    }

    /**
     * Checks whether the bootloader appears unlocked based on
     * the available boot property.
     */
    fun hasUnlockedBootloader(): Boolean {

        val flashLocked =
            readProperty(
                "ro.boot.flash.locked"
            )

        val deviceState =
            readProperty(
                "ro.boot.vbmeta.device_state"
            )?.lowercase()

        return flashLocked == "0" ||
                deviceState == "unlocked"
    }

    /**
     * Returns all properties classified as suspicious.
     */
    fun getSuspiciousProperties(): List<RootPropertyEvidence> {

        return scan()
            .properties
            .filter {
                it.suspicious
            }
    }

    /**
     * Returns only high-severity property evidence.
     */
    fun getHighSeverityProperties(): List<RootPropertyEvidence> {

        return scan()
            .properties
            .filter {
                it.severity == RootPropertySeverity.HIGH ||
                        it.severity == RootPropertySeverity.CRITICAL
            }
    }

    /**
     * Returns true if any suspicious property configuration
     * was observed.
     */
    fun hasSuspiciousProperties(): Boolean {

        return getSuspiciousProperties()
            .isNotEmpty()
    }

    /**
     * Determines the severity of a property observation.
     *
     * The severity intentionally varies because some properties
     * are stronger integrity indicators than others.
     */
    private fun determineSeverity(
        propertyName: String,
        value: String
    ): RootPropertySeverity {

        val normalizedValue =
            value.trim().lowercase()

        return when (propertyName) {

            "ro.debuggable" -> {

                if (normalizedValue == "1") {
                    RootPropertySeverity.MEDIUM
                } else {
                    RootPropertySeverity.INFO
                }
            }

            "ro.secure" -> {

                if (normalizedValue == "0") {
                    RootPropertySeverity.MEDIUM
                } else {
                    RootPropertySeverity.INFO
                }
            }

            "ro.build.tags" -> {

                if (
                    normalizedValue
                        .split(",", " ", ";")
                        .contains("test-keys")
                ) {
                    RootPropertySeverity.MEDIUM
                } else {
                    RootPropertySeverity.INFO
                }
            }

            "ro.build.type" -> {

                when (normalizedValue) {

                    "eng" ->
                        RootPropertySeverity.MEDIUM

                    "userdebug" ->
                        RootPropertySeverity.LOW

                    else ->
                        RootPropertySeverity.INFO
                }
            }

            "ro.boot.verifiedbootstate" -> {

                when (normalizedValue) {

                    "orange" ->
                        RootPropertySeverity.HIGH

                    "red" ->
                        RootPropertySeverity.CRITICAL

                    else ->
                        RootPropertySeverity.INFO
                }
            }

            "ro.boot.flash.locked" -> {

                if (normalizedValue == "0") {
                    RootPropertySeverity.HIGH
                } else {
                    RootPropertySeverity.INFO
                }
            }

            "ro.boot.vbmeta.device_state" -> {

                if (normalizedValue == "unlocked") {
                    RootPropertySeverity.HIGH
                } else {
                    RootPropertySeverity.INFO
                }
            }

            else ->
                RootPropertySeverity.INFO
        }
    }

    /**
     * Determines confidence for an observed property.
     *
     * Confidence describes how useful the observation is as a
     * security signal. It does NOT represent probability that
     * the device is rooted.
     */
    private fun determineConfidence(
        propertyName: String,
        value: String
    ): Double {

        val normalizedValue =
            value.trim().lowercase()

        return when {

            propertyName == "ro.boot.verifiedbootstate" &&
                    normalizedValue == "red" ->
                0.95

            propertyName == "ro.boot.flash.locked" &&
                    normalizedValue == "0" ->
                0.90

            propertyName == "ro.boot.vbmeta.device_state" &&
                    normalizedValue == "unlocked" ->
                0.90

            propertyName == "ro.boot.verifiedbootstate" &&
                    normalizedValue == "orange" ->
                0.85

            propertyName == "ro.secure" &&
                    normalizedValue == "0" ->
                0.75

            propertyName == "ro.debuggable" &&
                    normalizedValue == "1" ->
                0.65

            propertyName == "ro.build.tags" &&
                    normalizedValue.contains("test-keys") ->
                0.70

            else ->
                1.0
        }
    }

    /**
     * Safely reads a system property using Android's getprop
     * command.
     *
     * Failure is represented by null rather than being treated
     * as suspicious evidence.
     */
    private fun readProperty(
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
     * Returns the configured property names.
     */
    fun getMonitoredProperties(): List<String> {

        return monitoredProperties.toList()
    }

    /**
     * Returns the suspicious-value configuration.
     *
     * A defensive copy is returned so callers cannot modify the
     * internal configuration.
     */
    fun getSuspiciousPropertyValues(): Map<String, Set<String>> {

        return suspiciousPropertyValues.mapValues {
            it.value.toSet()
        }
    }
}

/**
 * Complete result of the root-property scan.
 */
data class RootPropertyScanResult(

    /**
     * Properties observed during the scan.
     */
    val properties: List<RootPropertyEvidence>,

    /**
     * Number of properties that were checked.
     */
    val propertiesChecked: Int,

    /**
     * Whether the scan completed.
     */
    val scanCompleted: Boolean,

    /**
     * Scan completion timestamp.
     */
    val scanTimestamp: Long,

    /**
     * Android release version.
     */
    val androidVersion: String,

    /**
     * Android API level.
     */
    val sdkVersion: Int
) {

    /**
     * True if at least one suspicious property was observed.
     */
    val hasSuspiciousProperties: Boolean
        get() = properties.any {
            it.suspicious
        }

    /**
     * Number of suspicious properties.
     */
    val suspiciousPropertyCount: Int
        get() = properties.count {
            it.suspicious
        }
}

/**
 * Structured evidence representing one Android system property.
 */
data class RootPropertyEvidence(

    /**
     * Property name.
     */
    val propertyName: String,

    /**
     * Observed property value.
     */
    val value: String,

    /**
     * Security significance of this observation.
     */
    val severity: RootPropertySeverity,

    /**
     * Confidence in the usefulness of this observation.
     *
     * This is NOT the probability that the device is rooted.
     */
    val confidence: Double,

    /**
     * Whether the property was classified as suspicious.
     */
    val suspicious: Boolean
)

/**
 * Severity associated with a system-property observation.
 */
enum class RootPropertySeverity {

    /**
     * Normal/contextual information.
     */
    INFO,

    /**
     * Weak integrity indicator.
     */
    LOW,

    /**
     * Moderate integrity indicator.
     */
    MEDIUM,

    /**
     * Strong integrity indicator.
     */
    HIGH,

    /**
     * Extremely strong integrity indicator.
     */
    CRITICAL
}
