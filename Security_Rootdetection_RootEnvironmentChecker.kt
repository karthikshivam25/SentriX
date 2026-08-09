package com.sentrix.security.rootdetection

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import android.os.Environment
import android.os.Process
import java.io.File

/**
 * RootEnvironmentChecker
 *
 * Performs environment-level checks that can provide additional
 * evidence about the security state of an Android device.
 *
 * This checker focuses on the runtime/device environment rather
 * than individual root binaries, packages, or commands.
 *
 * Responsibilities:
 *
 * - Inspect Android build characteristics.
 * - Inspect debugger/development indicators.
 * - Inspect application installation environment.
 * - Inspect selected filesystem characteristics.
 * - Inspect runtime identity.
 * - Inspect external-storage state.
 * - Collect structured environment evidence.
 *
 * This class does NOT:
 *
 * - execute root commands
 * - search for su binaries
 * - enumerate root-management applications
 * - determine the final rooted/not-rooted verdict
 * - calculate the complete SentriX device risk score
 *
 * Architecture:
 *
 * RootDetectionManager
 *        ↓
 * RootChecker
 *        ↓
 * RootEnvironmentChecker
 *        ↓
 * Android runtime/device environment
 *
 * IMPORTANT:
 *
 * Environment indicators are heuristic.
 * Development builds, emulators, test devices, and enterprise
 * devices can legitimately exhibit some of these characteristics.
 */
class RootEnvironmentChecker(
    private val context: Context
) {

    /**
     * Package/application information for the current SentriX app.
     */
    private val applicationInfo: ApplicationInfo =
        context.applicationInfo

    /**
     * Performs the complete environment scan.
     *
     * @return RootEnvironmentScanResult containing all collected
     * environment evidence.
     */
    fun scan(): RootEnvironmentScanResult {

        val evidence = mutableListOf<RootEnvironmentEvidence>()

        collectBuildEnvironmentEvidence(evidence)

        collectRuntimeEvidence(evidence)

        collectApplicationEnvironmentEvidence(evidence)

        collectFilesystemEnvironmentEvidence(evidence)

        collectExternalStorageEvidence(evidence)

        collectDebugEnvironmentEvidence(evidence)

        return RootEnvironmentScanResult(
            evidence = evidence,
            checksPerformed = CHECK_COUNT,
            scanCompleted = true,
            scanTimestamp = System.currentTimeMillis(),
            deviceModel = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            androidVersion = Build.VERSION.RELEASE,
            sdkVersion = Build.VERSION.SDK_INT
        )
    }

    /**
     * Collects Android build/environment characteristics.
     */
    private fun collectBuildEnvironmentEvidence(
        evidence: MutableList<RootEnvironmentEvidence>
    ) {

        /**
         * Build type.
         */
        val buildType = Build.TYPE

        if (!buildType.isNullOrBlank()) {

            evidence += RootEnvironmentEvidence(
                type = RootEnvironmentEvidenceType.BUILD_TYPE,
                source = "Build.TYPE",
                value = buildType,
                description = "Android build type detected.",
                severity = when {
                    buildType.equals("eng", true) ->
                        RootEnvironmentSeverity.MEDIUM

                    buildType.equals("userdebug", true) ->
                        RootEnvironmentSeverity.LOW

                    else ->
                        RootEnvironmentSeverity.INFO
                },
                confidence = 1.0
            )
        }

        /**
         * Build tags.
         */
        val buildTags = Build.TAGS

        if (!buildTags.isNullOrBlank()) {

            evidence += RootEnvironmentEvidence(
                type = RootEnvironmentEvidenceType.BUILD_TAGS,
                source = "Build.TAGS",
                value = buildTags,
                description = "Android build tags detected.",
                severity =
                    if (
                        buildTags.contains(
                            "test-keys",
                            ignoreCase = true
                        )
                    ) {
                        RootEnvironmentSeverity.MEDIUM
                    } else {
                        RootEnvironmentSeverity.INFO
                    },
                confidence = 0.90
            )
        }

        /**
         * Debuggable build flag.
         */
        val debuggable =
            (applicationInfo.flags and
                    ApplicationInfo.FLAG_DEBUGGABLE) != 0

        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.APPLICATION_DEBUGGABLE,
            source = "ApplicationInfo.FLAG_DEBUGGABLE",
            value = debuggable.toString(),
            description =
                if (debuggable) {
                    "The SentriX application is running as a debuggable build."
                } else {
                    "The SentriX application is not marked debuggable."
                },
            severity =
                if (debuggable) {
                    RootEnvironmentSeverity.LOW
                } else {
                    RootEnvironmentSeverity.INFO
                },
            confidence = 1.0
        )
    }

    /**
     * Collects process and runtime identity information.
     */
    private fun collectRuntimeEvidence(
        evidence: MutableList<RootEnvironmentEvidence>
    ) {

        /**
         * Android application process UID.
         *
         * Normal Android applications generally operate under
         * an application-specific non-root UID.
         */
        val processUid = Process.myUid()

        val uidSeverity =
            if (processUid == ROOT_UID) {
                RootEnvironmentSeverity.CRITICAL
            } else {
                RootEnvironmentSeverity.INFO
            }

        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.PROCESS_UID,
            source = "Process.myUid()",
            value = processUid.toString(),
            description =
                if (processUid == ROOT_UID) {
                    "Application process reports UID 0."
                } else {
                    "Application process is running under a non-root UID."
                },
            severity = uidSeverity,
            confidence = 1.0
        )

        /**
         * Process ID.
         *
         * This is primarily contextual evidence and should not
         * independently influence the root verdict.
         */
        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.PROCESS_ID,
            source = "Process.myPid()",
            value = Process.myPid().toString(),
            description = "Current application process ID.",
            severity = RootEnvironmentSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Collects information about how the application itself is
     * installed and configured.
     */
    private fun collectApplicationEnvironmentEvidence(
        evidence: MutableList<RootEnvironmentEvidence>
    ) {

        /**
         * Application source directory.
         */
        val sourceDir =
            applicationInfo.sourceDir

        if (!sourceDir.isNullOrBlank()) {

            evidence += RootEnvironmentEvidence(
                type = RootEnvironmentEvidenceType.APPLICATION_SOURCE,
                source = "ApplicationInfo.sourceDir",
                value = sourceDir,
                description =
                    "Application installation source path.",
                severity = RootEnvironmentSeverity.INFO,
                confidence = 1.0
            )
        }

        /**
         * Native library directory.
         */
        val nativeLibraryDir =
            applicationInfo.nativeLibraryDir

        if (!nativeLibraryDir.isNullOrBlank()) {

            evidence += RootEnvironmentEvidence(
                type = RootEnvironmentEvidenceType.NATIVE_LIBRARY_PATH,
                source = "ApplicationInfo.nativeLibraryDir",
                value = nativeLibraryDir,
                description =
                    "Application native-library directory.",
                severity = RootEnvironmentSeverity.INFO,
                confidence = 1.0
            )
        }

        /**
         * Whether the application is marked as a system app.
         *
         * A normal Play-distributed application should generally
         * not be a system application.
         */
        val isSystemApp =
            (applicationInfo.flags and
                    ApplicationInfo.FLAG_SYSTEM) != 0

        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.SYSTEM_APPLICATION,
            source = "ApplicationInfo.FLAG_SYSTEM",
            value = isSystemApp.toString(),
            description =
                if (isSystemApp) {
                    "Application is marked as a system application."
                } else {
                    "Application is not marked as a system application."
                },
            severity =
                if (isSystemApp) {
                    RootEnvironmentSeverity.LOW
                } else {
                    RootEnvironmentSeverity.INFO
                },
            confidence = 1.0
        )
    }

    /**
     * Collects filesystem/environment information.
     *
     * These checks intentionally avoid modifying the filesystem.
     */
    private fun collectFilesystemEnvironmentEvidence(
        evidence: MutableList<RootEnvironmentEvidence>
    ) {

        /**
         * Check whether the application-specific data directory
         * is available and writable.
         *
         * A writable application data directory is NORMAL and
         * therefore is informational only.
         */
        val dataDirectory =
            context.filesDir

        try {

            evidence += RootEnvironmentEvidence(
                type = RootEnvironmentEvidenceType.APP_DATA_DIRECTORY,
                source = dataDirectory.absolutePath,
                value =
                    if (dataDirectory.canWrite()) {
                        "writable"
                    } else {
                        "not_writable"
                    },
                description =
                    "Application-private data directory state.",
                severity = RootEnvironmentSeverity.INFO,
                confidence = 1.0
            )

        } catch (_: SecurityException) {

            evidence += RootEnvironmentEvidence(
                type = RootEnvironmentEvidenceType.APP_DATA_DIRECTORY,
                source = dataDirectory.absolutePath,
                value = "access_denied",
                description =
                    "Application data directory could not be inspected.",
                severity = RootEnvironmentSeverity.INFO,
                confidence = 0.50
            )
        }

        /**
         * Check selected Android environment paths.
         *
         * Their existence is contextual evidence only.
         */
        val environmentPaths = listOf(
            "/system",
            "/vendor",
            "/product",
            "/system_root"
        )

        environmentPaths.forEach { path ->

            try {

                val file = File(path)

                evidence += RootEnvironmentEvidence(
                    type = RootEnvironmentEvidenceType.SYSTEM_PATH,
                    source = path,
                    value =
                        when {
                            !file.exists() ->
                                "not_present"

                            file.canWrite() ->
                                "writable"

                            else ->
                                "present_not_writable"
                        },
                    description =
                        "System environment path state.",
                    severity =
                        if (
                            file.exists() &&
                            file.canWrite()
                        ) {
                            RootEnvironmentSeverity.HIGH
                        } else {
                            RootEnvironmentSeverity.INFO
                        },
                    confidence =
                        if (
                            file.exists() &&
                            file.canWrite()
                        ) {
                            0.80
                        } else {
                            1.0
                        }
                )

            } catch (_: SecurityException) {

                evidence += RootEnvironmentEvidence(
                    type = RootEnvironmentEvidenceType.SYSTEM_PATH,
                    source = path,
                    value = "access_denied",
                    description =
                        "System environment path could not be inspected.",
                    severity = RootEnvironmentSeverity.INFO,
                    confidence = 0.50
                )

            } catch (_: Exception) {

                evidence += RootEnvironmentEvidence(
                    type = RootEnvironmentEvidenceType.SYSTEM_PATH,
                    source = path,
                    value = "check_failed",
                    description =
                        "System environment path check failed.",
                    severity = RootEnvironmentSeverity.INFO,
                    confidence = 0.50
                )
            }
        }
    }

    /**
     * Collects external-storage environment information.
     *
     * External storage state alone is not a root indicator.
     */
    private fun collectExternalStorageEvidence(
        evidence: MutableList<RootEnvironmentEvidence>
    ) {

        val storageState =
            Environment.getExternalStorageState()

        val removable =
            Environment.isExternalStorageRemovable()

        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.EXTERNAL_STORAGE_STATE,
            source = "Environment.getExternalStorageState()",
            value = storageState,
            description =
                "External-storage state.",
            severity = RootEnvironmentSeverity.INFO,
            confidence = 1.0
        )

        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.EXTERNAL_STORAGE_REMOVABLE,
            source = "Environment.isExternalStorageRemovable()",
            value = removable.toString(),
            description =
                "Whether external storage is reported as removable.",
            severity = RootEnvironmentSeverity.INFO,
            confidence = 1.0
        )
    }

    /**
     * Collects debugging and instrumentation indicators.
     */
    private fun collectDebugEnvironmentEvidence(
        evidence: MutableList<RootEnvironmentEvidence>
    ) {

        /**
         * Debugger connection state.
         *
         * A debugger being attached is not proof of root, but can
         * be useful context for SentriX integrity analysis.
         */
        val debuggerConnected =
            Debug.isDebuggerConnected()

        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.DEBUGGER_CONNECTED,
            source = "Debug.isDebuggerConnected()",
            value = debuggerConnected.toString(),
            description =
                if (debuggerConnected) {
                    "A debugger is currently connected to the process."
                } else {
                    "No debugger is currently connected."
                },
            severity =
                if (debuggerConnected) {
                    RootEnvironmentSeverity.LOW
                } else {
                    RootEnvironmentSeverity.INFO
                },
            confidence = 1.0
        )

        /**
         * Wait-for-debugger state.
         */
        val waitingForDebugger =
            Debug.waitingForDebugger()

        evidence += RootEnvironmentEvidence(
            type = RootEnvironmentEvidenceType.WAITING_FOR_DEBUGGER,
            source = "Debug.waitingForDebugger()",
            value = waitingForDebugger.toString(),
            description =
                if (waitingForDebugger) {
                    "Application is waiting for a debugger."
                } else {
                    "Application is not waiting for a debugger."
                },
            severity =
                if (waitingForDebugger) {
                    RootEnvironmentSeverity.LOW
                } else {
                    RootEnvironmentSeverity.INFO
                },
            confidence = 1.0
        )
    }

    /**
     * Returns true when the current application process is
     * running under UID 0.
     *
     * This is a very strong local signal.
     */
    fun isProcessRunningAsRoot(): Boolean {

        return Process.myUid() == ROOT_UID
    }

    /**
     * Returns true when the current process has a debugger attached.
     *
     * This is contextual information and should not be interpreted
     * as evidence of root by itself.
     */
    fun isDebuggerConnected(): Boolean {

        return Debug.isDebuggerConnected()
    }

    /**
     * Returns true when the current application is marked
     * debuggable.
     */
    fun isApplicationDebuggable(): Boolean {

        return (
            applicationInfo.flags and
                ApplicationInfo.FLAG_DEBUGGABLE
            ) != 0
    }

    /**
     * Returns true when the current application is marked
     * as a system application.
     */
    fun isSystemApplication(): Boolean {

        return (
            applicationInfo.flags and
                ApplicationInfo.FLAG_SYSTEM
            ) != 0
    }

    /**
     * Returns a list of strong environment indicators.
     *
     * This does not mean the device is rooted.
     */
    fun getStrongEvidence(): List<RootEnvironmentEvidence> {

        return scan()
            .evidence
            .filter {
                it.severity == RootEnvironmentSeverity.HIGH ||
                        it.severity == RootEnvironmentSeverity.CRITICAL
            }
    }

    /**
     * Returns a list of all significant environment indicators.
     */
    fun getSignificantEvidence(): List<RootEnvironmentEvidence> {

        return scan()
            .evidence
            .filter {
                it.severity == RootEnvironmentSeverity.MEDIUM ||
                        it.severity == RootEnvironmentSeverity.HIGH ||
                        it.severity == RootEnvironmentSeverity.CRITICAL
            }
    }

    /**
     * Indicates whether strong environment evidence exists.
     */
    fun hasStrongEvidence(): Boolean {

        return getStrongEvidence().isNotEmpty()
    }

    companion object {

        /**
         * UID 0 represents the traditional root/superuser identity.
         */
        private const val ROOT_UID = 0

        /**
         * Number of logical environment check groups.
         */
        private const val CHECK_COUNT = 6
    }
}

/**
 * Complete environment-scan result.
 */
data class RootEnvironmentScanResult(

    /**
     * Collected environment evidence.
     */
    val evidence: List<RootEnvironmentEvidence>,

    /**
     * Number of logical check groups performed.
     */
    val checksPerformed: Int,

    /**
     * Indicates whether scanning completed normally.
     */
    val scanCompleted: Boolean,

    /**
     * Scan completion timestamp.
     */
    val scanTimestamp: Long,

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
) {

    /**
     * True when any significant environment evidence exists.
     */
    val hasSignificantEvidence: Boolean
        get() = evidence.any {
            it.severity == RootEnvironmentSeverity.MEDIUM ||
                    it.severity == RootEnvironmentSeverity.HIGH ||
                    it.severity == RootEnvironmentSeverity.CRITICAL
        }

    /**
     * Number of significant environment indicators.
     */
    val significantEvidenceCount: Int
        get() = evidence.count {
            it.severity == RootEnvironmentSeverity.MEDIUM ||
                    it.severity == RootEnvironmentSeverity.HIGH ||
                    it.severity == RootEnvironmentSeverity.CRITICAL
        }

    /**
     * Returns only high/critical evidence.
     */
    val strongEvidence: List<RootEnvironmentEvidence>
        get() = evidence.filter {
            it.severity == RootEnvironmentSeverity.HIGH ||
                    it.severity == RootEnvironmentSeverity.CRITICAL
        }
}

/**
 * Represents one environment-level root/integrity signal.
 */
data class RootEnvironmentEvidence(

    /**
     * Type of environment evidence.
     */
    val type: RootEnvironmentEvidenceType,

    /**
     * Source from which the observation originated.
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
     * Security significance of this observation.
     */
    val severity: RootEnvironmentSeverity,

    /**
     * Confidence that the observation itself is reliable/useful.
     *
     * This is NOT the probability that the device is rooted.
     */
    val confidence: Double
)

/**
 * Categories of environment-level evidence.
 */
enum class RootEnvironmentEvidenceType {

    /**
     * Android build type.
     */
    BUILD_TYPE,

    /**
     * Android build tags.
     */
    BUILD_TAGS,

    /**
     * Whether the application itself is debuggable.
     */
    APPLICATION_DEBUGGABLE,

    /**
     * UID under which the application process executes.
     */
    PROCESS_UID,

    /**
     * Current process ID.
     */
    PROCESS_ID,

    /**
     * Application source directory.
     */
    APPLICATION_SOURCE,

    /**
     * Native library directory.
     */
    NATIVE_LIBRARY_PATH,

    /**
     * Whether the application is a system application.
     */
    SYSTEM_APPLICATION,

    /**
     * Application-private data directory state.
     */
    APP_DATA_DIRECTORY,

    /**
     * Selected Android system path.
     */
    SYSTEM_PATH,

    /**
     * External storage state.
     */
    EXTERNAL_STORAGE_STATE,

    /**
     * External storage removability.
     */
    EXTERNAL_STORAGE_REMOVABLE,

    /**
     * Debugger connection state.
     */
    DEBUGGER_CONNECTED,

    /**
     * Waiting-for-debugger state.
     */
    WAITING_FOR_DEBUGGER
}

/**
 * Severity of environment-level evidence.
 */
enum class RootEnvironmentSeverity {

    /**
     * Normal/contextual information.
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
