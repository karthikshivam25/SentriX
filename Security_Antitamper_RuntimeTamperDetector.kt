package com.sentrix.security.antitamper

import android.app.Application
import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.Process
import java.io.File

/**
 * RuntimeTamperDetector
 *
 * Detects runtime-level indicators that may suggest that the
 * application's execution environment has been modified.
 *
 * Responsibilities:
 *
 * - Inspect application class-loader configuration.
 * - Inspect runtime class paths.
 * - Inspect application native library paths.
 * - Inspect process identity.
 * - Inspect runtime debugging state.
 * - Inspect application process state.
 * - Inspect unexpected runtime directories.
 * - Collect runtime integrity evidence.
 *
 * This class does NOT:
 *
 * - terminate suspicious processes
 * - kill the application
 * - modify the class loader
 * - unload libraries
 * - execute arbitrary commands
 * - perform final anti-tamper scoring
 *
 * Runtime observations are signals rather than absolute proof of
 * malicious tampering. The AntiTamperValidator should correlate
 * them with:
 *
 * - SignatureTamperDetector
 * - CodeTamperDetector
 * - ResourceTamperDetector
 * - PackageTamperDetector
 * - Hook/Debugger detectors
 *
 * Architecture:
 *
 * AntiTamperManager
 *        ↓
 * RuntimeTamperDetector
 *        ↓
 * RuntimeTamperResult
 *        ↓
 * AntiTamperEvidenceCollector
 *        ↓
 * AntiTamperValidator
 */
class RuntimeTamperDetector(
    private val context: Context,
    private val configuration: RuntimeTamperConfiguration =
        RuntimeTamperConfiguration()
) {

    /**
     * Application package name.
     */
    private val packageName: String =
        context.packageName

    /**
     * Performs the complete runtime integrity assessment.
     */
    fun detect(): RuntimeTamperResult {

        val evidence =
            mutableListOf<RuntimeTamperEvidence>()

        var checksPerformed = 0
        var checksSuccessful = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * 1. Process identity
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectProcessIdentity(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "ProcessIdentity"
            )
        }

        /**
         * ---------------------------------------------------------
         * 2. Class-loader integrity
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectClassLoaderEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "ClassLoader"
            )
        }

        /**
         * ---------------------------------------------------------
         * 3. Runtime class path
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectRuntimeClassPathEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "RuntimeClassPath"
            )
        }

        /**
         * ---------------------------------------------------------
         * 4. Native library path
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectNativeLibraryPathEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "NativeLibraryPath"
            )
        }

        /**
         * ---------------------------------------------------------
         * 5. Debug state
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectDebugStateEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "DebugState"
            )
        }

        /**
         * ---------------------------------------------------------
         * 6. Application process state
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectApplicationStateEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "ApplicationState"
            )
        }

        /**
         * ---------------------------------------------------------
         * 7. Runtime directory inspection
         * ---------------------------------------------------------
         */
        try {

            checksPerformed++

            collectRuntimeDirectoryEvidence(
                evidence
            )

            checksSuccessful++

        } catch (_: Exception) {

            checksFailed++

            evidence += failureEvidence(
                source = "RuntimeDirectories"
            )
        }

        /**
         * ---------------------------------------------------------
         * Determine status
         * ---------------------------------------------------------
         */
        val status =
            determineStatus(
                evidence = evidence,
                checksFailed = checksFailed
            )

        return RuntimeTamperResult(
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
     * Collects process identity information.
     */
    private fun collectProcessIdentity(
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        val pid =
            Process.myPid()

        val uid =
            Process.myUid()

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.PROCESS_ID,
            source = "Process",
            description =
                "Current application process identifier.",
            value = pid.toString(),
            severity = RuntimeTamperSeverity.INFO,
            confidence = 1.0
        )

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.PROCESS_UID,
            source = "Process",
            description =
                "UID associated with the current application process.",
            value = uid.toString(),
            severity = RuntimeTamperSeverity.INFO,
            confidence = 1.0
        )

        val processName =
            getCurrentProcessName()

        if (!processName.isNullOrBlank()) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.PROCESS_NAME,
                source = "Process",
                description =
                    "Current application process name.",
                value = processName,
                severity = RuntimeTamperSeverity.INFO,
                confidence = 1.0
            )

            val expectedProcessName =
                configuration.expectedProcessName

            if (
                !expectedProcessName.isNullOrBlank()
            ) {

                if (
                    processName ==
                    expectedProcessName
                ) {

                    evidence += RuntimeTamperEvidence(
                        type =
                            RuntimeTamperEvidenceType.PROCESS_NAME_MATCH,
                        source = "Process",
                        description =
                            "Current process name matches trusted configuration.",
                        value = processName,
                        expectedValue =
                            expectedProcessName,
                        severity = RuntimeTamperSeverity.INFO,
                        confidence = 1.0
                    )

                } else {

                    evidence += RuntimeTamperEvidence(
                        type =
                            RuntimeTamperEvidenceType.PROCESS_NAME_MISMATCH,
                        source = "Process",
                        description =
                            "Current process name differs from trusted configuration.",
                        value = processName,
                        expectedValue =
                            expectedProcessName,
                        severity = RuntimeTamperSeverity.HIGH,
                        confidence = 0.90
                    )
                }
            }
        }
    }

    /**
     * Inspects the application's class loader.
     *
     * Unexpected class-loader configurations can sometimes be
     * associated with runtime instrumentation.
     *
     * This check is intentionally conservative because legitimate
     * frameworks may also use custom class loaders.
     */
    private fun collectClassLoaderEvidence(
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        val classLoader =
            context.classLoader

        val classLoaderName =
            classLoader::class.java.name

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.CLASS_LOADER,
            source = "Context.classLoader",
            description =
                "Runtime class-loader implementation.",
            value = classLoaderName,
            severity = RuntimeTamperSeverity.INFO,
            confidence = 1.0
        )

        val classLoaderClassName =
            configuration.expectedClassLoaderClassName

        if (
            !classLoaderClassName.isNullOrBlank()
        ) {

            val matches =
                classLoaderName ==
                        classLoaderClassName

            evidence += RuntimeTamperEvidence(
                type =
                    if (matches) {
                        RuntimeTamperEvidenceType.CLASS_LOADER_MATCH
                    } else {
                        RuntimeTamperEvidenceType.CLASS_LOADER_MISMATCH
                    },
                source = "Context.classLoader",
                description =
                    if (matches) {
                        "Runtime class loader matches trusted configuration."
                    } else {
                        "Runtime class loader differs from trusted configuration."
                    },
                value = classLoaderName,
                expectedValue =
                    classLoaderClassName,
                severity =
                    if (matches) {
                        RuntimeTamperSeverity.INFO
                    } else {
                        RuntimeTamperSeverity.MEDIUM
                    },
                confidence = 0.80
            )
        }

        /**
         * Parent class-loader information.
         */
        val parent =
            classLoader.parent

        if (parent != null) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.CLASS_LOADER_PARENT,
                source = "ClassLoader.parent",
                description =
                    "Parent class-loader implementation.",
                value =
                    parent::class.java.name,
                severity = RuntimeTamperSeverity.INFO,
                confidence = 1.0
            )
        }
    }

    /**
     * Collects runtime class-path information.
     *
     * Android runtime environments differ by OS version, so this
     * check records observable paths rather than assuming a fixed
     * class-loader implementation.
     */
    private fun collectRuntimeClassPathEvidence(
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        val javaClassPath =
            System.getProperty(
                "java.class.path"
            )

        if (!javaClassPath.isNullOrBlank()) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.JAVA_CLASS_PATH,
                source = "System.getProperty",
                description =
                    "Runtime Java class path.",
                value = javaClassPath,
                severity = RuntimeTamperSeverity.INFO,
                confidence = 0.90
            )
        }

        val javaLibraryPath =
            System.getProperty(
                "java.library.path"
            )

        if (!javaLibraryPath.isNullOrBlank()) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.JAVA_LIBRARY_PATH,
                source = "System.getProperty",
                description =
                    "Runtime native library search path.",
                value = javaLibraryPath,
                severity = RuntimeTamperSeverity.INFO,
                confidence = 0.90
            )
        }

        /**
         * Compare configured unexpected class-path fragments.
         */
        configuration
            .suspiciousClassPathFragments
            .forEach { fragment ->

                if (
                    !javaClassPath.isNullOrBlank() &&
                    javaClassPath.contains(
                        fragment,
                        ignoreCase = true
                    )
                ) {

                    evidence += RuntimeTamperEvidence(
                        type =
                            RuntimeTamperEvidenceType.SUSPICIOUS_CLASS_PATH,
                        source = "java.class.path",
                        description =
                            "Configured suspicious class-path fragment was observed.",
                        value = fragment,
                        severity = RuntimeTamperSeverity.HIGH,
                        confidence = 0.80
                    )
                }
            }
    }

    /**
     * Inspects native library directories.
     */
    private fun collectNativeLibraryPathEvidence(
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        val nativeLibraryDir =
            context.applicationInfo.nativeLibraryDir

        if (
            nativeLibraryDir.isNullOrBlank()
        ) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.NATIVE_LIBRARY_PATH_UNAVAILABLE,
                source = "ApplicationInfo.nativeLibraryDir",
                description =
                    "Application native library directory is unavailable.",
                severity = RuntimeTamperSeverity.MEDIUM,
                confidence = 0.60
            )

            return
        }

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.NATIVE_LIBRARY_PATH,
            source = "ApplicationInfo.nativeLibraryDir",
            description =
                "Application native library directory.",
            value = nativeLibraryDir,
            severity = RuntimeTamperSeverity.INFO,
            confidence = 1.0
        )

        val directory =
            File(nativeLibraryDir)

        if (!directory.exists()) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.NATIVE_LIBRARY_DIRECTORY_MISSING,
                source = "File.exists",
                description =
                    "Configured native library directory does not exist.",
                value = nativeLibraryDir,
                severity = RuntimeTamperSeverity.MEDIUM,
                confidence = 0.80
            )

            return
        }

        if (!directory.isDirectory) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.NATIVE_LIBRARY_PATH_INVALID,
                source = "File.isDirectory",
                description =
                    "Native library path is not a directory.",
                value = nativeLibraryDir,
                severity = RuntimeTamperSeverity.MEDIUM,
                confidence = 0.80
            )
        }
    }

    /**
     * Collects Android runtime debugging state.
     *
     * This is intentionally an observation rather than a direct
     * tampering verdict.
     */
    private fun collectDebugStateEvidence(
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        val debuggerConnected =
            Debug.isDebuggerConnected()

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.DEBUGGER_CONNECTED,
            source = "Debug.isDebuggerConnected",
            description =
                if (debuggerConnected) {
                    "A debugger is currently connected to the process."
                } else {
                    "No debugger is currently reported as connected."
                },
            value =
                debuggerConnected.toString(),
            severity =
                if (debuggerConnected) {
                    RuntimeTamperSeverity.HIGH
                } else {
                    RuntimeTamperSeverity.INFO
                },
            confidence = 0.95
        )

        val waitingForDebugger =
            Debug.waitingForDebugger()

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.WAITING_FOR_DEBUGGER,
            source = "Debug.waitingForDebugger",
            description =
                if (waitingForDebugger) {
                    "The process is waiting for a debugger."
                } else {
                    "The process is not waiting for a debugger."
                },
            value =
                waitingForDebugger.toString(),
            severity =
                if (waitingForDebugger) {
                    RuntimeTamperSeverity.HIGH
                } else {
                    RuntimeTamperSeverity.INFO
                },
            confidence = 0.95
        )
    }

    /**
     * Collects application-level runtime state.
     */
    private fun collectApplicationStateEvidence(
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        val application =
            context.applicationContext

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.APPLICATION_CONTEXT,
            source = "Context.applicationContext",
            description =
                "Application context implementation.",
            value =
                application::class.java.name,
            severity = RuntimeTamperSeverity.INFO,
            confidence = 1.0
        )

        val applicationInfo =
            application.applicationInfo

        evidence += RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.APPLICATION_SOURCE_DIRECTORY,
            source = "ApplicationInfo.sourceDir",
            description =
                "Application source directory visible at runtime.",
            value =
                applicationInfo.sourceDir,
            severity = RuntimeTamperSeverity.INFO,
            confidence = 1.0
        )

        /**
         * Record data directory.
         */
        val dataDirectory =
            applicationInfo.dataDir

        if (!dataDirectory.isNullOrBlank()) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.APPLICATION_DATA_DIRECTORY,
                source = "ApplicationInfo.dataDir",
                description =
                    "Application private data directory.",
                value = dataDirectory,
                severity = RuntimeTamperSeverity.INFO,
                confidence = 1.0
            )
        }
    }

    /**
     * Inspects runtime-related directories.
     *
     * This intentionally performs conservative checks only.
     */
    private fun collectRuntimeDirectoryEvidence(
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        val cacheDir =
            context.cacheDir

        inspectDirectory(
            directory = cacheDir,
            type =
                RuntimeTamperEvidenceType.CACHE_DIRECTORY,
            evidence = evidence
        )

        val filesDir =
            context.filesDir

        inspectDirectory(
            directory = filesDir,
            type =
                RuntimeTamperEvidenceType.FILES_DIRECTORY,
            evidence = evidence
        )

        val codeCacheDir =
            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.LOLLIPOP
            ) {
                context.codeCacheDir
            } else {
                null
            }

        if (codeCacheDir != null) {

            inspectDirectory(
                directory = codeCacheDir,
                type =
                    RuntimeTamperEvidenceType.CODE_CACHE_DIRECTORY,
                evidence = evidence
            )
        }
    }

    /**
     * Validates one runtime directory.
     */
    private fun inspectDirectory(
        directory: File,
        type: RuntimeTamperEvidenceType,
        evidence: MutableList<RuntimeTamperEvidence>
    ) {

        evidence += RuntimeTamperEvidence(
            type = type,
            source = "File",
            description =
                "Runtime application directory.",
            value =
                directory.absolutePath,
            severity = RuntimeTamperSeverity.INFO,
            confidence = 1.0
        )

        if (!directory.exists()) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.RUNTIME_DIRECTORY_MISSING,
                source = "File.exists",
                description =
                    "Expected runtime directory does not exist.",
                value =
                    directory.absolutePath,
                severity = RuntimeTamperSeverity.MEDIUM,
                confidence = 0.80
            )

            return
        }

        if (!directory.isDirectory) {

            evidence += RuntimeTamperEvidence(
                type =
                    RuntimeTamperEvidenceType.RUNTIME_DIRECTORY_INVALID,
                source = "File.isDirectory",
                description =
                    "Expected runtime directory is not a directory.",
                value =
                    directory.absolutePath,
                severity = RuntimeTamperSeverity.MEDIUM,
                confidence = 0.80
            )
        }
    }

    /**
     * Attempts to retrieve the current process name.
     *
     * Application.getProcessName() is used on modern Android.
     * A fallback is used for older versions.
     */
    private fun getCurrentProcessName():
            String? {

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.P
        ) {

            return Application
                .getProcessName()
        }

        return try {

            File(
                "/proc/${Process.myPid()}/cmdline"
            )
                .bufferedReader()
                .use {
                    it.readLine()
                }
                ?.trim()

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Determines the overall runtime tamper status.
     *
     * Runtime signals are intentionally conservative because
     * legitimate development, profiling, testing, and framework
     * behavior can produce some of the same observations.
     */
    private fun determineStatus(
        evidence: List<RuntimeTamperEvidence>,
        checksFailed: Int
    ): RuntimeTamperStatus {

        /**
         * Explicit trusted process mismatch.
         */
        if (
            evidence.any {
                it.type ==
                        RuntimeTamperEvidenceType.PROCESS_NAME_MISMATCH
            }
        ) {

            return RuntimeTamperStatus.SUSPICIOUS
        }

        /**
         * Explicitly configured suspicious class-path fragment.
         */
        if (
            evidence.any {
                it.type ==
                        RuntimeTamperEvidenceType.SUSPICIOUS_CLASS_PATH
            }
        ) {

            return RuntimeTamperStatus.SUSPICIOUS
        }

        /**
         * Runtime debugger signals.
         *
         * These are not automatically classified as confirmed
         * tampering because legitimate debugging is possible.
         */
        if (
            evidence.any {
                it.type ==
                        RuntimeTamperEvidenceType.DEBUGGER_CONNECTED ||
                        it.type ==
                        RuntimeTamperEvidenceType.WAITING_FOR_DEBUGGER
            }
        ) {

            return RuntimeTamperStatus.DEBUGGING_DETECTED
        }

        if (checksFailed > 0) {

            return RuntimeTamperStatus.CHECK_INCOMPLETE
        }

        return RuntimeTamperStatus.NO_RUNTIME_TAMPER_DETECTED
    }

    /**
     * Creates standardized check-failure evidence.
     */
    private fun failureEvidence(
        source: String
    ): RuntimeTamperEvidence {

        return RuntimeTamperEvidence(
            type =
                RuntimeTamperEvidenceType.CHECK_FAILURE,
            source = source,
            description =
                "Runtime tamper check could not be completed.",
            severity = RuntimeTamperSeverity.MEDIUM,
            confidence = 0.50
        )
    }

    /**
     * Returns true if runtime tamper indicators were detected.
     */
    fun isRuntimeTampered(): Boolean {

        return detect().status ==
                RuntimeTamperStatus.RUNTIME_TAMPER_DETECTED
    }

    /**
     * Returns true if runtime state is suspicious.
     */
    fun isSuspicious(): Boolean {

        return detect().status ==
                RuntimeTamperStatus.SUSPICIOUS
    }

    /**
     * Returns true when a debugger is currently detected.
     */
    fun isDebuggerDetected(): Boolean {

        return Debug.isDebuggerConnected() ||
                Debug.waitingForDebugger()
    }

    /**
     * Returns all runtime evidence.
     */
    fun getEvidence():
            List<RuntimeTamperEvidence> {

        return detect().evidence
    }

    /**
     * Returns the current process ID.
     */
    fun getProcessId(): Int {

        return Process.myPid()
    }

    /**
     * Returns the current process name.
     */
    fun getProcessName(): String? {

        return getCurrentProcessName()
    }
}

/**
 * Runtime tamper configuration.
 */
data class RuntimeTamperConfiguration(

    /**
     * Expected process name.
     *
     * Example:
     *
     * com.sentrix
     */
    val expectedProcessName: String? = null,

    /**
     * Expected class-loader implementation.
     *
     * This should only be configured when the application has a
     * stable and known class-loader architecture.
     */
    val expectedClassLoaderClassName: String? = null,

    /**
     * Runtime class-path fragments considered suspicious.
     *
     * These should be configured carefully because legitimate
     * Android/framework components can influence runtime paths.
     */
    val suspiciousClassPathFragments:
        Set<String> = emptySet()
)

/**
 * Complete runtime tamper result.
 */
data class RuntimeTamperResult(

    /**
     * Application package.
     */
    val packageName: String,

    /**
     * Overall runtime status.
     */
    val status: RuntimeTamperStatus,

    /**
     * Collected evidence.
     */
    val evidence: List<RuntimeTamperEvidence>,

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
     * Whether detection completed.
     */
    val detectionCompleted: Boolean,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long
) {

    /**
     * Whether runtime tampering was strongly identified.
     */
    val isTampered: Boolean
        get() =
            status ==
                    RuntimeTamperStatus.RUNTIME_TAMPER_DETECTED

    /**
     * Whether runtime state is suspicious.
     */
    val isSuspicious: Boolean
        get() =
            status ==
                    RuntimeTamperStatus.SUSPICIOUS

    /**
     * Whether debugging was detected.
     */
    val debuggerDetected: Boolean
        get() =
            status ==
                    RuntimeTamperStatus.DEBUGGING_DETECTED

    /**
     * Highest evidence severity.
     */
    val highestSeverity:
            RuntimeTamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: RuntimeTamperSeverity.INFO

    private fun severityWeight(
        severity: RuntimeTamperSeverity
    ): Int {

        return when (severity) {

            RuntimeTamperSeverity.INFO -> 0
            RuntimeTamperSeverity.LOW -> 1
            RuntimeTamperSeverity.MEDIUM -> 2
            RuntimeTamperSeverity.HIGH -> 3
            RuntimeTamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Runtime tamper evidence.
 */
data class RuntimeTamperEvidence(

    /**
     * Evidence type.
     */
    val type: RuntimeTamperEvidenceType,

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
     * Expected value when applicable.
     */
    val expectedValue: String? = null,

    /**
     * Evidence severity.
     */
    val severity: RuntimeTamperSeverity,

    /**
     * Confidence in the observation.
     */
    val confidence: Double
)

/**
 * Runtime tamper evidence categories.
 */
enum class RuntimeTamperEvidenceType {

    /**
     * Current process ID.
     */
    PROCESS_ID,

    /**
     * Current process UID.
     */
    PROCESS_UID,

    /**
     * Current process name.
     */
    PROCESS_NAME,

    /**
     * Process name matches trusted configuration.
     */
    PROCESS_NAME_MATCH,

    /**
     * Process name differs from trusted configuration.
     */
    PROCESS_NAME_MISMATCH,

    /**
     * Current application class-loader.
     */
    CLASS_LOADER,

    /**
     * Class-loader matches trusted configuration.
     */
    CLASS_LOADER_MATCH,

    /**
     * Class-loader differs from trusted configuration.
     */
    CLASS_LOADER_MISMATCH,

    /**
     * Parent class-loader.
     */
    CLASS_LOADER_PARENT,

    /**
     * Java runtime class path.
     */
    JAVA_CLASS_PATH,

    /**
     * Java runtime native library path.
     */
    JAVA_LIBRARY_PATH,

    /**
     * Configured suspicious class-path fragment detected.
     */
    SUSPICIOUS_CLASS_PATH,

    /**
     * Application native library directory.
     */
    NATIVE_LIBRARY_PATH,

    /**
     * Native library path unavailable.
     */
    NATIVE_LIBRARY_PATH_UNAVAILABLE,

    /**
     * Native library directory missing.
     */
    NATIVE_LIBRARY_DIRECTORY_MISSING,

    /**
     * Native library path invalid.
     */
    NATIVE_LIBRARY_PATH_INVALID,

    /**
     * Debugger connection state.
     */
    DEBUGGER_CONNECTED,

    /**
     * Process waiting for debugger.
     */
    WAITING_FOR_DEBUGGER,

    /**
     * Application context information.
     */
    APPLICATION_CONTEXT,

    /**
     * Application source directory.
     */
    APPLICATION_SOURCE_DIRECTORY,

    /**
     * Application data directory.
     */
    APPLICATION_DATA_DIRECTORY,

    /**
     * Cache directory.
     */
    CACHE_DIRECTORY,

    /**
     * Application files directory.
     */
    FILES_DIRECTORY,

    /**
     * Code cache directory.
     */
    CODE_CACHE_DIRECTORY,

    /**
     * Runtime directory missing.
     */
    RUNTIME_DIRECTORY_MISSING,

    /**
     * Runtime directory invalid.
     */
    RUNTIME_DIRECTORY_INVALID,

    /**
     * Generic check failure.
     */
    CHECK_FAILURE
}

/**
 * Runtime tamper evidence severity.
 */
enum class RuntimeTamperSeverity {

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
 * Overall runtime tamper state.
 */
enum class RuntimeTamperStatus {

    /**
     * No runtime tamper indicators detected.
     */
    NO_RUNTIME_TAMPER_DETECTED,

    /**
     * Runtime environment contains suspicious indicators.
     */
    SUSPICIOUS,

    /**
     * Runtime tampering has been established by correlated
     * runtime checks.
     */
    RUNTIME_TAMPER_DETECTED,

    /**
     * Debugger activity was detected.
     */
    DEBUGGING_DETECTED,

    /**
     * Runtime assessment could not fully complete.
     */
    CHECK_INCOMPLETE
}
