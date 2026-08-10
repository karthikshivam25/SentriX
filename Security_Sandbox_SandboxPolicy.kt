package com.sentrix.security.sandbox

/**
 * SandboxPolicy
 *
 * Defines the security restrictions and resource limits that apply
 * to a SentriX sandbox environment.
 *
 * This class represents POLICY, not ENFORCEMENT.
 *
 * The policy answers questions such as:
 *
 * - Is network access allowed?
 * - Can external storage be accessed?
 * - Can application data be accessed?
 * - Is process creation allowed?
 * - Is dynamic code execution allowed?
 * - How much input/output storage is permitted?
 * - How much memory can be consumed?
 * - How much CPU time is permitted?
 *
 * Actual enforcement should be performed by components such as:
 *
 * SandboxExecutor
 * SandboxIsolationController
 * SandboxResourceLimiter
 *
 * Architecture:
 *
 *                  SandboxService
 *                         |
 *                         v
 *                  SandboxManager
 *                         |
 *                         v
 *                 SandboxEnvironment
 *                         |
 *                         v
 *                   SandboxPolicy
 *                    /         \
 *                   /           \
 *                  v             v
 *       SandboxExecutor   ResourceLimiter
 *
 * IMPORTANT:
 * A policy object by itself does not create a security boundary.
 * The execution/isolation layer must enforce these restrictions.
 */
data class SandboxPolicy(

    /**
     * Unique policy identifier.
     *
     * Useful when security policies are persisted, logged,
     * remotely configured, or attached to security reports.
     */
    val policyId: String = DEFAULT_POLICY_ID,

    /**
     * Human-readable policy name.
     */
    val name: String = DEFAULT_POLICY_NAME,

    /**
     * Policy version.
     *
     * Increment this whenever the security semantics of the policy
     * change in a backward-incompatible way.
     */
    val version: Int = DEFAULT_POLICY_VERSION,

    /**
     * Whether network access is permitted.
     *
     * Suspicious files should normally be analyzed without network
     * connectivity to prevent:
     *
     * - Command-and-control communication.
     * - Data exfiltration.
     * - Malware callbacks.
     * - Contact with attacker infrastructure.
     */
    val networkAccess: Boolean = false,

    /**
     * Whether outbound network connections are permitted.
     *
     * This is intentionally separate from networkAccess so that
     * future sandbox implementations can distinguish inbound and
     * outbound traffic.
     */
    val outboundNetworkAccess: Boolean = false,

    /**
     * Whether inbound network connections are permitted.
     */
    val inboundNetworkAccess: Boolean = false,

    /**
     * Whether DNS resolution is permitted.
     *
     * DNS can itself be used as a covert communication mechanism,
     * so it should normally remain disabled during high-risk analysis.
     */
    val dnsAccess: Boolean = false,

    /**
     * Whether external storage access is permitted.
     */
    val externalStorageAccess: Boolean = false,

    /**
     * Whether access to SentriX/application-private data is permitted.
     *
     * This should normally remain disabled for untrusted content.
     */
    val applicationDataAccess: Boolean = false,

    /**
     * Whether access to Android shared/private application state
     * is permitted.
     */
    val sharedApplicationDataAccess: Boolean = false,

    /**
     * Whether process creation is permitted.
     *
     * Arbitrary process creation should normally be disabled.
     */
    val processCreationAllowed: Boolean = false,

    /**
     * Whether child-process creation is permitted.
     */
    val childProcessCreationAllowed: Boolean = false,

    /**
     * Whether dynamic code execution is permitted.
     *
     * This should remain disabled unless the actual execution mechanism
     * provides appropriate isolation.
     */
    val dynamicCodeExecutionAllowed: Boolean = false,

    /**
     * Whether native library loading is permitted.
     *
     * Loading arbitrary native code significantly increases the
     * security risk of an analysis environment.
     */
    val nativeLibraryLoadingAllowed: Boolean = false,

    /**
     * Whether reflection-based execution is permitted.
     */
    val reflectionAllowed: Boolean = false,

    /**
     * Maximum size of all sandbox input files combined.
     */
    val maxInputBytes: Long = DEFAULT_MAX_INPUT_BYTES,

    /**
     * Maximum size of all sandbox output files combined.
     */
    val maxOutputBytes: Long = DEFAULT_MAX_OUTPUT_BYTES,

    /**
     * Maximum amount of temporary storage.
     */
    val maxTemporaryStorageBytes: Long =
        DEFAULT_MAX_TEMPORARY_STORAGE_BYTES,

    /**
     * Maximum number of files that may exist inside the sandbox.
     */
    val maxFileCount: Int = DEFAULT_MAX_FILE_COUNT,

    /**
     * Maximum size of an individual file.
     */
    val maxIndividualFileBytes: Long =
        DEFAULT_MAX_INDIVIDUAL_FILE_BYTES,

    /**
     * Maximum memory available to the execution layer.
     *
     * This is a policy value and must be enforced by the actual
     * execution/isolation mechanism.
     */
    val maxMemoryBytes: Long = DEFAULT_MAX_MEMORY_BYTES,

    /**
     * Maximum CPU execution time.
     */
    val maxCpuTimeMs: Long = DEFAULT_MAX_CPU_TIME_MS,

    /**
     * Maximum wall-clock execution time.
     */
    val maxExecutionTimeMs: Long = DEFAULT_MAX_EXECUTION_TIME_MS,

    /**
     * Maximum number of threads allowed by the execution layer.
     */
    val maxThreads: Int = DEFAULT_MAX_THREADS,

    /**
     * Whether filesystem writes are allowed.
     *
     * Even when enabled, writes should remain restricted to the
     * sandbox-controlled directories.
     */
    val fileWriteAccess: Boolean = true,

    /**
     * Whether filesystem reads are allowed.
     *
     * Reads should still be restricted to explicitly approved
     * sandbox directories.
     */
    val fileReadAccess: Boolean = true,

    /**
     * Whether access outside the sandbox root is allowed.
     *
     * This should ALWAYS remain false for untrusted analysis.
     */
    val hostFilesystemAccess: Boolean = false,

    /**
     * Whether symbolic links are permitted.
     *
     * Symbolic links can potentially be abused to escape an
     * intended filesystem boundary.
     */
    val symbolicLinksAllowed: Boolean = false,

    /**
     * Whether hidden files may be created.
     */
    val hiddenFileCreationAllowed: Boolean = false,

    /**
     * Whether executable file creation is permitted.
     *
     * This should normally be disabled for static analysis.
     */
    val executableFileCreationAllowed: Boolean = false,

    /**
     * Whether clipboard access is permitted.
     */
    val clipboardAccess: Boolean = false,

    /**
     * Whether device sensors can be accessed.
     *
     * Examples:
     * - Camera
     * - Microphone
     * - Accelerometer
     * - GPS
     */
    val sensorAccess: Boolean = false,

    /**
     * Whether camera access is permitted.
     */
    val cameraAccess: Boolean = false,

    /**
     * Whether microphone access is permitted.
     */
    val microphoneAccess: Boolean = false,

    /**
     * Whether location access is permitted.
     */
    val locationAccess: Boolean = false,

    /**
     * Whether notification access is permitted.
     */
    val notificationAccess: Boolean = false,

    /**
     * Whether accessibility services may be accessed.
     */
    val accessibilityAccess: Boolean = false,

    /**
     * Whether biometric APIs may be accessed.
     */
    val biometricAccess: Boolean = false,

    /**
     * Whether VPN/network tunneling is permitted.
     */
    val vpnAccess: Boolean = false,

    /**
     * Whether debugging interfaces are permitted.
     *
     * Debugging capabilities should normally be disabled when
     * analyzing untrusted content.
     */
    val debuggingAllowed: Boolean = false,

    /**
     * Whether attaching a debugger is permitted.
     */
    val debuggerAttachAllowed: Boolean = false,

    /**
     * Whether logs generated by the sandbox may contain raw input data.
     *
     * Keeping this false helps reduce accidental sensitive-data leakage.
     */
    val sensitiveDataLoggingAllowed: Boolean = false,

    /**
     * Whether the sandbox may persist state after termination.
     */
    val persistentStateAllowed: Boolean = false,

    /**
     * Whether sandbox-generated metadata should be retained.
     */
    val metadataRetentionAllowed: Boolean = true,

    /**
     * Whether failed security checks should immediately terminate
     * the sandbox.
     */
    val terminateOnSecurityViolation: Boolean = true,

    /**
     * Maximum number of security violations tolerated before
     * termination.
     */
    val maxSecurityViolations: Int = 0,

    /**
     * Whether the policy should be treated as immutable during execution.
     *
     * Immutable policies are preferable for security-sensitive
     * operations because runtime policy changes can introduce
     * unexpected security states.
     */
    val immutableDuringExecution: Boolean = true
) {

    companion object {

        /**
         * Default policy identifier.
         */
        const val DEFAULT_POLICY_ID =
            "SENTRIX_SANDBOX_DEFAULT"

        /**
         * Default policy name.
         */
        const val DEFAULT_POLICY_NAME =
            "SentriX Default Secure Sandbox Policy"

        /**
         * Current policy version.
         */
        const val DEFAULT_POLICY_VERSION = 1

        /**
         * Maximum total input size.
         */
        const val DEFAULT_MAX_INPUT_BYTES =
            50L * 1024L * 1024L

        /**
         * Maximum total output size.
         */
        const val DEFAULT_MAX_OUTPUT_BYTES =
            50L * 1024L * 1024L

        /**
         * Maximum temporary storage.
         */
        const val DEFAULT_MAX_TEMPORARY_STORAGE_BYTES =
            50L * 1024L * 1024L

        /**
         * Maximum number of files.
         */
        const val DEFAULT_MAX_FILE_COUNT = 1_000

        /**
         * Maximum individual file size.
         */
        const val DEFAULT_MAX_INDIVIDUAL_FILE_BYTES =
            25L * 1024L * 1024L

        /**
         * Default memory limit.
         */
        const val DEFAULT_MAX_MEMORY_BYTES =
            128L * 1024L * 1024L

        /**
         * Default CPU time limit.
         */
        const val DEFAULT_MAX_CPU_TIME_MS = 30_000L

        /**
         * Default wall-clock execution limit.
         */
        const val DEFAULT_MAX_EXECUTION_TIME_MS = 60_000L

        /**
         * Default maximum thread count.
         */
        const val DEFAULT_MAX_THREADS = 4
    }

    /**
     * Determines whether the policy permits any network communication.
     */
    fun isNetworkRestricted(): Boolean {

        return !networkAccess &&
            !outboundNetworkAccess &&
            !inboundNetworkAccess &&
            !dnsAccess
    }

    /**
     * Determines whether filesystem access is restricted to the
     * sandbox environment.
     */
    fun isFilesystemRestricted(): Boolean {

        return !hostFilesystemAccess
    }

    /**
     * Determines whether code execution is restricted.
     */
    fun isExecutionRestricted(): Boolean {

        return !dynamicCodeExecutionAllowed &&
            !nativeLibraryLoadingAllowed &&
            !processCreationAllowed &&
            !childProcessCreationAllowed
    }

    /**
     * Determines whether device access is restricted.
     */
    fun isDeviceAccessRestricted(): Boolean {

        return !sensorAccess &&
            !cameraAccess &&
            !microphoneAccess &&
            !locationAccess &&
            !clipboardAccess &&
            !biometricAccess &&
            !vpnAccess
    }

    /**
     * Returns true when this is considered a hardened policy.
     *
     * A hardened policy disables the most sensitive capabilities
     * and applies conservative resource limits.
     */
    fun isHardened(): Boolean {

        return isNetworkRestricted() &&
            isFilesystemRestricted() &&
            isExecutionRestricted() &&
            isDeviceAccessRestricted() &&
            !debuggingAllowed &&
            !debuggerAttachAllowed &&
            !persistentStateAllowed &&
            terminateOnSecurityViolation
    }

    /**
     * Determines whether the supplied input size is permitted.
     */
    fun isInputSizeAllowed(
        sizeBytes: Long
    ): Boolean {

        return sizeBytes >= 0 &&
            sizeBytes <= maxIndividualFileBytes &&
            sizeBytes <= maxInputBytes
    }

    /**
     * Determines whether the supplied output size is permitted.
     */
    fun isOutputSizeAllowed(
        sizeBytes: Long
    ): Boolean {

        return sizeBytes >= 0 &&
            sizeBytes <= maxOutputBytes
    }

    /**
     * Determines whether a new file can be created.
     */
    fun isFileCountAllowed(
        currentFileCount: Int
    ): Boolean {

        return currentFileCount >= 0 &&
            currentFileCount < maxFileCount
    }

    /**
     * Determines whether a requested execution duration is allowed.
     */
    fun isExecutionTimeAllowed(
        durationMs: Long
    ): Boolean {

        return durationMs >= 0 &&
            durationMs <= maxExecutionTimeMs
    }

    /**
     * Determines whether requested memory is within policy.
     */
    fun isMemoryUsageAllowed(
        memoryBytes: Long
    ): Boolean {

        return memoryBytes >= 0 &&
            memoryBytes <= maxMemoryBytes
    }

    /**
     * Determines whether a requested thread count is allowed.
     */
    fun isThreadCountAllowed(
        threadCount: Int
    ): Boolean {

        return threadCount > 0 &&
            threadCount <= maxThreads
    }

    /**
     * Determines whether a security violation should terminate
     * the sandbox.
     */
    fun shouldTerminateForViolation(
        violationCount: Int
    ): Boolean {

        if (!terminateOnSecurityViolation) {
            return false
        }

        return violationCount > maxSecurityViolations
    }

    /**
     * Performs consistency validation on the policy.
     *
     * This should be called before assigning the policy to a
     * sandbox environment.
     */
    fun validate(): PolicyValidationResult {

        val errors = mutableListOf<String>()

        if (policyId.isBlank()) {
            errors.add(
                "Policy ID cannot be empty."
            )
        }

        if (name.isBlank()) {
            errors.add(
                "Policy name cannot be empty."
            )
        }

        if (version <= 0) {
            errors.add(
                "Policy version must be greater than zero."
            )
        }

        if (maxInputBytes <= 0) {
            errors.add(
                "Maximum input size must be greater than zero."
            )
        }

        if (maxOutputBytes <= 0) {
            errors.add(
                "Maximum output size must be greater than zero."
            )
        }

        if (maxTemporaryStorageBytes <= 0) {
            errors.add(
                "Maximum temporary storage must be greater than zero."
            )
        }

        if (maxFileCount <= 0) {
            errors.add(
                "Maximum file count must be greater than zero."
            )
        }

        if (maxIndividualFileBytes <= 0) {
            errors.add(
                "Maximum individual file size must be greater than zero."
            )
        }

        if (maxIndividualFileBytes > maxInputBytes) {
            errors.add(
                "Individual file limit cannot exceed total input limit."
            )
        }

        if (maxMemoryBytes <= 0) {
            errors.add(
                "Maximum memory must be greater than zero."
            )
        }

        if (maxCpuTimeMs <= 0) {
            errors.add(
                "Maximum CPU time must be greater than zero."
            )
        }

        if (maxExecutionTimeMs <= 0) {
            errors.add(
                "Maximum execution time must be greater than zero."
            )
        }

        if (maxThreads <= 0) {
            errors.add(
                "Maximum thread count must be greater than zero."
            )
        }

        if (maxSecurityViolations < 0) {
            errors.add(
                "Maximum security violations cannot be negative."
            )
        }

        /*
         * A policy that allows host filesystem access while also
         * disabling sandbox restrictions should be treated as invalid.
         */
        if (hostFilesystemAccess) {
            errors.add(
                "Host filesystem access must remain disabled."
            )
        }

        /*
         * Native code loading without a dedicated isolated executor
         * is unsafe for the default policy.
         */
        if (nativeLibraryLoadingAllowed &&
            !dynamicCodeExecutionAllowed
        ) {
            errors.add(
                "Native library loading requires explicit dynamic " +
                    "execution permission."
            )
        }

        return if (errors.isEmpty()) {

            PolicyValidationResult(
                valid = true,
                errors = emptyList()
            )

        } else {

            PolicyValidationResult(
                valid = false,
                errors = errors
            )
        }
    }

    /**
     * Creates a stricter version of this policy.
     *
     * This is useful when SentriX detects a high-risk threat and wants
     * to reduce the available sandbox capabilities.
     */
    fun hardened(): SandboxPolicy {

        return copy(
            networkAccess = false,
            outboundNetworkAccess = false,
            inboundNetworkAccess = false,
            dnsAccess = false,

            externalStorageAccess = false,
            applicationDataAccess = false,
            sharedApplicationDataAccess = false,

            processCreationAllowed = false,
            childProcessCreationAllowed = false,
            dynamicCodeExecutionAllowed = false,
            nativeLibraryLoadingAllowed = false,
            reflectionAllowed = false,

            hostFilesystemAccess = false,
            symbolicLinksAllowed = false,
            executableFileCreationAllowed = false,

            clipboardAccess = false,
            sensorAccess = false,
            cameraAccess = false,
            microphoneAccess = false,
            locationAccess = false,
            notificationAccess = false,
            accessibilityAccess = false,
            biometricAccess = false,
            vpnAccess = false,

            debuggingAllowed = false,
            debuggerAttachAllowed = false,

            sensitiveDataLoggingAllowed = false,
            persistentStateAllowed = false,

            terminateOnSecurityViolation = true,
            maxSecurityViolations = 0,

            immutableDuringExecution = true
        )
    }

    /**
     * Creates a static-analysis policy.
     *
     * This profile is appropriate for operations such as:
     *
     * - APK inspection
     * - Manifest analysis
     * - Permission analysis
     * - File metadata inspection
     * - Hash calculation
     *
     * No dynamic execution is permitted.
     */
    fun staticAnalysis(): SandboxPolicy {

        return hardened().copy(
            name = "SentriX Static Analysis Policy",
            maxExecutionTimeMs = 30_000L
        )
    }

    /**
     * Creates a file-analysis policy.
     *
     * Designed for:
     *
     * - PDF analysis
     * - Document inspection
     * - Downloaded file analysis
     * - Archive inspection
     */
    fun fileAnalysis(): SandboxPolicy {

        return hardened().copy(
            name = "SentriX File Analysis Policy",
            maxInputBytes =
                50L * 1024L * 1024L,
            maxIndividualFileBytes =
                25L * 1024L * 1024L
        )
    }

    /**
     * Creates a policy intended for high-risk malware analysis.
     *
     * The execution layer must provide the actual process-level
     * isolation before this policy is used for dynamic analysis.
     */
    fun malwareAnalysis(): SandboxPolicy {

        return hardened().copy(
            name = "SentriX Malware Analysis Policy",
            maxExecutionTimeMs = 30_000L,
            maxCpuTimeMs = 20_000L,
            maxMemoryBytes =
                128L * 1024L * 1024L,
            maxThreads = 2
        )
    }
}


/**
 * Result of sandbox policy validation.
 */
data class PolicyValidationResult(

    /**
     * Indicates whether the policy is valid.
     */
    val valid: Boolean,

    /**
     * List of validation errors.
     */
    val errors: List<String>
) {

    /**
     * Throws an exception when the policy is invalid.
     *
     * Useful when a policy must be validated before sandbox creation.
     */
    fun requireValid() {

        require(valid) {

            "Invalid SandboxPolicy: " +
                errors.joinToString("; ")
        }
    }
}
