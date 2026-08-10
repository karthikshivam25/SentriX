package com.sentrix.security.sandbox

import java.io.File
import java.util.UUID

/**
 * SandboxEnvironment
 *
 * Represents the complete runtime environment allocated to a
 * SentriX sandbox session.
 *
 * This class is intentionally modeled as a security-focused
 * environment descriptor rather than an execution engine.
 *
 * Responsibilities:
 * - Describe sandbox directories.
 * - Define security restrictions.
 * - Define resource limits.
 * - Track environment state.
 * - Track network/file-system permissions.
 * - Provide safe path validation.
 *
 * Architecture:
 *
 * SandboxService
 *       |
 *       v
 * SandboxManager
 *       |
 *       v
 * SandboxEnvironment
 *       |
 *       +---- input/
 *       +---- output/
 *       +---- metadata/
 *       +---- temp/
 *
 * IMPORTANT:
 * A directory-based environment is not equivalent to a kernel-level
 * sandbox. Arbitrary malicious/native code must not be executed merely
 * because it is placed inside this directory.
 *
 * Actual isolated execution should be handled by a dedicated
 * SandboxExecutor / isolated process / platform-supported mechanism.
 */
data class SandboxEnvironment(

    /**
     * Unique identifier for this environment.
     */
    val id: String = UUID.randomUUID().toString(),

    /**
     * Human-readable purpose of the environment.
     *
     * Examples:
     * - "APK malware analysis"
     * - "Suspicious PDF inspection"
     * - "Downloaded file analysis"
     */
    val purpose: String,

    /**
     * Root directory containing the entire sandbox environment.
     */
    val rootDirectory: File,

    /**
     * Directory containing files supplied for analysis.
     */
    val inputDirectory: File,

    /**
     * Directory containing generated analysis results.
     */
    val outputDirectory: File,

    /**
     * Directory containing sandbox metadata.
     */
    val metadataDirectory: File,

    /**
     * Temporary working directory.
     *
     * Temporary artifacts should never be treated as trusted data.
     */
    val temporaryDirectory: File,

    /**
     * Time at which the environment was created.
     */
    val createdAt: Long = System.currentTimeMillis(),

    /**
     * Maximum lifetime of this environment.
     */
    val timeoutMs: Long = DEFAULT_TIMEOUT_MS,

    /**
     * Security policy associated with this environment.
     */
    val policy: SandboxPolicy = SandboxPolicy(),

    /**
     * Current lifecycle state.
     */
    var state: EnvironmentState = EnvironmentState.CREATED
) {

    companion object {

        /**
         * Default sandbox lifetime.
         */
        const val DEFAULT_TIMEOUT_MS = 60_000L

        /**
         * Maximum allowed sandbox lifetime.
         */
        const val MAX_TIMEOUT_MS = 5 * 60_000L

        /**
         * Maximum input storage.
         */
        const val DEFAULT_MAX_INPUT_BYTES =
            50L * 1024L * 1024L

        /**
         * Maximum output storage.
         */
        const val DEFAULT_MAX_OUTPUT_BYTES =
            50L * 1024L * 1024L
    }

    /**
     * Returns true if the environment is currently usable.
     */
    fun isActive(): Boolean {

        if (state == EnvironmentState.DESTROYED) {
            return false
        }

        if (state == EnvironmentState.EXPIRED) {
            return false
        }

        return !isExpired()
    }

    /**
     * Determines whether the environment has exceeded its
     * configured lifetime.
     */
    fun isExpired(
        currentTimeMillis: Long = System.currentTimeMillis()
    ): Boolean {

        return currentTimeMillis - createdAt >= timeoutMs
    }

    /**
     * Marks the environment as actively running.
     */
    fun markActive() {

        check(state != EnvironmentState.DESTROYED) {
            "Cannot activate a destroyed sandbox."
        }

        check(!isExpired()) {
            "Cannot activate an expired sandbox."
        }

        state = EnvironmentState.ACTIVE
    }

    /**
     * Marks the environment as paused.
     */
    fun markPaused() {

        check(state != EnvironmentState.DESTROYED) {
            "Cannot pause a destroyed sandbox."
        }

        state = EnvironmentState.PAUSED
    }

    /**
     * Marks the environment as expired.
     */
    fun markExpired() {

        state = EnvironmentState.EXPIRED
    }

    /**
     * Marks the environment as destroyed.
     */
    fun markDestroyed() {

        state = EnvironmentState.DESTROYED
    }

    /**
     * Validates that a file belongs to the requested sandbox
     * directory.
     *
     * This is an important defense against path traversal.
     */
    fun isPathInsideEnvironment(
        file: File
    ): Boolean {

        return try {

            val root =
                rootDirectory.canonicalFile

            val target =
                file.canonicalFile

            target.path.startsWith(
                root.path + File.separator
            ) || target == root

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Validates a file against a specific sandbox directory.
     */
    fun isPathInsideInput(
        file: File
    ): Boolean {

        return isPathInside(
            file,
            inputDirectory
        )
    }

    /**
     * Validates a file against the sandbox output directory.
     */
    fun isPathInsideOutput(
        file: File
    ): Boolean {

        return isPathInside(
            file,
            outputDirectory
        )
    }

    /**
     * Validates a file against the sandbox temporary directory.
     */
    fun isPathInsideTemporary(
        file: File
    ): Boolean {

        return isPathInside(
            file,
            temporaryDirectory
        )
    }

    /**
     * Returns the remaining lifetime of the sandbox.
     */
    fun getRemainingTimeMs(
        currentTimeMillis: Long = System.currentTimeMillis()
    ): Long {

        val elapsed =
            currentTimeMillis - createdAt

        return (timeoutMs - elapsed)
            .coerceAtLeast(0L)
    }

    /**
     * Returns the total size of the input directory.
     */
    fun getInputSizeBytes(): Long {

        return calculateDirectorySize(
            inputDirectory
        )
    }

    /**
     * Returns the total size of the output directory.
     */
    fun getOutputSizeBytes(): Long {

        return calculateDirectorySize(
            outputDirectory
        )
    }

    /**
     * Determines whether the input storage limit has been exceeded.
     */
    fun isInputLimitExceeded(): Boolean {

        return getInputSizeBytes() >
                policy.maxInputBytes
    }

    /**
     * Determines whether the output storage limit has been exceeded.
     */
    fun isOutputLimitExceeded(): Boolean {

        return getOutputSizeBytes() >
                policy.maxOutputBytes
    }

    /**
     * Returns a compact security summary.
     */
    fun securitySummary(): String {

        return buildString {

            append("SandboxEnvironment(")
            append("id=$id, ")
            append("state=$state, ")
            append("network=${policy.networkAccess}, ")
            append("inputLimit=${policy.maxInputBytes}, ")
            append("outputLimit=${policy.maxOutputBytes}, ")
            append("timeout=$timeoutMs")
            append(")")
        }
    }

    /**
     * Performs a structural validation of the environment.
     */
    fun validate(): EnvironmentValidationResult {

        val errors = mutableListOf<String>()

        if (purpose.isBlank()) {
            errors.add(
                "Sandbox purpose cannot be empty."
            )
        }

        if (timeoutMs <= 0) {
            errors.add(
                "Sandbox timeout must be greater than zero."
            )
        }

        if (timeoutMs > MAX_TIMEOUT_MS) {
            errors.add(
                "Sandbox timeout exceeds maximum allowed lifetime."
            )
        }

        if (!isPathInsideEnvironment(inputDirectory)) {
            errors.add(
                "Input directory is outside sandbox root."
            )
        }

        if (!isPathInsideEnvironment(outputDirectory)) {
            errors.add(
                "Output directory is outside sandbox root."
            )
        }

        if (!isPathInsideEnvironment(metadataDirectory)) {
            errors.add(
                "Metadata directory is outside sandbox root."
            )
        }

        if (!isPathInsideEnvironment(temporaryDirectory)) {
            errors.add(
                "Temporary directory is outside sandbox root."
            )
        }

        if (policy.maxInputBytes <= 0) {
            errors.add(
                "Maximum input size must be greater than zero."
            )
        }

        if (policy.maxOutputBytes <= 0) {
            errors.add(
                "Maximum output size must be greater than zero."
            )
        }

        return if (errors.isEmpty()) {

            EnvironmentValidationResult(
                valid = true,
                errors = emptyList()
            )

        } else {

            EnvironmentValidationResult(
                valid = false,
                errors = errors
            )
        }
    }

    /**
     * Checks whether a file is located inside a specified
     * sandbox directory.
     */
    private fun isPathInside(
        file: File,
        directory: File
    ): Boolean {

        return try {

            val root =
                directory.canonicalFile

            val target =
                file.canonicalFile

            target.path.startsWith(
                root.path + File.separator
            ) || target == root

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Recursively calculates directory size.
     *
     * This is intentionally defensive because sandbox contents
     * may be malformed or disappear while being analyzed.
     */
    private fun calculateDirectorySize(
        directory: File
    ): Long {

        if (!directory.exists()) {
            return 0L
        }

        if (directory.isFile) {
            return directory.length()
        }

        return directory.listFiles()
            ?.sumOf { file ->

                try {

                    calculateDirectorySize(
                        file
                    )

                } catch (_: Exception) {

                    0L
                }
            }
            ?: 0L
    }
}


/**
 * SandboxPolicy
 *
 * Defines the security restrictions applied to a sandbox environment.
 *
 * This object does not enforce the restrictions by itself.
 * Enforcement belongs to SandboxExecutor,
 * SandboxIsolationController, and SandboxResourceLimiter.
 */
data class SandboxPolicy(

    /**
     * Whether network access is allowed.
     *
     * For suspicious-file analysis this should normally be false.
     */
    val networkAccess: Boolean = false,

    /**
     * Whether access to external storage is permitted.
     */
    val externalStorageAccess: Boolean = false,

    /**
     * Whether the sandbox may access application-sensitive data.
     */
    val applicationDataAccess: Boolean = false,

    /**
     * Whether process creation should be allowed.
     */
    val processCreationAllowed: Boolean = false,

    /**
     * Whether dynamic code execution is permitted.
     *
     * This should normally remain disabled unless a dedicated
     * isolated execution mechanism is being used.
     */
    val dynamicCodeExecutionAllowed: Boolean = false,

    /**
     * Maximum input storage.
     */
    val maxInputBytes: Long =
        SandboxEnvironment.DEFAULT_MAX_INPUT_BYTES,

    /**
     * Maximum output storage.
     */
    val maxOutputBytes: Long =
        SandboxEnvironment.DEFAULT_MAX_OUTPUT_BYTES,

    /**
     * Maximum memory allowed by the execution layer.
     *
     * This is a policy value; actual enforcement must happen
     * in the appropriate execution/isolation layer.
     */
    val maxMemoryBytes: Long =
        128L * 1024L * 1024L,

    /**
     * Maximum CPU time allowed.
     */
    val maxCpuTimeMs: Long = 30_000L,

    /**
     * Maximum number of files that may be created.
     */
    val maxFileCount: Int = 1_000
)


/**
 * Sandbox environment lifecycle states.
 */
enum class EnvironmentState {

    /**
     * Environment has been created but analysis has not started.
     */
    CREATED,

    /**
     * Environment is actively being used.
     */
    ACTIVE,

    /**
     * Environment is temporarily paused.
     */
    PAUSED,

    /**
     * Environment lifetime has expired.
     */
    EXPIRED,

    /**
     * Environment has been permanently destroyed.
     */
    DESTROYED
}


/**
 * Result of validating a sandbox environment.
 */
data class EnvironmentValidationResult(

    /**
     * True when the environment passed all validation checks.
     */
    val valid: Boolean,

    /**
     * Validation failures, if any.
     */
    val errors: List<String>
)
