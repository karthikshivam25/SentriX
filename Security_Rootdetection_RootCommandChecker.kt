package com.sentrix.security.rootdetection

import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

/**
 * RootCommandChecker
 *
 * Performs safe command-based checks for indicators of elevated
 * privileges on an Android device.
 *
 * The checker uses only read-only / identity-oriented operations.
 *
 * Primary checks:
 *
 * 1. Determine whether the `su` command is discoverable.
 * 2. Determine whether `su` appears executable.
 * 3. Attempt a harmless `id` command through `su`.
 * 4. Analyze the resulting identity information.
 *
 * This class does NOT:
 *
 * - install or modify anything
 * - change device configuration
 * - bypass security controls
 * - persist elevated privileges
 * - execute arbitrary caller-provided commands
 * - determine the final device root verdict
 * - calculate the overall SentriX risk score
 *
 * Architecture:
 *
 * RootDetectionManager
 *        ↓
 * RootChecker
 *        ↓
 * RootCommandChecker
 *        ↓
 * Safe command execution
 *
 * IMPORTANT:
 *
 * Command execution is inherently heuristic.
 * A successful `su` invocation is strong evidence, but the final
 * security decision belongs to RootDetectionValidator.
 */
class RootCommandChecker {

    /**
     * Maximum amount of time allowed for an individual command.
     *
     * Keeping this short prevents a blocked or malicious command
     * environment from holding the detection process indefinitely.
     */
    private val commandTimeoutSeconds = 2L

    /**
     * Common locations where the su executable may exist.
     *
     * This complements RootBinaryChecker but does not replace it.
     */
    private val knownSuPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/su/bin/daemonsu",
        "/vendor/bin/su",
        "/vendor/xbin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su"
    )

    /**
     * Performs the complete safe command-based check.
     */
    fun check(): RootCommandScanResult {

        val evidence = mutableListOf<RootCommandEvidence>()

        /**
         * Check whether a su command can be discovered through
         * standard command lookup.
         */
        val whichResult = executeReadOnlyCommand(
            command = arrayOf(
                "/system/bin/sh",
                "-c",
                "command -v su"
            )
        )

        if (whichResult.success &&
            whichResult.output.isNotBlank()
        ) {

            evidence += RootCommandEvidence(
                type = RootCommandEvidenceType.SU_COMMAND_AVAILABLE,
                command = "command -v su",
                output = sanitizeOutput(
                    whichResult.output
                ),
                exitCode = whichResult.exitCode,
                severity = RootCommandSeverity.HIGH,
                confidence = 0.85
            )
        }

        /**
         * Check known filesystem locations without executing
         * the discovered binary.
         */
        val discoveredPaths =
            findKnownSuPaths()

        if (discoveredPaths.isNotEmpty()) {

            evidence += RootCommandEvidence(
                type = RootCommandEvidenceType.SU_PATH_AVAILABLE,
                command = "filesystem path inspection",
                output = discoveredPaths.joinToString(","),
                exitCode = 0,
                severity = RootCommandSeverity.HIGH,
                confidence = 0.90
            )
        }

        /**
         * Attempt a harmless identity query through su.
         *
         * The command only asks for process identity information.
         *
         * No filesystem or device state is modified.
         */
        val suResult = executeSuIdentityCheck()

        if (suResult.success) {

            val identityOutput =
                sanitizeOutput(suResult.output)

            if (isElevatedIdentity(identityOutput)) {

                evidence += RootCommandEvidence(
                    type = RootCommandEvidenceType.SU_ELEVATED_IDENTITY,
                    command = "su -c id",
                    output = identityOutput,
                    exitCode = suResult.exitCode,
                    severity = RootCommandSeverity.CRITICAL,
                    confidence = 0.98
                )

            } else {

                evidence += RootCommandEvidence(
                    type = RootCommandEvidenceType.SU_COMMAND_EXECUTED,
                    command = "su -c id",
                    output = identityOutput,
                    exitCode = suResult.exitCode,
                    severity = RootCommandSeverity.HIGH,
                    confidence = 0.90
                )
            }
        }

        return RootCommandScanResult(
            evidence = evidence,
            commandsChecked = 3,
            scanCompleted = true,
            scanTimestamp = System.currentTimeMillis()
        )
    }

    /**
     * Determines whether a root-capable `su` command appears
     * available.
     */
    fun isSuAvailable(): Boolean {

        val result = executeReadOnlyCommand(
            command = arrayOf(
                "/system/bin/sh",
                "-c",
                "command -v su"
            )
        )

        return result.success &&
                result.output.isNotBlank()
    }

    /**
     * Checks known filesystem locations for su.
     *
     * This is intentionally duplicated here as a lightweight
     * command-checking signal. RootBinaryChecker remains the
     * dedicated filesystem component.
     */
    fun hasKnownSuPath(): Boolean {

        return findKnownSuPaths().isNotEmpty()
    }

    /**
     * Returns all known su paths that are observable.
     */
    fun findKnownSuPaths(): List<String> {

        return knownSuPaths.filter { path ->

            try {

                java.io.File(path).exists()

            } catch (_: SecurityException) {

                false

            } catch (_: Exception) {

                false
            }
        }
    }

    /**
     * Performs a harmless identity check through su.
     *
     * The executed operation is read-only:
     *
     *     id
     *
     * No caller-supplied command is accepted.
     */
    fun checkSuIdentity(): RootCommandExecutionResult {

        return executeSuIdentityCheck()
    }

    /**
     * Determines whether the output indicates an elevated
     * root identity.
     *
     * Typical root identity output contains:
     *
     *     uid=0
     *
     * The method deliberately avoids assuming that every output
     * format is identical.
     */
    fun isElevatedIdentity(
        identityOutput: String
    ): Boolean {

        if (identityOutput.isBlank()) {
            return false
        }

        val normalized =
            identityOutput
                .lowercase()
                .replace(
                    Regex("\\s+"),
                    " "
                )

        /**
         * UID 0 is the strongest local identity signal.
         */
        return Regex(
            """\buid\s*=\s*0(?:\D|$)"""
        ).containsMatchIn(normalized)
    }

    /**
     * Executes the fixed harmless `su -c id` operation.
     *
     * No arbitrary command string is accepted.
     */
    private fun executeSuIdentityCheck():
            RootCommandExecutionResult {

        return executeReadOnlyCommand(
            command = arrayOf(
                "su",
                "-c",
                "id"
            )
        )
    }

    /**
     * Executes a strictly controlled read-only command.
     *
     * The method:
     *
     * - does not accept arbitrary shell input from callers
     * - captures stdout
     * - captures stderr
     * - applies a timeout
     * - destroys the process after completion
     */
    private fun executeReadOnlyCommand(
        command: Array<String>
    ): RootCommandExecutionResult {

        var process: Process? = null

        return try {

            process = ProcessBuilder(*command)
                .redirectErrorStream(false)
                .start()

            val stdout =
                readStreamSafely(
                    process.inputStream
                )

            val stderr =
                readStreamSafely(
                    process.errorStream
                )

            val completed =
                process.waitFor(
                    commandTimeoutSeconds,
                    TimeUnit.SECONDS
                )

            if (!completed) {

                process.destroy()

                if (process.isAlive) {
                    process.destroyForcibly()
                }

                return RootCommandExecutionResult(
                    success = false,
                    output = stdout,
                    error = "Command timed out.",
                    exitCode = null,
                    timedOut = true
                )
            }

            RootCommandExecutionResult(
                success = process.exitValue() == 0,
                output = stdout,
                error = stderr,
                exitCode = process.exitValue(),
                timedOut = false
            )

        } catch (_: SecurityException) {

            RootCommandExecutionResult(
                success = false,
                output = "",
                error = "Command execution denied.",
                exitCode = null,
                timedOut = false
            )

        } catch (_: Exception) {

            RootCommandExecutionResult(
                success = false,
                output = "",
                error = "Command execution failed.",
                exitCode = null,
                timedOut = false
            )

        } finally {

            try {
                process?.destroy()
            } catch (_: Exception) {
                // Ignore cleanup failure.
            }
        }
    }

    /**
     * Reads a process stream safely.
     *
     * Output is deliberately limited so that an unexpected command
     * environment cannot cause excessive memory consumption.
     */
    private fun readStreamSafely(
        stream: java.io.InputStream
    ): String {

        val maxOutputLength = 4096

        return try {

            BufferedReader(
                InputStreamReader(stream)
            ).use { reader ->

                val builder = StringBuilder()

                var line: String?

                while (
                    reader.readLine()
                        .also { line = it } != null
                ) {

                    if (
                        builder.length +
                        (line?.length ?: 0) >
                        maxOutputLength
                    ) {
                        break
                    }

                    if (builder.isNotEmpty()) {
                        builder.append('\n')
                    }

                    builder.append(line)
                }

                builder.toString()
            }

        } catch (_: Exception) {

            ""
        }
    }

    /**
     * Removes potentially unnecessary whitespace and limits the
     * output that is stored in the security evidence model.
     */
    private fun sanitizeOutput(
        output: String
    ): String {

        return output
            .trim()
            .take(4096)
    }

    /**
     * Returns true when strong command-based evidence exists.
     *
     * This does NOT mean the final device state is rooted.
     */
    fun hasStrongEvidence(): Boolean {

        val result = check()

        return result.evidence.any {
            it.severity == RootCommandSeverity.CRITICAL ||
                    it.severity == RootCommandSeverity.HIGH
        }
    }

    /**
     * Returns true only when the harmless `su -c id` check
     * successfully demonstrates UID 0.
     */
    fun confirmsElevatedIdentity(): Boolean {

        val result = checkSuIdentity()

        return result.success &&
                isElevatedIdentity(
                    result.output
                )
    }
}

/**
 * Result of the complete command-based root check.
 */
data class RootCommandScanResult(

    /**
     * Command-related evidence collected.
     */
    val evidence: List<RootCommandEvidence>,

    /**
     * Number of logical command checks performed.
     */
    val commandsChecked: Int,

    /**
     * Whether the scan completed.
     */
    val scanCompleted: Boolean,

    /**
     * Scan completion timestamp.
     */
    val scanTimestamp: Long
) {

    /**
     * Indicates whether any command-based evidence was found.
     */
    val hasEvidence: Boolean
        get() = evidence.isNotEmpty()

    /**
     * Indicates whether strong evidence was found.
     */
    val hasStrongEvidence: Boolean
        get() = evidence.any {
            it.severity == RootCommandSeverity.HIGH ||
                    it.severity == RootCommandSeverity.CRITICAL
        }

    /**
     * Indicates whether command execution demonstrated UID 0.
     */
    val confirmsRootIdentity: Boolean
        get() = evidence.any {
            it.type ==
                    RootCommandEvidenceType.SU_ELEVATED_IDENTITY
        }
}

/**
 * Individual command-based root evidence.
 */
data class RootCommandEvidence(

    /**
     * Evidence category.
     */
    val type: RootCommandEvidenceType,

    /**
     * Safe command or operation that generated the evidence.
     */
    val command: String,

    /**
     * Sanitized command output.
     */
    val output: String,

    /**
     * Process exit code, if available.
     */
    val exitCode: Int?,

    /**
     * Security significance of the evidence.
     */
    val severity: RootCommandSeverity,

    /**
     * Confidence that the observation is useful as evidence.
     *
     * This is NOT the probability that the device is rooted.
     */
    val confidence: Double
)

/**
 * Categories of command-based root evidence.
 */
enum class RootCommandEvidenceType {

    /**
     * `su` was discoverable through command lookup.
     */
    SU_COMMAND_AVAILABLE,

    /**
     * A known su filesystem location exists.
     */
    SU_PATH_AVAILABLE,

    /**
     * su executed successfully.
     */
    SU_COMMAND_EXECUTED,

    /**
     * su successfully returned an elevated UID.
     */
    SU_ELEVATED_IDENTITY
}

/**
 * Severity of command-based evidence.
 */
enum class RootCommandSeverity {

    /**
     * Informational observation.
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

/**
 * Result of one controlled command execution.
 */
data class RootCommandExecutionResult(

    /**
     * Whether the command completed successfully.
     */
    val success: Boolean,

    /**
     * Standard output.
     */
    val output: String,

    /**
     * Standard error.
     */
    val error: String,

    /**
     * Process exit code.
     */
    val exitCode: Int?,

    /**
     * Whether execution exceeded the timeout.
     */
    val timedOut: Boolean
)
