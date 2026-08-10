package com.sentrix.security.sandbox

import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * SandboxViolationDetector
 *
 * Detects and classifies security violations occurring within
 * SentriX sandbox environments.
 *
 * Responsibilities:
 *
 * - Detect filesystem escape attempts.
 * - Detect unauthorized file access.
 * - Detect unauthorized network activity.
 * - Detect unauthorized process activity.
 * - Detect permission violations.
 * - Detect isolation degradation.
 * - Detect resource-limit violations.
 * - Detect suspicious debugger activity.
 * - Detect policy violations.
 * - Maintain violation history.
 * - Calculate violation severity.
 * - Provide violation reports to higher-level components.
 *
 * Architectural position:
 *
 * SandboxExecutor
 *       |
 *       v
 * SandboxViolationDetector
 *       |
 *       +--------------------+
 *       |                    |
 *       v                    v
 * PermissionManager    IsolationManager
 *       |                    |
 *       └──────────┬─────────┘
 *                  v
 *           ViolationReport
 *                  |
 *                  v
 *        SandboxService / Security Engine
 *
 * IMPORTANT:
 *
 * This class detects violations. It does not directly terminate
 * processes or destroy sandbox environments.
 *
 * Enforcement should be delegated to:
 *
 * - SandboxIsolationController
 * - SandboxResourceLimiter
 * - SandboxService
 */
class SandboxViolationDetector {

    companion object {

        /**
         * Maximum number of violation records retained per sandbox.
         */
        private const val MAX_VIOLATIONS_PER_SANDBOX = 500

        /**
         * Maximum total tracked sandbox violation contexts.
         */
        private const val MAX_TRACKED_SANDBOXES = 100

        /**
         * Number of high/critical violations after which the
         * sandbox should be considered high risk.
         */
        private const val HIGH_RISK_THRESHOLD = 3
    }

    /**
     * Violation history indexed by sandbox ID.
     */
    private val violations =
        ConcurrentHashMap<
            String,
            MutableList<SandboxViolation>
        >()

    /**
     * Registers a sandbox for violation monitoring.
     */
    @Synchronized
    fun registerSandbox(
        sandboxId: String
    ) {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        if (!violations.containsKey(sandboxId) &&
            violations.size >= MAX_TRACKED_SANDBOXES
        ) {
            throw IllegalStateException(
                "Maximum tracked sandbox violation contexts reached."
            )
        }

        violations.putIfAbsent(
            sandboxId,
            mutableListOf()
        )
    }

    /**
     * Detects a filesystem path violation.
     *
     * The requested path must remain inside the permitted directory.
     */
    fun detectFilesystemAccess(
        sandboxId: String,
        requestedPath: File,
        allowedRoot: File,
        operation: FileOperation
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        val violation =
            try {

                val root =
                    allowedRoot.canonicalFile

                val requested =
                    requestedPath.canonicalFile

                val inside =
                    requested == root ||
                        requested.path.startsWith(
                            root.path + File.separator
                        )

                if (inside) {
                    null
                } else {
                    createViolation(
                        sandboxId = sandboxId,
                        type =
                            SandboxViolationType
                                .FILESYSTEM_ESCAPE,
                        severity =
                            SandboxViolationSeverity
                                .HIGH,
                        description =
                            "Filesystem access outside the " +
                                "permitted sandbox directory.",
                        operation = operation.name,
                        evidence =
                            requested.absolutePath
                    )
                }

            } catch (exception: Exception) {

                createViolation(
                    sandboxId = sandboxId,
                    type =
                        SandboxViolationType
                            .PATH_VALIDATION_FAILURE,
                    severity =
                        SandboxViolationSeverity
                            .HIGH,
                    description =
                        "Unable to safely validate requested " +
                            "filesystem path.",
                    operation = operation.name,
                    evidence =
                        exception.javaClass.simpleName
                )
            }

        return buildResult(
            sandboxId = sandboxId,
            violation = violation
        )
    }

    /**
     * Detects an attempt to access the host filesystem.
     */
    fun detectHostFilesystemAccess(
        sandboxId: String,
        requestedPath: File,
        sandboxRoot: File
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        val violation =
            try {

                val requested =
                    requestedPath.canonicalFile

                val root =
                    sandboxRoot.canonicalFile

                val inside =
                    requested == root ||
                        requested.path.startsWith(
                            root.path + File.separator
                        )

                if (inside) {
                    null
                } else {
                    createViolation(
                        sandboxId = sandboxId,
                        type =
                            SandboxViolationType
                                .HOST_FILESYSTEM_ACCESS,
                        severity =
                            SandboxViolationSeverity
                                .CRITICAL,
                        description =
                            "Attempted access outside the sandbox " +
                                "filesystem boundary.",
                        evidence =
                            requested.absolutePath
                    )
                }

            } catch (exception: Exception) {

                createViolation(
                    sandboxId = sandboxId,
                    type =
                        SandboxViolationType
                            .PATH_VALIDATION_FAILURE,
                    severity =
                        SandboxViolationSeverity
                            .HIGH,
                    description =
                        "Filesystem boundary validation failed.",
                    evidence =
                        exception.javaClass.simpleName
                )
            }

        return buildResult(
            sandboxId = sandboxId,
            violation = violation
        )
    }

    /**
     * Detects symbolic-link usage.
     *
     * Symbolic links should normally be disabled in a hardened
     * sandbox because they can complicate filesystem boundary
     * validation.
     */
    fun detectSymbolicLink(
        sandboxId: String,
        file: File
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        /*
         * Canonical-path comparison can reveal many symlink-based
         * path escapes, but complete symlink detection should be
         * implemented using platform/filesystem-specific APIs when
         * required.
         */
        val canonical =
            try {
                file.canonicalFile
            } catch (_: Exception) {
                null
            }

        val violation =
            if (canonical == null) {

                createViolation(
                    sandboxId = sandboxId,
                    type =
                        SandboxViolationType
                            .PATH_VALIDATION_FAILURE,
                    severity =
                        SandboxViolationSeverity
                            .HIGH,
                    description =
                        "Unable to resolve sandbox file path.",
                    evidence = file.absolutePath
                )

            } else {

                /*
                 * The actual sandbox boundary check is intentionally
                 * performed separately by detectFilesystemAccess().
                 */
                null
            }

        return buildResult(
            sandboxId = sandboxId,
            violation = violation
        )
    }

    /**
     * Detects unauthorized network activity.
     */
    fun detectNetworkAccess(
        sandboxId: String,
        host: String?,
        port: Int?,
        protocol: NetworkProtocol,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId = sandboxId,
                violation = null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_NETWORK_ACCESS,
                severity =
                    SandboxViolationSeverity
                        .CRITICAL,
                description =
                    "Sandbox attempted unauthorized network access.",
                operation =
                    "${protocol.name}:${port ?: -1}",
                evidence =
                    host ?: "unknown-host"
            )

        return buildResult(
            sandboxId = sandboxId,
            violation = violation
        )
    }

    /**
     * Detects unauthorized DNS activity.
     */
    fun detectDnsAccess(
        sandboxId: String,
        hostname: String,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_DNS_ACCESS,
                severity =
                    SandboxViolationSeverity
                        .HIGH,
                description =
                    "Sandbox attempted unauthorized DNS resolution.",
                evidence = hostname
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects unauthorized process creation.
     */
    fun detectProcessCreation(
        sandboxId: String,
        processName: String,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_PROCESS_CREATION,
                severity =
                    SandboxViolationSeverity
                        .CRITICAL,
                description =
                    "Sandbox attempted unauthorized process creation.",
                evidence = processName
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects unauthorized child-process creation.
     */
    fun detectChildProcessCreation(
        sandboxId: String,
        processName: String,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_CHILD_PROCESS,
                severity =
                    SandboxViolationSeverity
                        .CRITICAL,
                description =
                    "Sandbox attempted unauthorized child-process creation.",
                evidence = processName
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects unauthorized dynamic code execution.
     */
    fun detectDynamicCodeExecution(
        sandboxId: String,
        codeType: String,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_CODE_EXECUTION,
                severity =
                    SandboxViolationSeverity
                        .CRITICAL,
                description =
                    "Sandbox attempted unauthorized dynamic code execution.",
                evidence = codeType
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects native library loading.
     */
    fun detectNativeLibraryLoading(
        sandboxId: String,
        libraryName: String,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_NATIVE_CODE,
                severity =
                    SandboxViolationSeverity
                        .CRITICAL,
                description =
                    "Sandbox attempted unauthorized native library loading.",
                evidence = libraryName
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects debugger attachment attempts.
     */
    fun detectDebuggerAccess(
        sandboxId: String,
        debuggerIdentifier: String?,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_DEBUGGER_ACCESS,
                severity =
                    SandboxViolationSeverity
                        .HIGH,
                description =
                    "Sandbox attempted unauthorized debugger access.",
                evidence =
                    debuggerIdentifier ?: "unknown"
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects unauthorized device access.
     */
    fun detectDeviceAccess(
        sandboxId: String,
        permission: SandboxPermission,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .UNAUTHORIZED_DEVICE_ACCESS,
                severity =
                    SandboxViolationSeverity
                        .HIGH,
                description =
                    "Sandbox attempted unauthorized device capability access.",
                evidence = permission.name
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects an unauthorized permission request.
     */
    fun detectPermissionViolation(
        sandboxId: String,
        permission: SandboxPermission,
        allowed: Boolean
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        if (allowed) {
            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .PERMISSION_VIOLATION,
                severity =
                    SandboxViolationSeverity
                        .HIGH,
                description =
                    "Sandbox requested a capability that is not permitted.",
                evidence = permission.name
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects a resource violation.
     */
    fun detectResourceViolation(
        sandboxId: String,
        resourceViolation:
            ResourceViolation
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        val severity =
            when (
                resourceViolation.type
            ) {

                ResourceViolationType.MEMORY_EXCEEDED,
                ResourceViolationType.CPU_TIME_EXCEEDED,
                ResourceViolationType.EXECUTION_TIME_EXCEEDED ->
                    SandboxViolationSeverity.HIGH

                ResourceViolationType.THREAD_LIMIT_EXCEEDED,
                ResourceViolationType.FILE_COUNT_EXCEEDED,
                ResourceViolationType.INPUT_STORAGE_EXCEEDED,
                ResourceViolationType.OUTPUT_STORAGE_EXCEEDED,
                ResourceViolationType.TEMPORARY_STORAGE_EXCEEDED ->
                    SandboxViolationSeverity.MEDIUM

                ResourceViolationType.INVALID_LIMIT ->
                    SandboxViolationSeverity.CRITICAL
            }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .RESOURCE_LIMIT_EXCEEDED,
                severity = severity,
                description =
                    "Sandbox exceeded a configured resource limit.",
                operation =
                    resourceViolation.resource.name,
                evidence =
                    "${resourceViolation.currentValue}/" +
                        "${resourceViolation.maximumValue}"
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects an isolation violation reported by
     * SandboxIsolationManager.
     */
    fun detectIsolationViolation(
        sandboxId: String,
        violationType:
            IsolationViolationType
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        val severity =
            when (violationType) {

                IsolationViolationType
                    .FILESYSTEM_ESCAPE_ATTEMPT,
                IsolationViolationType
                    .NETWORK_ESCAPE_ATTEMPT,
                IsolationViolationType
                    .UNAUTHORIZED_PROCESS_ACCESS,
                IsolationViolationType
                    .RESOURCE_BOUNDARY_BYPASS ->
                    SandboxViolationSeverity.CRITICAL

                IsolationViolationType
                    .DEVICE_DATA_ACCESS_ATTEMPT,
                IsolationViolationType
                    .DEBUGGER_ACCESS_ATTEMPT,
                IsolationViolationType
                    .EXTERNAL_STORAGE_ACCESS_ATTEMPT,
                IsolationViolationType
                    .IPC_VIOLATION ->
                    SandboxViolationSeverity.HIGH

                IsolationViolationType
                    .UNAUTHORIZED_CAPABILITY_REQUEST,
                IsolationViolationType
                    .POLICY_VIOLATION ->
                    SandboxViolationSeverity.MEDIUM
            }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .ISOLATION_VIOLATION,
                severity = severity,
                description =
                    "Sandbox isolation policy was violated.",
                evidence =
                    violationType.name
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects a generic policy violation.
     */
    fun detectPolicyViolation(
        sandboxId: String,
        policyId: String,
        description: String,
        evidence: String? = null
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .POLICY_VIOLATION,
                severity =
                    SandboxViolationSeverity
                        .HIGH,
                description =
                    description,
                operation =
                    "policy:$policyId",
                evidence =
                    evidence
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Detects repeated violations.
     *
     * Useful for escalating a sandbox from suspicious to high-risk.
     */
    fun detectRepeatedViolations(
        sandboxId: String
    ): SandboxViolationResult {

        ensureRegistered(sandboxId)

        val history =
            getViolations(
                sandboxId
            )

        val highRiskCount =
            history.count {
                it.severity ==
                    SandboxViolationSeverity.HIGH ||
                    it.severity ==
                    SandboxViolationSeverity.CRITICAL
            }

        if (highRiskCount <
            HIGH_RISK_THRESHOLD
        ) {

            return buildResult(
                sandboxId,
                null
            )
        }

        val violation =
            createViolation(
                sandboxId = sandboxId,
                type =
                    SandboxViolationType
                        .REPEATED_VIOLATIONS,
                severity =
                    SandboxViolationSeverity
                        .CRITICAL,
                description =
                    "Multiple high-risk sandbox violations were detected.",
                evidence =
                    "highRiskCount=$highRiskCount"
            )

        return buildResult(
            sandboxId,
            violation
        )
    }

    /**
     * Records a violation explicitly.
     *
     * Useful when another sandbox component has already performed
     * the detection.
     */
    fun recordViolation(
        violation: SandboxViolation
    ) {

        ensureRegistered(
            violation.sandboxId
        )

        val history =
            violations[
                violation.sandboxId
            ] ?: return

        synchronized(history) {

            if (history.size >=
                MAX_VIOLATIONS_PER_SANDBOX
            ) {
                history.removeAt(0)
            }

            history.add(
                violation
            )
        }
    }

    /**
     * Returns all violations for a sandbox.
     */
    fun getViolations(
        sandboxId: String
    ): List<SandboxViolation> {

        ensureRegistered(sandboxId)

        val history =
            violations[
                sandboxId
            ] ?: return emptyList()

        synchronized(history) {
            return history.toList()
        }
    }

    /**
     * Returns only critical violations.
     */
    fun getCriticalViolations(
        sandboxId: String
    ): List<SandboxViolation> {

        return getViolations(
            sandboxId
        ).filter {
            it.severity ==
                SandboxViolationSeverity.CRITICAL
        }
    }

    /**
     * Returns only high-severity violations.
     */
    fun getHighRiskViolations(
        sandboxId: String
    ): List<SandboxViolation> {

        return getViolations(
            sandboxId
        ).filter {
            it.severity ==
                SandboxViolationSeverity.HIGH ||
                it.severity ==
                SandboxViolationSeverity.CRITICAL
        }
    }

    /**
     * Returns the total number of violations.
     */
    fun getViolationCount(
        sandboxId: String
    ): Int {

        return getViolations(
            sandboxId
        ).size
    }

    /**
     * Determines whether the sandbox should be treated as high risk.
     */
    fun isHighRisk(
        sandboxId: String
    ): Boolean {

        return getHighRiskViolations(
            sandboxId
        ).size >= HIGH_RISK_THRESHOLD
    }

    /**
     * Calculates the current violation risk score.
     *
     * The score is intentionally simple and deterministic so it can
     * later be replaced by SentriX's broader threat-scoring engine.
     */
    fun calculateRiskScore(
        sandboxId: String
    ): Int {

        val history =
            getViolations(
                sandboxId
            )

        return history.sumOf {
            severityScore(
                it.severity
            )
        }.coerceAtMost(100)
    }

    /**
     * Generates a complete violation report.
     */
    fun generateReport(
        sandboxId: String
    ): SandboxViolationReport {

        val history =
            getViolations(
                sandboxId
            )

        val critical =
            history.count {
                it.severity ==
                    SandboxViolationSeverity.CRITICAL
            }

        val high =
            history.count {
                it.severity ==
                    SandboxViolationSeverity.HIGH
            }

        val medium =
            history.count {
                it.severity ==
                    SandboxViolationSeverity.MEDIUM
            }

        val low =
            history.count {
                it.severity ==
                    SandboxViolationSeverity.LOW
            }

        return SandboxViolationReport(
            sandboxId = sandboxId,
            totalViolations = history.size,
            criticalViolations = critical,
            highViolations = high,
            mediumViolations = medium,
            lowViolations = low,
            riskScore =
                calculateRiskScore(
                    sandboxId
                ),
            highRisk =
                isHighRisk(
                    sandboxId
                ),
            violations = history
        )
    }

    /**
     * Removes violation history for one sandbox.
     */
    @Synchronized
    fun releaseSandbox(
        sandboxId: String
    ): Boolean {

        return violations.remove(
            sandboxId
        ) != null
    }

    /**
     * Removes all violation history.
     */
    @Synchronized
    fun releaseAll() {

        violations.clear()
    }

    /**
     * Creates a violation object.
     */
    private fun createViolation(
        sandboxId: String,
        type: SandboxViolationType,
        severity: SandboxViolationSeverity,
        description: String,
        operation: String? = null,
        evidence: String? = null
    ): SandboxViolation {

        val violation =
            SandboxViolation(
                sandboxId = sandboxId,
                type = type,
                severity = severity,
                description = description,
                operation = operation,
                evidence = evidence
            )

        recordViolation(
            violation
        )

        return violation
    }

    /**
     * Builds a detector result.
     */
    private fun buildResult(
        sandboxId: String,
        violation: SandboxViolation?
    ): SandboxViolationResult {

        return SandboxViolationResult(
            sandboxId = sandboxId,
            violated = violation != null,
            violation = violation,
            riskScore =
                calculateRiskScore(
                    sandboxId
                )
        )
    }

    /**
     * Maps severity to risk points.
     */
    private fun severityScore(
        severity: SandboxViolationSeverity
    ): Int {

        return when (severity) {

            SandboxViolationSeverity.LOW ->
                5

            SandboxViolationSeverity.MEDIUM ->
                15

            SandboxViolationSeverity.HIGH ->
                30

            SandboxViolationSeverity.CRITICAL ->
                50
        }
    }

    /**
     * Ensures the sandbox has been registered.
     */
    private fun ensureRegistered(
        sandboxId: String
    ) {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        if (!violations.containsKey(
                sandboxId
            )
        ) {
            registerSandbox(
                sandboxId
            )
        }
    }
}


/**
 * Types of sandbox violations detected by SentriX.
 */
enum class SandboxViolationType {

    FILESYSTEM_ESCAPE,

    HOST_FILESYSTEM_ACCESS,

    PATH_VALIDATION_FAILURE,

    SYMBOLIC_LINK_ESCAPE,

    UNAUTHORIZED_FILE_READ,

    UNAUTHORIZED_FILE_WRITE,

    UNAUTHORIZED_NETWORK_ACCESS,

    UNAUTHORIZED_DNS_ACCESS,

    UNAUTHORIZED_PROCESS_CREATION,

    UNAUTHORIZED_CHILD_PROCESS,

    UNAUTHORIZED_CODE_EXECUTION,

    UNAUTHORIZED_NATIVE_CODE,

    UNAUTHORIZED_DEBUGGER_ACCESS,

    UNAUTHORIZED_DEVICE_ACCESS,

    PERMISSION_VIOLATION,

    RESOURCE_LIMIT_EXCEEDED,

    ISOLATION_VIOLATION,

    POLICY_VIOLATION,

    REPEATED_VIOLATIONS
}


/**
 * Severity assigned to a sandbox violation.
 */
enum class SandboxViolationSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}


/**
 * Filesystem operation associated with a violation check.
 */
enum class FileOperation {

    READ,

    WRITE,

    CREATE,

    DELETE,

    RENAME,

    EXECUTE,

    LIST
}


/**
 * Supported network protocol categories.
 */
enum class NetworkProtocol {

    TCP,

    UDP,

    HTTP,

    HTTPS,

    DNS,

    TLS,

    UNKNOWN
}


/**
 * A single detected sandbox violation.
 */
data class SandboxViolation(

    /**
     * Sandbox where the violation occurred.
     */
    val sandboxId: String,

    /**
     * Type of violation.
     */
    val type: SandboxViolationType,

    /**
     * Severity of the violation.
     */
    val severity: SandboxViolationSeverity,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Operation that caused the violation.
     */
    val operation: String? = null,

    /**
     * Evidence associated with the violation.
     *
     * This should be sanitized before being included in user-facing
     * reports because sandbox evidence may contain attacker-controlled
     * strings.
     */
    val evidence: String? = null,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long =
        System.currentTimeMillis()
)


/**
 * Result of a violation-detection operation.
 */
data class SandboxViolationResult(

    val sandboxId: String,

    /**
     * True when a violation was detected.
     */
    val violated: Boolean,

    /**
     * Detected violation, if present.
     */
    val violation: SandboxViolation?,

    /**
     * Current aggregate risk score.
     */
    val riskScore: Int
)


/**
 * Aggregated sandbox violation report.
 */
data class SandboxViolationReport(

    val sandboxId: String,

    val totalViolations: Int,

    val criticalViolations: Int,

    val highViolations: Int,

    val mediumViolations: Int,

    val lowViolations: Int,

    /**
     * Aggregate score from 0 to 100.
     */
    val riskScore: Int,

    /**
     * Indicates whether repeated high-risk activity was observed.
     */
    val highRisk: Boolean,

    /**
     * Complete violation history.
     */
    val violations: List<SandboxViolation>
)
