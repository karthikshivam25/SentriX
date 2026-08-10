package com.sentrix.security.sandbox

import java.util.concurrent.ConcurrentHashMap

/**
 * SandboxIsolationManager
 *
 * Central coordinator for sandbox isolation state inside SentriX.
 *
 * Responsibilities:
 *
 * - Register sandbox isolation contexts.
 * - Validate isolation requirements against SandboxPolicy.
 * - Track isolation state.
 * - Track isolation capabilities.
 * - Enable / disable logical isolation requirements.
 * - Detect isolation violations.
 * - Escalate a sandbox into a hardened isolation state.
 * - Coordinate cleanup of isolation metadata.
 *
 * Architectural role:
 *
 *                  SandboxService
 *                        |
 *                        v
 *               SandboxIsolationManager
 *                        |
 *             ┌──────────┼───────────┐
 *             v          v           v
 *       SandboxPolicy  Permission  Environment
 *       Manager       Manager
 *                        |
 *                        v
 *              SandboxIsolationController
 *                        |
 *                        v
 *                 Actual platform
 *                 isolation mechanism
 *
 * IMPORTANT:
 *
 * This class manages isolation STATE and REQUIREMENTS.
 *
 * It does not itself create a kernel-level sandbox or bypass Android's
 * process/security model.
 *
 * Actual isolation enforcement must be implemented by
 * SandboxIsolationController using an appropriate Android-supported
 * mechanism.
 */
class SandboxIsolationManager {

    companion object {

        /**
         * Maximum number of isolation contexts.
         */
        private const val MAX_ISOLATION_CONTEXTS = 100

        /**
         * Default maximum number of isolation violations.
         */
        private const val DEFAULT_MAX_VIOLATIONS = 0
    }

    /**
     * Isolation contexts indexed by sandbox ID.
     */
    private val isolationContexts =
        ConcurrentHashMap<String, SandboxIsolationContext>()

    /**
     * Registers a sandbox for isolation management.
     *
     * The isolation configuration is derived from the supplied policy.
     */
    @Synchronized
    fun registerSandbox(
        sandboxId: String,
        policy: SandboxPolicy
    ): SandboxIsolationContext {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        policy.validate()
            .requireValid()

        isolationContexts[sandboxId]?.let {
            return it
        }

        if (isolationContexts.size >=
            MAX_ISOLATION_CONTEXTS
        ) {
            throw IllegalStateException(
                "Maximum sandbox isolation contexts reached."
            )
        }

        val context =
            SandboxIsolationContext(
                sandboxId = sandboxId,
                policyId = policy.policyId,
                state = IsolationState.CREATED,
                capabilities =
                    buildCapabilities(policy),
                maxViolations =
                    if (policy.terminateOnSecurityViolation) {
                        policy.maxSecurityViolations
                    } else {
                        Int.MAX_VALUE
                    }
            )

        isolationContexts[sandboxId] =
            context

        return context
    }

    /**
     * Returns an isolation context.
     */
    fun getIsolationContext(
        sandboxId: String
    ): SandboxIsolationContext? {

        return isolationContexts[sandboxId]
    }

    /**
     * Initializes isolation for a sandbox.
     *
     * This changes the logical state to PREPARING.
     *
     * The actual platform isolation is performed by
     * SandboxIsolationController.
     */
    fun prepareIsolation(
        sandboxId: String
    ): IsolationOperationResult {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            if (context.state ==
                IsolationState.DESTROYED
            ) {
                return IsolationOperationResult.failure(
                    sandboxId = sandboxId,
                    reason =
                        IsolationFailureReason
                            .ALREADY_DESTROYED
                )
            }

            if (context.state ==
                IsolationState.ISOLATED
            ) {
                return IsolationOperationResult.success(
                    sandboxId = sandboxId
                )
            }

            context.state =
                IsolationState.PREPARING

            return IsolationOperationResult.success(
                sandboxId = sandboxId
            )
        }
    }

    /**
     * Marks isolation as successfully established.
     *
     * This method should be called by SandboxIsolationController
     * after the actual isolation mechanism has been successfully
     * established.
     */
    fun markIsolated(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            if (context.state ==
                IsolationState.DESTROYED
            ) {
                return false
            }

            context.state =
                IsolationState.ISOLATED

            context.isolationEstablishedAt =
                System.currentTimeMillis()

            return true
        }
    }

    /**
     * Marks the sandbox as running inside its isolated environment.
     */
    fun markRunning(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            if (context.state !=
                IsolationState.ISOLATED
            ) {
                return false
            }

            context.state =
                IsolationState.RUNNING

            return true
        }
    }

    /**
     * Pauses the logical isolation context.
     */
    fun markPaused(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            if (
                context.state != IsolationState.RUNNING &&
                context.state != IsolationState.ISOLATED
            ) {
                return false
            }

            context.state =
                IsolationState.PAUSED

            return true
        }
    }

    /**
     * Resumes a paused sandbox.
     */
    fun resume(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            if (context.state !=
                IsolationState.PAUSED
            ) {
                return false
            }

            context.state =
                IsolationState.RUNNING

            return true
        }
    }

    /**
     * Marks isolation as degraded.
     *
     * A degraded state means that the sandbox is still tracked but
     * one or more expected isolation guarantees are no longer known
     * to be fully intact.
     */
    fun markDegraded(
        sandboxId: String,
        reason: IsolationViolationType
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            context.state =
                IsolationState.DEGRADED

            recordViolationInternal(
                context = context,
                violation = reason
            )

            return true
        }
    }

    /**
     * Marks isolation as failed.
     */
    fun markFailed(
        sandboxId: String,
        reason: IsolationFailureReason
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            context.state =
                IsolationState.FAILED

            context.failureReason =
                reason

            return true
        }
    }

    /**
     * Marks the isolation context as destroyed.
     */
    fun markDestroyed(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            context.state =
                IsolationState.DESTROYED

            context.destroyedAt =
                System.currentTimeMillis()

            return true
        }
    }

    /**
     * Returns the current isolation state.
     */
    fun getIsolationState(
        sandboxId: String
    ): IsolationState? {

        return isolationContexts[
            sandboxId
        ]?.state
    }

    /**
     * Determines whether the sandbox is currently isolated.
     */
    fun isIsolated(
        sandboxId: String
    ): Boolean {

        return when (
            getIsolationState(sandboxId)
        ) {

            IsolationState.ISOLATED,
            IsolationState.RUNNING,
            IsolationState.PAUSED ->
                true

            else ->
                false
        }
    }

    /**
     * Determines whether the isolation state is considered safe.
     */
    fun isIsolationHealthy(
        sandboxId: String
    ): Boolean {

        return when (
            getIsolationState(sandboxId)
        ) {

            IsolationState.ISOLATED,
            IsolationState.RUNNING,
            IsolationState.PAUSED ->
                true

            else ->
                false
        }
    }

    /**
     * Checks whether a particular isolation capability is enabled.
     */
    fun hasCapability(
        sandboxId: String,
        capability: IsolationCapability
    ): Boolean {

        val context =
            isolationContexts[
                sandboxId
            ] ?: return false

        return context.capabilities[
            capability
        ] == true
    }

    /**
     * Returns all enabled isolation capabilities.
     */
    fun getEnabledCapabilities(
        sandboxId: String
    ): Set<IsolationCapability> {

        val context =
            isolationContexts[
                sandboxId
            ] ?: return emptySet()

        return context.capabilities
            .filterValues { enabled ->
                enabled
            }
            .keys
    }

    /**
     * Returns all disabled isolation capabilities.
     */
    fun getDisabledCapabilities(
        sandboxId: String
    ): Set<IsolationCapability> {

        val context =
            isolationContexts[
                sandboxId
            ] ?: return emptySet()

        return context.capabilities
            .filterValues { enabled ->
                !enabled
            }
            .keys
    }

    /**
     * Attempts to enable an isolation capability.
     *
     * A capability cannot be enabled if the corresponding sandbox
     * policy does not permit it.
     *
     * Because this manager does not retain the entire policy object,
     * callers should normally establish the capability set during
     * sandbox registration.
     */
    fun enableCapability(
        sandboxId: String,
        capability: IsolationCapability
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            if (context.state ==
                IsolationState.DESTROYED
            ) {
                return false
            }

            /*
             * Capability escalation is intentionally prevented.
             *
             * A capability that was not present in the original
             * policy-derived configuration cannot be dynamically
             * added here.
             */
            if (!context.allowedCapabilities.contains(
                    capability
                )
            ) {
                recordViolationInternal(
                    context = context,
                    violation =
                        IsolationViolationType
                            .UNAUTHORIZED_CAPABILITY_REQUEST
                )

                return false
            }

            context.capabilities[
                capability
            ] = true

            return true
        }
    }

    /**
     * Disables an isolation capability.
     *
     * Revocation is always permitted because it makes the sandbox
     * more restrictive rather than less restrictive.
     */
    fun disableCapability(
        sandboxId: String,
        capability: IsolationCapability
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            context.capabilities[
                capability
            ] = false

            return true
        }
    }

    /**
     * Immediately hardens the sandbox.
     *
     * All optional isolation capabilities are disabled.
     */
    fun hardenIsolation(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            context.capabilities.keys.forEach {
                capability ->

                /*
                 * Core isolation guarantees remain enabled.
                 * Optional access capabilities are disabled.
                 */
                if (!isCoreCapability(
                        capability
                    )
                ) {
                    context.capabilities[
                        capability
                    ] = false
                }
            }

            context.hardened = true

            return true
        }
    }

    /**
     * Records an isolation violation.
     */
    fun recordViolation(
        sandboxId: String,
        violation: IsolationViolationType
    ): IsolationViolation {

        val context =
            requireContext(sandboxId)

        synchronized(context) {

            return recordViolationInternal(
                context = context,
                violation = violation
            )
        }
    }

    /**
     * Returns the number of isolation violations.
     */
    fun getViolationCount(
        sandboxId: String
    ): Int {

        return requireContext(
            sandboxId
        ).violationCount
    }

    /**
     * Determines whether the isolation violation limit has
     * been exceeded.
     */
    fun hasExceededViolationLimit(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        return context.violationCount >
            context.maxViolations
    }

    /**
     * Determines whether isolation should be considered unsafe.
     */
    fun shouldTerminate(
        sandboxId: String
    ): Boolean {

        val context =
            requireContext(sandboxId)

        return context.state ==
                IsolationState.FAILED ||
            context.state ==
                IsolationState.DEGRADED &&
                context.violationCount >
                    context.maxViolations
    }

    /**
     * Validates whether a sandbox has the required isolation
     * capabilities for a given analysis.
     */
    fun validateForAnalysis(
        sandboxId: String,
        analysisType:
            SandboxService.SandboxAnalysisType
    ): IsolationValidationResult {

        val context =
            isolationContexts[
                sandboxId
            ] ?: return IsolationValidationResult(
                valid = false,
                sandboxId = sandboxId,
                missingCapabilities =
                    emptySet(),
                reason =
                    "Sandbox isolation context not found."
            )

        val required =
            requiredCapabilitiesFor(
                analysisType
            )

        val missing =
            required.filter { capability ->
                context.capabilities[
                    capability
                ] != true
            }.toSet()

        return if (
            context.state !=
                IsolationState.ISOLATED &&
            context.state !=
                IsolationState.RUNNING
        ) {

            IsolationValidationResult(
                valid = false,
                sandboxId = sandboxId,
                missingCapabilities = missing,
                reason =
                    "Sandbox is not isolated."
            )

        } else if (missing.isNotEmpty()) {

            IsolationValidationResult(
                valid = false,
                sandboxId = sandboxId,
                missingCapabilities = missing,
                reason =
                    "Required isolation capabilities are missing."
            )

        } else {

            IsolationValidationResult(
                valid = true,
                sandboxId = sandboxId,
                missingCapabilities = emptySet(),
                reason = null
            )
        }
    }

    /**
     * Returns the isolation capabilities required for a given
     * analysis type.
     */
    fun requiredCapabilitiesFor(
        analysisType:
            SandboxService.SandboxAnalysisType
    ): Set<IsolationCapability> {

        return when (analysisType) {

            SandboxService.SandboxAnalysisType.APK_ANALYSIS ->
                setOf(
                    IsolationCapability
                        .FILESYSTEM_ISOLATION,
                    IsolationCapability
                        .PROCESS_ISOLATION,
                    IsolationCapability
                        .DEVICE_DATA_ISOLATION
                )

            SandboxService.SandboxAnalysisType.FILE_ANALYSIS ->
                setOf(
                    IsolationCapability
                        .FILESYSTEM_ISOLATION,
                    IsolationCapability
                        .PROCESS_ISOLATION
                )

            SandboxService.SandboxAnalysisType.PDF_ANALYSIS ->
                setOf(
                    IsolationCapability
                        .FILESYSTEM_ISOLATION,
                    IsolationCapability
                        .PROCESS_ISOLATION,
                    IsolationCapability
                        .NETWORK_ISOLATION
                )

            SandboxService.SandboxAnalysisType.MALWARE_ANALYSIS ->
                setOf(
                    IsolationCapability
                        .FILESYSTEM_ISOLATION,
                    IsolationCapability
                        .PROCESS_ISOLATION,
                    IsolationCapability
                        .NETWORK_ISOLATION,
                    IsolationCapability
                        .DEVICE_DATA_ISOLATION,
                    IsolationCapability
                        .RESOURCE_ISOLATION
                )

            SandboxService.SandboxAnalysisType.BEHAVIOR_ANALYSIS ->
                setOf(
                    IsolationCapability
                        .FILESYSTEM_ISOLATION,
                    IsolationCapability
                        .PROCESS_ISOLATION,
                    IsolationCapability
                        .NETWORK_ISOLATION,
                    IsolationCapability
                        .DEVICE_DATA_ISOLATION,
                    IsolationCapability
                        .RESOURCE_ISOLATION
                )

            SandboxService.SandboxAnalysisType.STATIC_ANALYSIS ->
                setOf(
                    IsolationCapability
                        .FILESYSTEM_ISOLATION,
                    IsolationCapability
                        .PROCESS_ISOLATION
                )

            SandboxService.SandboxAnalysisType.NETWORK_ANALYSIS ->
                setOf(
                    IsolationCapability
                        .FILESYSTEM_ISOLATION,
                    IsolationCapability
                        .PROCESS_ISOLATION,
                    IsolationCapability
                        .NETWORK_ISOLATION,
                    IsolationCapability
                        .RESOURCE_ISOLATION
                )
        }
    }

    /**
     * Returns a complete isolation snapshot.
     */
    fun getIsolationSnapshot(
        sandboxId: String
    ): SandboxIsolationSnapshot {

        val context =
            requireContext(sandboxId)

        return SandboxIsolationSnapshot(
            sandboxId = sandboxId,
            state = context.state,
            policyId = context.policyId,
            enabledCapabilities =
                getEnabledCapabilities(
                    sandboxId
                ),
            disabledCapabilities =
                getDisabledCapabilities(
                    sandboxId
                ),
            violationCount =
                context.violationCount,
            hardened =
                context.hardened,
            failureReason =
                context.failureReason,
            lastViolation =
                context.lastViolation
        )
    }

    /**
     * Releases all isolation state associated with a sandbox.
     *
     * This does not destroy the actual platform isolation.
     * SandboxIsolationController must perform the real cleanup.
     */
    @Synchronized
    fun releaseSandbox(
        sandboxId: String
    ): Boolean {

        return isolationContexts.remove(
            sandboxId
        ) != null
    }

    /**
     * Releases all isolation metadata.
     */
    @Synchronized
    fun releaseAll() {

        isolationContexts.clear()
    }

    /**
     * Returns the number of tracked isolation contexts.
     */
    fun getContextCount(): Int {

        return isolationContexts.size
    }

    /**
     * Builds isolation capabilities from a sandbox policy.
     *
     * Core isolation capabilities are enabled by default because
     * this manager is responsible for a security sandbox.
     */
    private fun buildCapabilities(
        policy: SandboxPolicy
    ): MutableMap<
        IsolationCapability,
        Boolean
    > {

        return mutableMapOf(

            IsolationCapability
                .FILESYSTEM_ISOLATION to
                !policy.hostFilesystemAccess,

            IsolationCapability
                .PROCESS_ISOLATION to
                !policy.processCreationAllowed,

            IsolationCapability
                .NETWORK_ISOLATION to
                !policy.networkAccess,

            IsolationCapability
                .DEVICE_DATA_ISOLATION to
                !policy.applicationDataAccess,

            IsolationCapability
                .RESOURCE_ISOLATION to
                true,

            IsolationCapability
                .IPC_ISOLATION to
                true,

            IsolationCapability
                .DEBUGGER_ISOLATION to
                !policy.debuggerAttachAllowed,

            IsolationCapability
                .STORAGE_ISOLATION to
                !policy.externalStorageAccess
        )
    }

    /**
     * Determines whether a capability is a core security guarantee.
     */
    private fun isCoreCapability(
        capability: IsolationCapability
    ): Boolean {

        return when (capability) {

            IsolationCapability.FILESYSTEM_ISOLATION,
            IsolationCapability.PROCESS_ISOLATION,
            IsolationCapability.NETWORK_ISOLATION,
            IsolationCapability.DEVICE_DATA_ISOLATION,
            IsolationCapability.RESOURCE_ISOLATION,
            IsolationCapability.IPC_ISOLATION,
            IsolationCapability.STORAGE_ISOLATION,
            IsolationCapability.DEBUGGER_ISOLATION ->
                true
        }
    }

    /**
     * Records a violation against an isolation context.
     */
    private fun recordViolationInternal(
        context: SandboxIsolationContext,
        violation: IsolationViolationType
    ): IsolationViolation {

        context.violationCount++

        val record =
            IsolationViolation(
                sandboxId = context.sandboxId,
                type = violation,
                violationNumber =
                    context.violationCount
            )

        context.lastViolation =
            record

        if (
            context.violationCount >
            context.maxViolations
        ) {
            context.state =
                IsolationState.DEGRADED
        }

        return record
    }

    /**
     * Returns an isolation context or throws.
     */
    private fun requireContext(
        sandboxId: String
    ): SandboxIsolationContext {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        return isolationContexts[
            sandboxId
        ] ?: throw IllegalArgumentException(
            "Sandbox isolation context not found: " +
                sandboxId
        )
    }
}


/**
 * Sandbox isolation capabilities.
 */
enum class IsolationCapability {

    /**
     * Prevents access outside the sandbox filesystem.
     */
    FILESYSTEM_ISOLATION,

    /**
     * Separates sandbox execution from the host process.
     */
    PROCESS_ISOLATION,

    /**
     * Prevents unauthorized network communication.
     */
    NETWORK_ISOLATION,

    /**
     * Prevents access to sensitive device/application data.
     */
    DEVICE_DATA_ISOLATION,

    /**
     * Provides resource boundaries.
     */
    RESOURCE_ISOLATION,

    /**
     * Restricts inter-process communication.
     */
    IPC_ISOLATION,

    /**
     * Restricts debugger interaction.
     */
    DEBUGGER_ISOLATION,

    /**
     * Restricts external/shared storage.
     */
    STORAGE_ISOLATION
}


/**
 * Current state of sandbox isolation.
 */
enum class IsolationState {

    /**
     * Isolation context exists but has not been prepared.
     */
    CREATED,

    /**
     * Isolation preparation is in progress.
     */
    PREPARING,

    /**
     * Isolation has been successfully established.
     */
    ISOLATED,

    /**
     * Sandbox is actively running inside the isolated environment.
     */
    RUNNING,

    /**
     * Sandbox execution is temporarily paused.
     */
    PAUSED,

    /**
     * Isolation guarantees are no longer fully trusted.
     */
    DEGRADED,

    /**
     * Isolation establishment failed.
     */
    FAILED,

    /**
     * Isolation context has been destroyed.
     */
    DESTROYED
}


/**
 * Isolation failure reasons.
 */
enum class IsolationFailureReason {

    UNKNOWN,

    ALREADY_DESTROYED,

    PROCESS_ISOLATION_FAILED,

    FILESYSTEM_ISOLATION_FAILED,

    NETWORK_ISOLATION_FAILED,

    DEVICE_ISOLATION_FAILED,

    RESOURCE_ISOLATION_FAILED,

    IPC_ISOLATION_FAILED,

    POLICY_CONFIGURATION_FAILED,

    PLATFORM_UNSUPPORTED
}


/**
 * Types of isolation violations.
 */
enum class IsolationViolationType {

    FILESYSTEM_ESCAPE_ATTEMPT,

    UNAUTHORIZED_PROCESS_ACCESS,

    NETWORK_ESCAPE_ATTEMPT,

    DEVICE_DATA_ACCESS_ATTEMPT,

    IPC_VIOLATION,

    RESOURCE_BOUNDARY_BYPASS,

    DEBUGGER_ACCESS_ATTEMPT,

    EXTERNAL_STORAGE_ACCESS_ATTEMPT,

    UNAUTHORIZED_CAPABILITY_REQUEST,

    POLICY_VIOLATION
}


/**
 * Runtime isolation context for one sandbox.
 */
data class SandboxIsolationContext(

    /**
     * Sandbox identifier.
     */
    val sandboxId: String,

    /**
     * Policy controlling this isolation context.
     */
    val policyId: String,

    /**
     * Current isolation state.
     */
    var state: IsolationState,

    /**
     * Available/enabled isolation capabilities.
     */
    val capabilities:
        MutableMap<
            IsolationCapability,
            Boolean
        >,

    /**
     * Original capabilities allowed by the policy.
     *
     * This prevents runtime code from escalating privileges
     * simply by calling enableCapability().
     */
    val allowedCapabilities:
        Set<IsolationCapability> =
            capabilities
                .filterValues { it }
                .keys,

    /**
     * Maximum permitted violations.
     */
    val maxViolations: Int =
        DEFAULT_MAX_VIOLATIONS,

    /**
     * Number of detected violations.
     */
    var violationCount: Int = 0,

    /**
     * Whether isolation has been hardened.
     */
    var hardened: Boolean = false,

    /**
     * Time at which isolation was established.
     */
    var isolationEstablishedAt: Long = 0L,

    /**
     * Time at which isolation was destroyed.
     */
    var destroyedAt: Long = 0L,

    /**
     * Last failure reason.
     */
    var failureReason:
        IsolationFailureReason? = null,

    /**
     * Last detected violation.
     */
    var lastViolation:
        IsolationViolation? = null
)


/**
 * Result of an isolation preparation operation.
 */
data class IsolationOperationResult(

    val sandboxId: String,

    val successful: Boolean,

    val reason:
        IsolationFailureReason? = null
) {

    companion object {

        fun success(
            sandboxId: String
        ): IsolationOperationResult {

            return IsolationOperationResult(
                sandboxId = sandboxId,
                successful = true
            )
        }

        fun failure(
            sandboxId: String,
            reason: IsolationFailureReason
        ): IsolationOperationResult {

            return IsolationOperationResult(
                sandboxId = sandboxId,
                successful = false,
                reason = reason
            )
        }
    }
}


/**
 * Result of validating isolation requirements.
 */
data class IsolationValidationResult(

    val valid: Boolean,

    val sandboxId: String,

    val missingCapabilities:
        Set<IsolationCapability>,

    val reason: String?
)


/**
 * Detailed isolation violation record.
 */
data class IsolationViolation(

    val sandboxId: String,

    val type: IsolationViolationType,

    val violationNumber: Int,

    val detectedAt: Long =
        System.currentTimeMillis()
)


/**
 * Snapshot of the sandbox isolation state.
 */
data class SandboxIsolationSnapshot(

    val sandboxId: String,

    val state: IsolationState,

    val policyId: String,

    val enabledCapabilities:
        Set<IsolationCapability>,

    val disabledCapabilities:
        Set<IsolationCapability>,

    val violationCount: Int,

    val hardened: Boolean,

    val failureReason:
        IsolationFailureReason?,

    val lastViolation:
        IsolationViolation?
)
