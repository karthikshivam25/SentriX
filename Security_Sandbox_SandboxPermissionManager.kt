package com.sentrix.security.sandbox

import java.util.concurrent.ConcurrentHashMap

/**
 * SandboxPermissionManager
 *
 * Central permission-management component for SentriX sandbox
 * environments.
 *
 * Responsibilities:
 *
 * - Register permissions for sandbox sessions.
 * - Grant/revoke sandbox capabilities.
 * - Check whether a capability is permitted.
 * - Enforce policy-derived permission decisions.
 * - Track permission state.
 * - Track permission violations.
 * - Prevent unauthorized capability escalation.
 * - Provide permission snapshots for security reporting.
 *
 * Architectural role:
 *
 * SandboxService
 *       |
 *       v
 * SandboxPermissionManager
 *       |
 *       +--------------------+
 *       |                    |
 *       v                    v
 * SandboxPolicy       SandboxEnvironment
 *                            |
 *                            v
 *                  SandboxIsolationController
 *
 * IMPORTANT:
 *
 * This class manages permission decisions and state.
 *
 * It does NOT by itself grant Android runtime permissions or
 * bypass Android's permission model.
 *
 * Actual enforcement must happen through the corresponding
 * Android/platform mechanism and SentriX's isolation layer.
 */
class SandboxPermissionManager {

    companion object {

        /**
         * Maximum number of sandbox permission contexts.
         */
        private const val MAX_PERMISSION_CONTEXTS = 100

        /**
         * Default maximum permission violations before a sandbox
         * should be considered unsafe.
         */
        private const val DEFAULT_MAX_VIOLATIONS = 0
    }

    /**
     * Permission contexts indexed by sandbox ID.
     */
    private val permissionContexts =
        ConcurrentHashMap<String, SandboxPermissionContext>()

    /**
     * Creates a permission context for a sandbox.
     *
     * Permissions are derived from the supplied SandboxPolicy.
     */
    @Synchronized
    fun registerSandbox(
        sandboxId: String,
        policy: SandboxPolicy
    ): SandboxPermissionContext {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        policy.validate()
            .requireValid()

        val existing =
            permissionContexts[sandboxId]

        if (existing != null) {
            return existing
        }

        if (permissionContexts.size >=
            MAX_PERMISSION_CONTEXTS
        ) {
            throw IllegalStateException(
                "Maximum sandbox permission contexts reached."
            )
        }

        val context =
            SandboxPermissionContext(
                sandboxId = sandboxId,
                permissions =
                    buildPermissionsFromPolicy(policy),
                maxViolations =
                    if (policy.terminateOnSecurityViolation) {
                        policy.maxSecurityViolations
                    } else {
                        Int.MAX_VALUE
                    }
            )

        permissionContexts[sandboxId] =
            context

        return context
    }

    /**
     * Returns a sandbox permission context.
     */
    fun getPermissionContext(
        sandboxId: String
    ): SandboxPermissionContext? {

        return permissionContexts[sandboxId]
    }

    /**
     * Checks whether a sandbox has a specific capability.
     */
    fun isPermissionGranted(
        sandboxId: String,
        permission: SandboxPermission
    ): Boolean {

        val context =
            permissionContexts[sandboxId]
                ?: return false

        val state =
            context.permissions[permission]
                ?: PermissionState.DENIED

        return state == PermissionState.GRANTED
    }

    /**
     * Checks whether a permission can be used.
     *
     * This is the primary method that execution components should
     * call before performing a sensitive sandbox operation.
     */
    fun checkPermission(
        sandboxId: String,
        permission: SandboxPermission
    ): PermissionCheckResult {

        val context =
            permissionContexts[sandboxId]
                ?: return PermissionCheckResult(
                    sandboxId = sandboxId,
                    permission = permission,
                    allowed = false,
                    reason =
                        PermissionDenyReason
                            .SANDBOX_NOT_REGISTERED
                )

        val state =
            context.permissions[permission]
                ?: PermissionState.DENIED

        return when (state) {

            PermissionState.GRANTED ->
                PermissionCheckResult(
                    sandboxId = sandboxId,
                    permission = permission,
                    allowed = true,
                    reason =
                        PermissionDenyReason
                            .NONE
                )

            PermissionState.DENIED ->
                PermissionCheckResult(
                    sandboxId = sandboxId,
                    permission = permission,
                    allowed = false,
                    reason =
                        PermissionDenyReason
                            .POLICY_DENIED
                )

            PermissionState.REVOKED ->
                PermissionCheckResult(
                    sandboxId = sandboxId,
                    permission = permission,
                    allowed = false,
                    reason =
                        PermissionDenyReason
                            .PERMISSION_REVOKED
                ),

            PermissionState.SUSPENDED ->
                PermissionCheckResult(
                    sandboxId = sandboxId,
                    permission = permission,
                    allowed = false,
                    reason =
                        PermissionDenyReason
                            .PERMISSION_SUSPENDED
                )
        }
    }

    /**
     * Requests a sandbox capability.
     *
     * A permission can only be granted when it is allowed by the
     * current policy.
     */
    fun requestPermission(
        sandboxId: String,
        permission: SandboxPermission
    ): PermissionCheckResult {

        val context =
            permissionContexts[sandboxId]
                ?: return PermissionCheckResult(
                    sandboxId = sandboxId,
                    permission = permission,
                    allowed = false,
                    reason =
                        PermissionDenyReason
                            .SANDBOX_NOT_REGISTERED
                )

        /*
         * A request cannot escalate a permission that the policy
         * explicitly denied.
         */
        if (!isPolicyCompatible(
                context.policy,
                permission
            )
        ) {

            recordViolation(
                sandboxId = sandboxId,
                permission = permission
            )

            return PermissionCheckResult(
                sandboxId = sandboxId,
                permission = permission,
                allowed = false,
                reason =
                    PermissionDenyReason
                        .POLICY_DENIED
            )
        }

        context.permissions[
            permission
        ] = PermissionState.GRANTED

        return PermissionCheckResult(
            sandboxId = sandboxId,
            permission = permission,
            allowed = true,
            reason = PermissionDenyReason.NONE
        )
    }

    /**
     * Explicitly grants a permission.
     *
     * This method is intended for trusted internal configuration
     * workflows and should not be exposed directly to untrusted
     * sandbox content.
     */
    fun grantPermission(
        sandboxId: String,
        permission: SandboxPermission
    ): Boolean {

        val context =
            requireContext(sandboxId)

        if (!isPolicyCompatible(
                context.policy,
                permission
            )
        ) {
            return false
        }

        context.permissions[
            permission
        ] = PermissionState.GRANTED

        return true
    }

    /**
     * Revokes a previously granted permission.
     */
    fun revokePermission(
        sandboxId: String,
        permission: SandboxPermission
    ): Boolean {

        val context =
            requireContext(sandboxId)

        val current =
            context.permissions[permission]
                ?: return false

        if (current != PermissionState.GRANTED) {
            return false
        }

        context.permissions[
            permission
        ] = PermissionState.REVOKED

        return true
    }

    /**
     * Denies a permission.
     */
    fun denyPermission(
        sandboxId: String,
        permission: SandboxPermission
    ): Boolean {

        val context =
            requireContext(sandboxId)

        context.permissions[
            permission
        ] = PermissionState.DENIED

        return true
    }

    /**
     * Temporarily suspends a permission.
     *
     * Useful when SentriX detects suspicious behavior while
     * retaining the sandbox itself for analysis.
     */
    fun suspendPermission(
        sandboxId: String,
        permission: SandboxPermission
    ): Boolean {

        val context =
            requireContext(sandboxId)

        context.permissions[
            permission
        ] = PermissionState.SUSPENDED

        return true
    }

    /**
     * Restores a permission to the policy-derived state.
     */
    fun restorePermission(
        sandboxId: String,
        permission: SandboxPermission
    ): Boolean {

        val context =
            requireContext(sandboxId)

        val policyAllows =
            isPolicyCompatible(
                context.policy,
                permission
            )

        context.permissions[
            permission
        ] =
            if (policyAllows) {
                PermissionState.GRANTED
            } else {
                PermissionState.DENIED
            }

        return policyAllows
    }

    /**
     * Checks multiple permissions at once.
     */
    fun checkPermissions(
        sandboxId: String,
        permissions: Set<SandboxPermission>
    ): SandboxPermissionSummary {

        val results =
            permissions.associateWith { permission ->

                checkPermission(
                    sandboxId = sandboxId,
                    permission = permission
                )
            }

        val granted =
            results.count {
                it.value.allowed
            }

        val denied =
            results.size - granted

        return SandboxPermissionSummary(
            sandboxId = sandboxId,
            totalRequested = results.size,
            granted = granted,
            denied = denied,
            results = results
        )
    }

    /**
     * Returns all currently granted permissions.
     */
    fun getGrantedPermissions(
        sandboxId: String
    ): Set<SandboxPermission> {

        val context =
            permissionContexts[sandboxId]
                ?: return emptySet()

        return context.permissions
            .filterValues {
                it == PermissionState.GRANTED
            }
            .keys
    }

    /**
     * Returns all denied permissions.
     */
    fun getDeniedPermissions(
        sandboxId: String
    ): Set<SandboxPermission> {

        val context =
            permissionContexts[sandboxId]
                ?: return emptySet()

        return context.permissions
            .filterValues {
                it == PermissionState.DENIED
            }
            .keys
    }

    /**
     * Returns all revoked permissions.
     */
    fun getRevokedPermissions(
        sandboxId: String
    ): Set<SandboxPermission> {

        val context =
            permissionContexts[sandboxId]
                ?: return emptySet()

        return context.permissions
            .filterValues {
                it == PermissionState.REVOKED
            }
            .keys
    }

    /**
     * Returns all suspended permissions.
     */
    fun getSuspendedPermissions(
        sandboxId: String
    ): Set<SandboxPermission> {

        val context =
            permissionContexts[sandboxId]
                ?: return emptySet()

        return context.permissions
            .filterValues {
                it == PermissionState.SUSPENDED
            }
            .keys
    }

    /**
     * Records a permission violation.
     */
    fun recordViolation(
        sandboxId: String,
        permission: SandboxPermission
    ): PermissionViolation {

        val context =
            requireContext(sandboxId)

        val violationCount =
            context.violationCount + 1

        context.violationCount =
            violationCount

        val violation =
            PermissionViolation(
                sandboxId = sandboxId,
                permission = permission,
                violationNumber = violationCount
            )

        context.lastViolation =
            violation

        if (violationCount >
            context.maxViolations
        ) {
            context.securityEscalated = true
        }

        return violation
    }

    /**
     * Returns the number of permission violations.
     */
    fun getViolationCount(
        sandboxId: String
    ): Int {

        return requireContext(
            sandboxId
        ).violationCount
    }

    /**
     * Determines whether the sandbox has exceeded its permission
     * violation threshold.
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
     * Determines whether the sandbox should be considered
     * security-escalated.
     */
    fun isSecurityEscalated(
        sandboxId: String
    ): Boolean {

        return requireContext(
            sandboxId
        ).securityEscalated
    }

    /**
     * Immediately revokes all permissions.
     *
     * Useful when a sandbox demonstrates malicious behavior.
     */
    fun revokeAllPermissions(
        sandboxId: String
    ) {

        val context =
            requireContext(sandboxId)

        context.permissions.keys.forEach {
            permission ->
            context.permissions[
                permission
            ] = PermissionState.REVOKED
        }

        context.securityEscalated = true
    }

    /**
     * Restores all permissions to their policy-defined state.
     *
     * This should only be used when a sandbox remains trusted enough
     * to continue analysis.
     */
    fun restorePolicyPermissions(
        sandboxId: String
    ) {

        val context =
            requireContext(sandboxId)

        context.permissions.keys.forEach {
            permission ->

            context.permissions[
                permission
            ] =
                if (
                    isPolicyCompatible(
                        context.policy,
                        permission
                    )
                ) {
                    PermissionState.GRANTED
                } else {
                    PermissionState.DENIED
                }
        }
    }

    /**
     * Returns a complete permission snapshot.
     */
    fun getPermissionSnapshot(
        sandboxId: String
    ): SandboxPermissionSnapshot {

        val context =
            requireContext(sandboxId)

        return SandboxPermissionSnapshot(
            sandboxId = sandboxId,
            granted =
                getGrantedPermissions(sandboxId),
            denied =
                getDeniedPermissions(sandboxId),
            revoked =
                getRevokedPermissions(sandboxId),
            suspended =
                getSuspendedPermissions(sandboxId),
            violationCount =
                context.violationCount,
            securityEscalated =
                context.securityEscalated
        )
    }

    /**
     * Releases all permission information for a sandbox.
     *
     * This should normally happen after the sandbox has been
     * terminated and its resources cleaned.
     */
    @Synchronized
    fun releaseSandbox(
        sandboxId: String
    ): Boolean {

        return permissionContexts.remove(
            sandboxId
        ) != null
    }

    /**
     * Releases every permission context.
     */
    @Synchronized
    fun releaseAll() {

        permissionContexts.clear()
    }

    /**
     * Returns the number of tracked permission contexts.
     */
    fun getContextCount(): Int {

        return permissionContexts.size
    }

    /**
     * Builds initial sandbox permissions from the security policy.
     *
     * The important principle here is:
     *
     * "Default deny unless the policy explicitly allows."
     */
    private fun buildPermissionsFromPolicy(
        policy: SandboxPolicy
    ): MutableMap<
        SandboxPermission,
        PermissionState
    > {

        return SandboxPermission.entries
            .associateWith { permission ->

                if (
                    isPolicyCompatible(
                        policy,
                        permission
                    )
                ) {
                    PermissionState.GRANTED
                } else {
                    PermissionState.DENIED
                }
            }
            .toMutableMap()
    }

    /**
     * Determines whether a permission is compatible with the
     * supplied SandboxPolicy.
     */
    private fun isPolicyCompatible(
        policy: SandboxPolicy,
        permission: SandboxPermission
    ): Boolean {

        return when (permission) {

            SandboxPermission.NETWORK_ACCESS ->
                policy.networkAccess

            SandboxPermission.OUTBOUND_NETWORK ->
                policy.outboundNetworkAccess

            SandboxPermission.INBOUND_NETWORK ->
                policy.inboundNetworkAccess

            SandboxPermission.DNS_ACCESS ->
                policy.dnsAccess

            SandboxPermission.EXTERNAL_STORAGE ->
                policy.externalStorageAccess

            SandboxPermission.APPLICATION_DATA ->
                policy.applicationDataAccess

            SandboxPermission.SHARED_APPLICATION_DATA ->
                policy.sharedApplicationDataAccess

            SandboxPermission.PROCESS_CREATION ->
                policy.processCreationAllowed

            SandboxPermission.CHILD_PROCESS_CREATION ->
                policy.childProcessCreationAllowed

            SandboxPermission.DYNAMIC_CODE_EXECUTION ->
                policy.dynamicCodeExecutionAllowed

            SandboxPermission.NATIVE_LIBRARY_LOADING ->
                policy.nativeLibraryLoadingAllowed

            SandboxPermission.REFLECTION ->
                policy.reflectionAllowed

            SandboxPermission.FILE_READ ->
                policy.fileReadAccess

            SandboxPermission.FILE_WRITE ->
                policy.fileWriteAccess

            SandboxPermission.HOST_FILESYSTEM ->
                policy.hostFilesystemAccess

            SandboxPermission.SYMBOLIC_LINKS ->
                policy.symbolicLinksAllowed

            SandboxPermission.EXECUTABLE_FILE_CREATION ->
                policy.executableFileCreationAllowed

            SandboxPermission.CLIPBOARD ->
                policy.clipboardAccess

            SandboxPermission.SENSORS ->
                policy.sensorAccess

            SandboxPermission.CAMERA ->
                policy.cameraAccess

            SandboxPermission.MICROPHONE ->
                policy.microphoneAccess

            SandboxPermission.LOCATION ->
                policy.locationAccess

            SandboxPermission.NOTIFICATIONS ->
                policy.notificationAccess

            SandboxPermission.ACCESSIBILITY ->
                policy.accessibilityAccess

            SandboxPermission.BIOMETRIC ->
                policy.biometricAccess

            SandboxPermission.VPN ->
                policy.vpnAccess

            SandboxPermission.DEBUGGING ->
                policy.debuggingAllowed

            SandboxPermission.DEBUGGER_ATTACH ->
                policy.debuggerAttachAllowed

            SandboxPermission.PERSISTENT_STATE ->
                policy.persistentStateAllowed

            SandboxPermission.SENSITIVE_DATA_LOGGING ->
                policy.sensitiveDataLoggingAllowed

            /*
             * Metadata retention is generally considered a
             * controlled internal capability rather than a
             * dangerous external capability.
             */
            SandboxPermission.METADATA_RETENTION ->
                policy.metadataRetentionAllowed
        }
    }

    /**
     * Returns an existing permission context or throws.
     */
    private fun requireContext(
        sandboxId: String
    ): SandboxPermissionContext {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        return permissionContexts[sandboxId]
            ?: throw IllegalArgumentException(
                "Sandbox permission context not found: " +
                    sandboxId
            )
    }
}


/**
 * Capabilities that can be granted to a SentriX sandbox.
 *
 * These are SentriX-level capabilities.
 *
 * They should not be confused with Android runtime permissions.
 */
enum class SandboxPermission {

    NETWORK_ACCESS,

    OUTBOUND_NETWORK,

    INBOUND_NETWORK,

    DNS_ACCESS,

    EXTERNAL_STORAGE,

    APPLICATION_DATA,

    SHARED_APPLICATION_DATA,

    PROCESS_CREATION,

    CHILD_PROCESS_CREATION,

    DYNAMIC_CODE_EXECUTION,

    NATIVE_LIBRARY_LOADING,

    REFLECTION,

    FILE_READ,

    FILE_WRITE,

    HOST_FILESYSTEM,

    SYMBOLIC_LINKS,

    EXECUTABLE_FILE_CREATION,

    CLIPBOARD,

    SENSORS,

    CAMERA,

    MICROPHONE,

    LOCATION,

    NOTIFICATIONS,

    ACCESSIBILITY,

    BIOMETRIC,

    VPN,

    DEBUGGING,

    DEBUGGER_ATTACH,

    PERSISTENT_STATE,

    SENSITIVE_DATA_LOGGING,

    METADATA_RETENTION
}


/**
 * Current state of a sandbox capability.
 */
enum class PermissionState {

    /**
     * Capability is allowed by policy.
     */
    GRANTED,

    /**
     * Capability is explicitly denied.
     */
    DENIED,

    /**
     * Capability was previously available but has been revoked.
     */
    REVOKED,

    /**
     * Capability is temporarily suspended.
     */
    SUSPENDED
}


/**
 * Reason a permission request was rejected.
 */
enum class PermissionDenyReason {

    NONE,

    SANDBOX_NOT_REGISTERED,

    POLICY_DENIED,

    PERMISSION_REVOKED,

    PERMISSION_SUSPENDED,

    SECURITY_ESCALATION
}


/**
 * Result of checking a sandbox capability.
 */
data class PermissionCheckResult(

    val sandboxId: String,

    val permission: SandboxPermission,

    val allowed: Boolean,

    val reason: PermissionDenyReason
)


/**
 * Aggregated result of checking multiple permissions.
 */
data class SandboxPermissionSummary(

    val sandboxId: String,

    val totalRequested: Int,

    val granted: Int,

    val denied: Int,

    val results:
        Map<
            SandboxPermission,
            PermissionCheckResult
        >
)


/**
 * Permission violation record.
 */
data class PermissionViolation(

    val sandboxId: String,

    val permission: SandboxPermission,

    val violationNumber: Int,

    val detectedAt: Long =
        System.currentTimeMillis()
)


/**
 * Complete permission snapshot for security reporting.
 */
data class SandboxPermissionSnapshot(

    val sandboxId: String,

    val granted:
        Set<SandboxPermission>,

    val denied:
        Set<SandboxPermission>,

    val revoked:
        Set<SandboxPermission>,

    val suspended:
        Set<SandboxPermission>,

    val violationCount: Int,

    val securityEscalated: Boolean
)


/**
 * Permission state associated with one sandbox.
 */
data class SandboxPermissionContext(

    /**
     * Sandbox identifier.
     */
    val sandboxId: String,

    /**
     * Policy from which the initial permissions were derived.
     */
    val policy: SandboxPolicy,

    /**
     * Current permission states.
     */
    val permissions:
        MutableMap<
            SandboxPermission,
            PermissionState
        >,

    /**
     * Maximum permitted violations.
     */
    val maxViolations: Int =
        0,

    /**
     * Number of detected permission violations.
     */
    var violationCount: Int = 0,

    /**
     * Last recorded violation.
     */
    var lastViolation:
        PermissionViolation? = null,

    /**
     * Whether the sandbox has entered a security-escalated state.
     */
    var securityEscalated: Boolean = false
)
