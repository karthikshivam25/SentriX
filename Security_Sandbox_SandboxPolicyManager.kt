package com.sentrix.security.sandbox

import java.util.concurrent.ConcurrentHashMap

/**
 * SandboxPolicyManager
 *
 * Central manager responsible for the lifecycle of SentriX sandbox
 * security policies.
 *
 * Responsibilities:
 *
 * - Register sandbox policies.
 * - Retrieve policies by ID.
 * - Select appropriate policies for analysis types.
 * - Validate policies before registration.
 * - Update policies.
 * - Remove policies.
 * - Harden policies when threat severity increases.
 * - Provide the default SentriX policy.
 * - Prevent invalid policies from entering the sandbox subsystem.
 *
 * Architecture:
 *
 *              SandboxService
 *                    |
 *                    v
 *          SandboxPolicyManager
 *                    |
 *                    v
 *              SandboxPolicy
 *                    |
 *          ┌─────────┴─────────┐
 *          v                   v
 * SandboxEnvironment    SandboxExecutor
 *
 * IMPORTANT:
 *
 * SandboxPolicyManager does NOT enforce policy restrictions.
 *
 * It determines WHICH policy should be used.
 *
 * Actual enforcement belongs to:
 *
 * - SandboxExecutor
 * - SandboxIsolationController
 * - SandboxResourceLimiter
 *
 * This separation follows the Single Responsibility Principle and
 * prevents policy management from becoming coupled to execution.
 */
class SandboxPolicyManager {

    companion object {

        /**
         * Default policy ID.
         */
        const val DEFAULT_POLICY_ID =
            SandboxPolicy.DEFAULT_POLICY_ID

        /**
         * Maximum number of custom policies that can be registered.
         *
         * This prevents uncontrolled policy accumulation.
         */
        private const val MAX_REGISTERED_POLICIES = 100

        /**
         * Default policy name used by SentriX.
         */
        private const val DEFAULT_POLICY_NAME =
            "SentriX Default Secure Sandbox Policy"
    }

    /**
     * Thread-safe policy registry.
     *
     * Policy lookups may happen from:
     *
     * - UI
     * - background workers
     * - security scans
     * - threat analysis
     * - sandbox execution workflows
     */
    private val policies =
        ConcurrentHashMap<String, SandboxPolicy>()

    /**
     * Initializes the manager with SentriX's default policy.
     */
    init {
        registerDefaultPolicies()
    }

    /**
     * Registers the default SentriX policy profiles.
     */
    private fun registerDefaultPolicies() {

        registerPolicy(
            SandboxPolicy(
                policyId = DEFAULT_POLICY_ID,
                name = DEFAULT_POLICY_NAME
            )
        )

        registerPolicy(
            SandboxPolicy.staticAnalysis()
                .copy(
                    policyId = STATIC_ANALYSIS_POLICY_ID
                )
        )

        registerPolicy(
            SandboxPolicy.fileAnalysis()
                .copy(
                    policyId = FILE_ANALYSIS_POLICY_ID
                )
        )

        registerPolicy(
            SandboxPolicy.malwareAnalysis()
                .copy(
                    policyId = MALWARE_ANALYSIS_POLICY_ID
                )
        )
    }

    /**
     * Registers a new sandbox policy.
     *
     * @throws IllegalArgumentException when the policy is invalid.
     * @throws IllegalStateException when the registry is full or the
     * policy ID already exists.
     */
    @Synchronized
    fun registerPolicy(
        policy: SandboxPolicy,
        overwrite: Boolean = false
    ): Boolean {

        val validation =
            policy.validate()

        validation.requireValid()

        if (!overwrite &&
            policies.containsKey(policy.policyId)
        ) {
            throw IllegalStateException(
                "Sandbox policy already exists: " +
                    policy.policyId
            )
        }

        if (!overwrite &&
            policies.size >= MAX_REGISTERED_POLICIES
        ) {
            throw IllegalStateException(
                "Maximum registered sandbox policies reached."
            )
        }

        policies[policy.policyId] = policy

        return true
    }

    /**
     * Retrieves a policy by its ID.
     */
    fun getPolicy(
        policyId: String
    ): SandboxPolicy? {

        if (policyId.isBlank()) {
            return null
        }

        return policies[policyId]
    }

    /**
     * Retrieves the default SentriX policy.
     */
    fun getDefaultPolicy(): SandboxPolicy {

        return policies[DEFAULT_POLICY_ID]
            ?: throw IllegalStateException(
                "SentriX default sandbox policy is not registered."
            )
    }

    /**
     * Checks whether a policy exists.
     */
    fun hasPolicy(
        policyId: String
    ): Boolean {

        return policies.containsKey(policyId)
    }

    /**
     * Returns all registered policies.
     *
     * A snapshot is returned rather than exposing the internal map.
     */
    fun getAllPolicies(): List<SandboxPolicy> {

        return policies.values.toList()
    }

    /**
     * Returns the number of registered policies.
     */
    fun getPolicyCount(): Int {

        return policies.size
    }

    /**
     * Updates an existing policy.
     *
     * The policy must already exist unless overwrite semantics are
     * explicitly handled through registerPolicy().
     */
    @Synchronized
    fun updatePolicy(
        policy: SandboxPolicy
    ): Boolean {

        val existing =
            policies[policy.policyId]
                ?: throw IllegalArgumentException(
                    "Sandbox policy does not exist: " +
                        policy.policyId
                )

        if (existing.immutableDuringExecution) {
            /*
             * The manager does not track individual running
             * environments. Therefore this check only ensures that
             * immutable policies are not accidentally replaced by
             * callers using updatePolicy().
             *
             * A future PolicyDeploymentManager can coordinate
             * version changes with active sandbox sessions.
             */
        }

        policy.validate()
            .requireValid()

        policies[policy.policyId] = policy

        return true
    }

    /**
     * Removes a policy.
     *
     * The default policy cannot be removed.
     */
    @Synchronized
    fun removePolicy(
        policyId: String
    ): Boolean {

        require(policyId.isNotBlank()) {
            "Policy ID cannot be empty."
        }

        if (policyId == DEFAULT_POLICY_ID) {
            throw IllegalArgumentException(
                "The default SentriX sandbox policy cannot be removed."
            )
        }

        return policies.remove(policyId) != null
    }

    /**
     * Returns the policy appropriate for a sandbox analysis type.
     */
    fun getPolicyForAnalysis(
        analysisType: SandboxService.SandboxAnalysisType
    ): SandboxPolicy {

        return when (analysisType) {

            SandboxService.SandboxAnalysisType.APK_ANALYSIS ->
                getStaticAnalysisPolicy()

            SandboxService.SandboxAnalysisType.FILE_ANALYSIS ->
                getFileAnalysisPolicy()

            SandboxService.SandboxAnalysisType.PDF_ANALYSIS ->
                getFileAnalysisPolicy()

            SandboxService.SandboxAnalysisType.MALWARE_ANALYSIS ->
                getMalwareAnalysisPolicy()

            SandboxService.SandboxAnalysisType.BEHAVIOR_ANALYSIS ->
                getMalwareAnalysisPolicy()

            SandboxService.SandboxAnalysisType.STATIC_ANALYSIS ->
                getStaticAnalysisPolicy()

            SandboxService.SandboxAnalysisType.NETWORK_ANALYSIS ->
                getNetworkRestrictedPolicy()
        }
    }

    /**
     * Returns the static-analysis policy.
     */
    fun getStaticAnalysisPolicy(): SandboxPolicy {

        return getPolicy(
            STATIC_ANALYSIS_POLICY_ID
        ) ?: throw IllegalStateException(
            "Static analysis policy is not registered."
        )
    }

    /**
     * Returns the file-analysis policy.
     */
    fun getFileAnalysisPolicy(): SandboxPolicy {

        return getPolicy(
            FILE_ANALYSIS_POLICY_ID
        ) ?: throw IllegalStateException(
            "File analysis policy is not registered."
        )
    }

    /**
     * Returns the malware-analysis policy.
     */
    fun getMalwareAnalysisPolicy(): SandboxPolicy {

        return getPolicy(
            MALWARE_ANALYSIS_POLICY_ID
        ) ?: throw IllegalStateException(
            "Malware analysis policy is not registered."
        )
    }

    /**
     * Returns a highly restricted network-analysis policy.
     *
     * Network analysis in SentriX should normally use captured,
     * simulated, or controlled traffic rather than allowing an
     * untrusted sample unrestricted access to the Internet.
     */
    fun getNetworkRestrictedPolicy(): SandboxPolicy {

        return getDefaultPolicy()
            .hardened()
            .copy(
                policyId = NETWORK_ANALYSIS_POLICY_ID,
                name = "SentriX Restricted Network Analysis Policy",
                networkAccess = false,
                outboundNetworkAccess = false,
                inboundNetworkAccess = false,
                dnsAccess = false
            )
    }

    /**
     * Creates a hardened copy of an existing policy.
     *
     * The original policy is never modified.
     */
    fun hardenPolicy(
        policyId: String
    ): SandboxPolicy {

        val policy =
            getPolicy(policyId)
                ?: throw IllegalArgumentException(
                    "Sandbox policy not found: $policyId"
                )

        return policy.hardened()
    }

    /**
     * Creates and registers a hardened policy derived from
     * an existing policy.
     */
    @Synchronized
    fun createHardenedPolicy(
        sourcePolicyId: String,
        newPolicyId: String,
        policyName: String? = null
    ): SandboxPolicy {

        require(newPolicyId.isNotBlank()) {
            "New policy ID cannot be empty."
        }

        if (hasPolicy(newPolicyId)) {
            throw IllegalStateException(
                "Policy already exists: $newPolicyId"
            )
        }

        val sourcePolicy =
            getPolicy(sourcePolicyId)
                ?: throw IllegalArgumentException(
                    "Source policy not found: " +
                        sourcePolicyId
                )

        val hardenedPolicy =
            sourcePolicy
                .hardened()
                .copy(
                    policyId = newPolicyId,
                    name = policyName
                        ?: "${sourcePolicy.name} - Hardened"
                )

        registerPolicy(
            hardenedPolicy
        )

        return hardenedPolicy
    }

    /**
     * Creates a policy for high-risk threat analysis.
     */
    @Synchronized
    fun createHighRiskPolicy(
        sourcePolicyId: String = DEFAULT_POLICY_ID,
        newPolicyId: String = HIGH_RISK_POLICY_ID
    ): SandboxPolicy {

        if (hasPolicy(newPolicyId)) {
            return getPolicy(
                newPolicyId
            )!!
        }

        val sourcePolicy =
            getPolicy(sourcePolicyId)
                ?: throw IllegalArgumentException(
                    "Source policy not found: " +
                        sourcePolicyId
                )

        val highRiskPolicy =
            sourcePolicy
                .hardened()
                .copy(
                    policyId = newPolicyId,
                    name =
                        "SentriX High-Risk Threat Analysis Policy",

                    maxMemoryBytes =
                        64L * 1024L * 1024L,

                    maxCpuTimeMs =
                        15_000L,

                    maxExecutionTimeMs =
                        30_000L,

                    maxThreads = 1,

                    maxFileCount = 500,

                    maxTemporaryStorageBytes =
                        25L * 1024L * 1024L,

                    maxSecurityViolations = 0,

                    terminateOnSecurityViolation = true
                )

        registerPolicy(
            highRiskPolicy
        )

        return highRiskPolicy
    }

    /**
     * Validates a registered policy.
     */
    fun validatePolicy(
        policyId: String
    ): PolicyValidationResult {

        val policy =
            getPolicy(policyId)
                ?: return PolicyValidationResult(
                    valid = false,
                    errors = listOf(
                        "Policy not found: $policyId"
                    )
                )

        return policy.validate()
    }

    /**
     * Validates every registered policy.
     *
     * Useful during:
     *
     * - Application startup
     * - Security diagnostics
     * - Configuration verification
     * - Automated tests
     */
    fun validateAllPolicies(): PolicyRegistryValidationResult {

        val results =
            policies.values.associate { policy ->

                policy.policyId to
                    policy.validate()
            }

        val invalidPolicies =
            results.filterValues {
                !it.valid
            }

        return PolicyRegistryValidationResult(
            valid = invalidPolicies.isEmpty(),
            totalPolicies = results.size,
            invalidPolicies = invalidPolicies.keys.toList()
        )
    }

    /**
     * Resets the policy registry to the built-in defaults.
     *
     * Custom policies are removed.
     */
    @Synchronized
    fun resetToDefaults() {

        policies.clear()

        registerDefaultPolicies()
    }

    /**
     * Returns a summary of the current policy registry.
     */
    fun getRegistrySummary(): SandboxPolicyRegistrySummary {

        val hardenedCount =
            policies.values.count {
                it.isHardened()
            }

        return SandboxPolicyRegistrySummary(
            totalPolicies = policies.size,
            hardenedPolicies = hardenedCount,
            customPolicies =
                (policies.size -
                    DEFAULT_POLICY_IDS.size)
                    .coerceAtLeast(0)
        )
    }

    companion object PolicyIds {

        const val STATIC_ANALYSIS_POLICY_ID =
            "SENTRIX_STATIC_ANALYSIS"

        const val FILE_ANALYSIS_POLICY_ID =
            "SENTRIX_FILE_ANALYSIS"

        const val MALWARE_ANALYSIS_POLICY_ID =
            "SENTRIX_MALWARE_ANALYSIS"

        const val NETWORK_ANALYSIS_POLICY_ID =
            "SENTRIX_NETWORK_ANALYSIS"

        const val HIGH_RISK_POLICY_ID =
            "SENTRIX_HIGH_RISK"

        private val DEFAULT_POLICY_IDS =
            setOf(
                DEFAULT_POLICY_ID,
                STATIC_ANALYSIS_POLICY_ID,
                FILE_ANALYSIS_POLICY_ID,
                MALWARE_ANALYSIS_POLICY_ID
            )
    }
}


/**
 * Result of validating the entire sandbox policy registry.
 */
data class PolicyRegistryValidationResult(

    /**
     * True when every registered policy is valid.
     */
    val valid: Boolean,

    /**
     * Total number of registered policies.
     */
    val totalPolicies: Int,

    /**
     * IDs of policies that failed validation.
     */
    val invalidPolicies: List<String>
)


/**
 * Summary of registered sandbox policies.
 */
data class SandboxPolicyRegistrySummary(

    /**
     * Total registered policies.
     */
    val totalPolicies: Int,

    /**
     * Number of hardened policies.
     */
    val hardenedPolicies: Int,

    /**
     * Number of policies beyond the built-in defaults.
     */
    val customPolicies: Int
)
