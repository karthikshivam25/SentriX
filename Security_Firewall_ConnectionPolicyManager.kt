package com.sentrix.security.firewall

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * ConnectionPolicyManager
 *
 * Manages high-level network connection policies for SentriX.
 *
 * A policy represents a security intention, while firewall rules
 * represent the concrete conditions used by FirewallRuleEvaluator.
 *
 * Example:
 *
 * Policy:
 *     "Block unknown applications on public Wi-Fi."
 *
 * Rules generated/associated with the policy may contain:
 *
 *     application = unknown
 *     network     = WIFI
 *     action      = BLOCK
 *
 * Responsibilities:
 *
 * - Create connection policies.
 * - Update policies.
 * - Delete policies.
 * - Enable/disable policies.
 * - Manage policy priority.
 * - Manage default connection behavior.
 * - Manage application policies.
 * - Manage network-type policies.
 * - Manage trusted networks.
 * - Manage policy groups.
 * - Evaluate which policy applies to a connection.
 * - Maintain policy statistics.
 *
 * This class DOES NOT:
 *
 * - Intercept packets.
 * - Modify network traffic.
 * - Start VpnService.
 * - Perform DNS lookups.
 * - Contact cloud threat intelligence.
 * - Directly execute firewall actions.
 *
 * Runtime decision flow:
 *
 * NetworkConnection
 *        |
 *        v
 * ConnectionPolicyManager
 *        |
 *        v
 * Applicable ConnectionPolicy
 *        |
 *        v
 * FirewallEngine
 *        |
 *        v
 * FirewallRuleEvaluator
 */
class ConnectionPolicyManager(
    context: Context,
    private val configuration:
        ConnectionPolicyManagerConfiguration =
        ConnectionPolicyManagerConfiguration()
) {

    companion object {

        private const val TAG =
            "ConnectionPolicyManager"

        private const val MAX_POLICIES =
            5_000

        private const val MAX_GROUPS =
            500

        private const val MAX_TRUSTED_NETWORKS =
            1_000
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Policy store.
     */
    private val policies =
        ConcurrentHashMap<
            String,
            ConnectionPolicy
        >()

    /**
     * Policy groups.
     */
    private val groups =
        ConcurrentHashMap<
            String,
            ConnectionPolicyGroup
        >()

    /**
     * Trusted network store.
     */
    private val trustedNetworks =
        ConcurrentHashMap<
            String,
            TrustedNetwork
        >()

    /**
     * Policy statistics.
     */
    private val statistics =
        ConnectionPolicyStatisticsCounter()

    /**
     * Initialization state.
     */
    @Volatile
    private var initialized =
        false

    /**
     * Initializes the policy manager.
     */
    suspend fun initialize():
            ConnectionPolicyOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized
            ) {

                return@withContext
                    ConnectionPolicyOperationResult.success(
                        "Connection policy manager is already initialized."
                    )
            }

            loadBuiltInPolicies()

            initialized = true

            Log.i(
                TAG,
                "ConnectionPolicyManager initialized."
            )

            ConnectionPolicyOperationResult.success(
                "Connection policy manager initialized successfully."
            )
        }

    /**
     * Returns whether the manager is initialized.
     */
    fun isInitialized():
            Boolean {

        return initialized
    }

    /**
     * Creates a connection policy.
     */
    suspend fun createPolicy(
        request:
            CreateConnectionPolicyRequest
    ): ConnectionPolicyOperationResultWithPolicy =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val validation =
                validatePolicyRequest(
                    request
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    ConnectionPolicyOperationResultWithPolicy.failure(
                        validation.message
                    )
            }

            if (
                policies.size >= MAX_POLICIES
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithPolicy.failure(
                        "Maximum connection policy count reached."
                    )
            }

            val policyId =
                request.id
                    ?.takeIf {
                        it.isNotBlank()
                    }
                    ?: generatePolicyId()

            if (
                policies.containsKey(
                    policyId
                )
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithPolicy.failure(
                        "A policy with this ID already exists."
                    )
            }

            val now =
                System.currentTimeMillis()

            val policy =
                ConnectionPolicy(
                    id =
                        policyId,

                    name =
                        request.name.trim(),

                    description =
                        request.description
                            .trim(),

                    type =
                        request.type,

                    action =
                        request.action,

                    priority =
                        request.priority
                            .coerceIn(
                                configuration.minimumPriority,
                                configuration.maximumPriority
                            ),

                    enabled =
                        request.enabled,

                    packageNames =
                        normalizePackages(
                            request.packageNames
                        ),

                    networkTypes =
                        request.networkTypes
                            .toSet(),

                    protocols =
                        request.protocols
                            .toSet(),

                    minimumThreatLevel =
                        request.minimumThreatLevel,

                    trustedNetworkOnly =
                        request.trustedNetworkOnly,

                    timeWindow =
                        request.timeWindow,

                    ruleIds =
                        request.ruleIds
                            .distinct(),

                    groupId =
                        request.groupId,

                    source =
                        request.source,

                    createdAt =
                        now,

                    updatedAt =
                        now
                )

            policies[
                policyId
            ] =
                policy

            statistics.incrementCreated()

            Log.d(
                TAG,
                "Connection policy created: $policyId"
            )

            ConnectionPolicyOperationResultWithPolicy.success(
                message =
                    "Connection policy created successfully.",
                policy =
                    policy
            )
        }

    /**
     * Updates an existing policy.
     */
    suspend fun updatePolicy(
        policyId:
            String,
        request:
            UpdateConnectionPolicyRequest
    ): ConnectionPolicyOperationResultWithPolicy =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val existing =
                policies[
                    policyId
                ]
                    ?: return@withContext
                        ConnectionPolicyOperationResultWithPolicy.failure(
                            "Connection policy was not found."
                        )

            val updated =
                existing.copy(

                    name =
                        request.name
                            ?.trim()
                            ?: existing.name,

                    description =
                        request.description
                            ?.trim()
                            ?: existing.description,

                    type =
                        request.type
                            ?: existing.type,

                    action =
                        request.action
                            ?: existing.action,

                    priority =
                        request.priority
                            ?.coerceIn(
                                configuration.minimumPriority,
                                configuration.maximumPriority
                            )
                            ?: existing.priority,

                    enabled =
                        request.enabled
                            ?: existing.enabled,

                    packageNames =
                        request.packageNames
                            ?.let {
                                normalizePackages(it)
                            }
                            ?: existing.packageNames,

                    networkTypes =
                        request.networkTypes
                            ?.toSet()
                            ?: existing.networkTypes,

                    protocols =
                        request.protocols
                            ?.toSet()
                            ?: existing.protocols,

                    minimumThreatLevel =
                        request.minimumThreatLevel
                            ?: existing.minimumThreatLevel,

                    trustedNetworkOnly =
                        request.trustedNetworkOnly
                            ?: existing.trustedNetworkOnly,

                    timeWindow =
                        if (
                            request.clearTimeWindow
                        ) {
                            null
                        } else {
                            request.timeWindow
                                ?: existing.timeWindow
                        },

                    ruleIds =
                        request.ruleIds
                            ?.distinct()
                            ?: existing.ruleIds,

                    groupId =
                        if (
                            request.clearGroup
                        ) {
                            null
                        } else {
                            request.groupId
                                ?: existing.groupId
                        },

                    updatedAt =
                        System.currentTimeMillis()
                )

            val validation =
                validatePolicy(
                    updated
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    ConnectionPolicyOperationResultWithPolicy.failure(
                        validation.message
                    )
            }

            policies[
                policyId
            ] =
                updated

            statistics.incrementUpdated()

            ConnectionPolicyOperationResultWithPolicy.success(
                message =
                    "Connection policy updated successfully.",
                policy =
                    updated
            )
        }

    /**
     * Deletes a policy.
     */
    suspend fun deletePolicy(
        policyId:
            String
    ): ConnectionPolicyOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val policy =
                policies[
                    policyId
                ]
                    ?: return@withContext
                        ConnectionPolicyOperationResult.failure(
                            "Connection policy was not found."
                        )

            if (
                policy.source ==
                ConnectionPolicySource.SYSTEM
            ) {

                return@withContext
                    ConnectionPolicyOperationResult.failure(
                        "System policies cannot be deleted."
                    )
            }

            policies.remove(
                policyId
            )

            statistics.incrementDeleted()

            ConnectionPolicyOperationResult.success(
                "Connection policy deleted successfully."
            )
        }

    /**
     * Enables a policy.
     */
    suspend fun enablePolicy(
        policyId:
            String
    ): ConnectionPolicyOperationResult {

        return updatePolicyState(
            policyId =
                policyId,
            enabled =
                true
        )
    }

    /**
     * Disables a policy.
     */
    suspend fun disablePolicy(
        policyId:
            String
    ): ConnectionPolicyOperationResult {

        return updatePolicyState(
            policyId =
                policyId,
            enabled =
                false
        )
    }

    /**
     * Updates policy enabled state.
     */
    private suspend fun updatePolicyState(
        policyId:
            String,
        enabled:
            Boolean
    ): ConnectionPolicyOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val policy =
                policies[
                    policyId
                ]
                    ?: return@withContext
                        ConnectionPolicyOperationResult.failure(
                            "Connection policy was not found."
                        )

            policies[
                policyId
            ] =
                policy.copy(
                    enabled =
                        enabled,

                    updatedAt =
                        System.currentTimeMillis()
                )

            statistics.incrementStateChanges()

            ConnectionPolicyOperationResult.success(
                if (enabled) {
                    "Connection policy enabled."
                } else {
                    "Connection policy disabled."
                }
            )
        }

    /**
     * Returns a policy by ID.
     */
    fun getPolicy(
        policyId:
            String
    ): ConnectionPolicy? {

        return policies[
            policyId
        ]
    }

    /**
     * Returns all policies ordered by priority.
     */
    fun getAllPolicies():
            List<ConnectionPolicy> {

        return policies.values
            .sortedWith(
                compareByDescending<ConnectionPolicy> {
                    it.priority
                }.thenBy {
                    it.name
                }
            )
    }

    /**
     * Returns only enabled policies.
     */
    fun getEnabledPolicies():
            List<ConnectionPolicy> {

        return getAllPolicies()
            .filter {
                it.enabled
            }
    }

    /**
     * Returns policies belonging to an application.
     */
    fun getPoliciesForPackage(
        packageName:
            String
    ): List<ConnectionPolicy> {

        val normalized =
            packageName
                .trim()
                .lowercase()

        return getEnabledPolicies()
            .filter { policy ->

                policy.packageNames.isEmpty() ||
                        policy.packageNames.any {
                            matchesWildcard(
                                normalized,
                                it
                            )
                        }
            }
    }

    /**
     * Returns policies applicable to a network type.
     */
    fun getPoliciesForNetwork(
        networkType:
            NetworkTransportType
    ): List<ConnectionPolicy> {

        return getEnabledPolicies()
            .filter { policy ->

                policy.networkTypes.isEmpty() ||
                        networkType in
                        policy.networkTypes
            }
    }

    /**
     * Evaluates which policy applies to a connection.
     *
     * The first matching policy wins because policies are sorted
     * by descending priority.
     */
    fun evaluateConnection(
        connection:
            NetworkConnection,
        currentTimeMillis:
            Long =
            System.currentTimeMillis()
    ): ConnectionPolicyEvaluationResult {

        val applicablePolicies =
            getEnabledPolicies()

        var evaluated =
            0

        for (
            policy in applicablePolicies
        ) {

            evaluated++

            if (
                matchesPolicy(
                    connection,
                    policy,
                    currentTimeMillis
                )
            ) {

                statistics.incrementEvaluations()

                return ConnectionPolicyEvaluationResult(
                    matched =
                        true,

                    policy =
                        policy,

                    action =
                        policy.action,

                    reason =
                        buildMatchReason(
                            connection,
                            policy
                        ),

                    evaluatedPolicies =
                        evaluated
                )
            }
        }

        statistics.incrementEvaluations()

        val defaultAction =
            getDefaultAction(
                connection
            )

        return ConnectionPolicyEvaluationResult(
            matched =
                false,

            policy =
                null,

            action =
                defaultAction,

            reason =
                "No connection policy matched. " +
                        "Default action=$defaultAction.",

            evaluatedPolicies =
                evaluated
        )
    }

    /**
     * Evaluates a raw network request by creating a lightweight
     * connection representation.
     */
    fun evaluateRequest(
        request:
            FirewallNetworkRequest
    ): ConnectionPolicyEvaluationResult {

        val connection =
            NetworkConnection(
                id =
                    "POLICY_EVALUATION",

                host =
                    request.host,

                remoteIp =
                    request.host,

                sourceIp =
                    null,

                remotePort =
                    request.port,

                localPort =
                    null,

                protocol =
                    request.protocol,

                packageName =
                    request.packageName,

                transport =
                    NetworkTransportType.UNKNOWN,

                state =
                    NetworkConnectionState.CONNECTING,

                direction =
                    NetworkTrafficDirection.OUTBOUND,

                encrypted =
                    true,

                startedAt =
                    System.currentTimeMillis(),

                lastActivityAt =
                    System.currentTimeMillis(),

                bytesSent =
                    0,

                bytesReceived =
                    0,

                firewallDecision =
                    null,

                firewallReason =
                    null,

                matchedRuleId =
                    null,

                threatLevel =
                    NetworkThreatLevel.UNKNOWN
            )

        return evaluateConnection(
            connection
        )
    }

    /**
     * Checks whether a connection matches a policy.
     */
    fun matchesPolicy(
        connection:
            NetworkConnection,
        policy:
            ConnectionPolicy,
        currentTimeMillis:
            Long =
            System.currentTimeMillis()
    ): Boolean {

        if (
            !policy.enabled
        ) {

            return false
        }

        /*
         * Application restriction.
         */
        if (
            policy.packageNames.isNotEmpty()
        ) {

            val packageName =
                connection.packageName
                    ?: return false

            val packageMatches =
                policy.packageNames.any {
                    matchesWildcard(
                        packageName
                            .lowercase(),
                        it.lowercase()
                    )
                }

            if (
                !packageMatches
            ) {

                return false
            }
        }

        /*
         * Network transport restriction.
         */
        if (
            policy.networkTypes.isNotEmpty() &&
            connection.transport !in
            policy.networkTypes
        ) {

            return false
        }

        /*
         * Protocol restriction.
         */
        if (
            policy.protocols.isNotEmpty() &&
            connection.protocol !in
            policy.protocols
        ) {

            return false
        }

        /*
         * Threat-level restriction.
         */
        if (
            connection.threatLevel
                .severity <
            policy.minimumThreatLevel
                .severity
        ) {

            return false
        }

        /*
         * Trusted network restriction.
         */
        if (
            policy.trustedNetworkOnly &&
            !isTrustedConnection(
                connection
            )
        ) {

            return false
        }

        /*
         * Time-window restriction.
         */
        if (
            policy.timeWindow != null &&
            !policy.timeWindow.isActive(
                currentTimeMillis
            )
        ) {

            return false
        }

        return true
    }

    /**
     * Returns default action for a connection.
     */
    fun getDefaultAction(
        connection:
            NetworkConnection
    ): FirewallDecision {

        return when (
            connection.transport
        ) {

            NetworkTransportType.VPN ->
                configuration
                    .defaultVpnAction

            NetworkTransportType.WIFI ->
                configuration
                    .defaultWifiAction

            NetworkTransportType.CELLULAR ->
                configuration
                    .defaultCellularAction

            NetworkTransportType.ETHERNET ->
                configuration
                    .defaultEthernetAction

            NetworkTransportType.BLUETOOTH ->
                configuration
                    .defaultBluetoothAction

            NetworkTransportType.LOWPAN ->
                configuration
                    .defaultLowpanAction

            NetworkTransportType.UNKNOWN,
            NetworkTransportType.NONE ->
                configuration
                    .defaultUnknownNetworkAction
        }
    }

    /**
     * Adds a trusted network.
     */
    suspend fun addTrustedNetwork(
        request:
            AddTrustedNetworkRequest
    ): ConnectionPolicyOperationResultWithTrustedNetwork =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                request.name.isBlank()
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithTrustedNetwork.failure(
                        "Trusted network name cannot be blank."
                    )
            }

            if (
                request.identifier.isBlank()
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithTrustedNetwork.failure(
                        "Trusted network identifier cannot be blank."
                    )
            }

            if (
                trustedNetworks.size >=
                MAX_TRUSTED_NETWORKS
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithTrustedNetwork.failure(
                        "Maximum trusted network count reached."
                    )
            }

            val id =
                request.id
                    ?.takeIf {
                        it.isNotBlank()
                    }
                    ?: generateTrustedNetworkId()

            if (
                trustedNetworks.containsKey(
                    id
                )
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithTrustedNetwork.failure(
                        "Trusted network already exists."
                    )
            }

            val trustedNetwork =
                TrustedNetwork(
                    id =
                        id,

                    name =
                        request.name.trim(),

                    identifier =
                        request.identifier.trim(),

                    transport =
                        request.transport,

                    enabled =
                        request.enabled,

                    createdAt =
                        System.currentTimeMillis()
                )

            trustedNetworks[
                id
            ] =
                trustedNetwork

            statistics.incrementTrustedNetworks()

            ConnectionPolicyOperationResultWithTrustedNetwork.success(
                message =
                    "Trusted network added successfully.",
                trustedNetwork =
                    trustedNetwork
            )
        }

    /**
     * Removes a trusted network.
     */
    suspend fun removeTrustedNetwork(
        networkId:
            String
    ): ConnectionPolicyOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val removed =
                trustedNetworks.remove(
                    networkId
                )

            if (
                removed == null
            ) {

                return@withContext
                    ConnectionPolicyOperationResult.failure(
                        "Trusted network was not found."
                    )
            }

            ConnectionPolicyOperationResult.success(
                "Trusted network removed."
            )
        }

    /**
     * Returns all trusted networks.
     */
    fun getTrustedNetworks():
            List<TrustedNetwork> {

        return trustedNetworks.values
            .sortedBy {
                it.name
            }
    }

    /**
     * Determines whether a connection belongs to a trusted network.
     *
     * Matching is based on:
     *
     * - transport
     * - network identifier
     * - connection metadata
     */
    fun isTrustedConnection(
        connection:
            NetworkConnection
    ): Boolean {

        return trustedNetworks.values.any { network ->

            if (
                !network.enabled
            ) {

                false

            } else if (
                network.transport !=
                NetworkTransportType.UNKNOWN &&
                network.transport !=
                connection.transport
            ) {

                false

            } else {

                network.identifier
                    .equals(
                        connection.host,
                        ignoreCase = true
                    ) ||
                        network.identifier
                            .equals(
                                connection.remoteIp,
                                ignoreCase = true
                            )
            }
        }
    }

    /**
     * Creates a policy group.
     */
    suspend fun createGroup(
        request:
            CreateConnectionPolicyGroupRequest
    ): ConnectionPolicyOperationResultWithGroup =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                request.name.isBlank()
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithGroup.failure(
                        "Policy group name cannot be blank."
                    )
            }

            if (
                groups.size >=
                MAX_GROUPS
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithGroup.failure(
                        "Maximum policy group count reached."
                    )
            }

            val groupId =
                request.id
                    ?.takeIf {
                        it.isNotBlank()
                    }
                    ?: generateGroupId()

            if (
                groups.containsKey(
                    groupId
                )
            ) {

                return@withContext
                    ConnectionPolicyOperationResultWithGroup.failure(
                        "Policy group already exists."
                    )
            }

            val group =
                ConnectionPolicyGroup(
                    id =
                        groupId,

                    name =
                        request.name.trim(),

                    description =
                        request.description
                            .trim(),

                    enabled =
                        request.enabled,

                    policyIds =
                        request.policyIds
                            .distinct()
                            .filter {
                                policies.containsKey(it)
                            },

                    createdAt =
                        System.currentTimeMillis(),

                    updatedAt =
                        System.currentTimeMillis()
                )

            groups[
                groupId
            ] =
                group

            ConnectionPolicyOperationResultWithGroup.success(
                message =
                    "Connection policy group created.",
                group =
                    group
            )
        }

    /**
     * Adds a policy to a group.
     */
    suspend fun addPolicyToGroup(
        groupId:
            String,
        policyId:
            String
    ): ConnectionPolicyOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                !policies.containsKey(
                    policyId
                )
            ) {

                return@withContext
                    ConnectionPolicyOperationResult.failure(
                        "Connection policy was not found."
                    )
            }

            val group =
                groups[
                    groupId
                ]
                    ?: return@withContext
                        ConnectionPolicyOperationResult.failure(
                            "Policy group was not found."
                        )

            groups[
                groupId
            ] =
                group.copy(
                    policyIds =
                        (
                            group.policyIds +
                                    policyId
                            ).distinct(),

                    updatedAt =
                        System.currentTimeMillis()
                )

            ConnectionPolicyOperationResult.success(
                "Policy added to group."
            )
        }

    /**
     * Removes a policy from a group.
     */
    suspend fun removePolicyFromGroup(
        groupId:
            String,
        policyId:
            String
    ): ConnectionPolicyOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val group =
                groups[
                    groupId
                ]
                    ?: return@withContext
                        ConnectionPolicyOperationResult.failure(
                            "Policy group was not found."
                        )

            groups[
                groupId
            ] =
                group.copy(
                    policyIds =
                        group.policyIds
                            .filterNot {
                                it == policyId
                            },

                    updatedAt =
                        System.currentTimeMillis()
                )

            ConnectionPolicyOperationResult.success(
                "Policy removed from group."
            )
        }

    /**
     * Returns all policy groups.
     */
    fun getAllGroups():
            List<ConnectionPolicyGroup> {

        return groups.values
            .sortedBy {
                it.name
            }
    }

    /**
     * Deletes a policy group.
     */
    suspend fun deleteGroup(
        groupId:
            String
    ): ConnectionPolicyOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                groups.remove(
                    groupId
                ) == null
            ) {

                return@withContext
                    ConnectionPolicyOperationResult.failure(
                        "Policy group was not found."
                    )
            }

            ConnectionPolicyOperationResult.success(
                "Policy group deleted."
            )
        }

    /**
     * Searches policies.
     */
    fun searchPolicies(
        query:
            String
    ): List<ConnectionPolicy> {

        if (
            query.isBlank()
        ) {

            return getAllPolicies()
        }

        val normalized =
            query
                .trim()
                .lowercase()

        return getAllPolicies()
            .filter { policy ->

                policy.name
                    .lowercase()
                    .contains(
                        normalized
                    ) ||

                        policy.description
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        policy.id
                            .lowercase()
                            .contains(
                                normalized
                            )
            }
    }

    /**
     * Validates a policy.
     */
    fun validatePolicy(
        policy:
            ConnectionPolicy
    ): ConnectionPolicyValidationResult {

        if (
            policy.id.isBlank()
        ) {

            return ConnectionPolicyValidationResult.invalid(
                "Policy ID cannot be blank."
            )
        }

        if (
            policy.name.isBlank()
        ) {

            return ConnectionPolicyValidationResult.invalid(
                "Policy name cannot be blank."
            )
        }

        if (
            policy.priority <
            configuration.minimumPriority ||
            policy.priority >
            configuration.maximumPriority
        ) {

            return ConnectionPolicyValidationResult.invalid(
                "Policy priority is outside the supported range."
            )
        }

        if (
            policy.trustedNetworkOnly &&
            trustedNetworks.isEmpty()
        ) {

            return ConnectionPolicyValidationResult.invalid(
                "Trusted-network-only policy requires at least one trusted network."
            )
        }

        return ConnectionPolicyValidationResult.valid()
    }

    /**
     * Validates creation request.
     */
    private fun validatePolicyRequest(
        request:
            CreateConnectionPolicyRequest
    ): ConnectionPolicyValidationResult {

        if (
            request.name.isBlank()
        ) {

            return ConnectionPolicyValidationResult.invalid(
                "Policy name cannot be blank."
            )
        }

        if (
            request.priority <
            configuration.minimumPriority ||
            request.priority >
            configuration.maximumPriority
        ) {

            return ConnectionPolicyValidationResult.invalid(
                "Policy priority is outside the supported range."
            )
        }

        return ConnectionPolicyValidationResult.valid()
    }

    /**
     * Builds human-readable policy match explanation.
     */
    private fun buildMatchReason(
        connection:
            NetworkConnection,
        policy:
            ConnectionPolicy
    ): String {

        return buildString {

            append(
                "Matched connection policy "
            )

            append(
                "'${policy.name}'"
            )

            append(
                " [${policy.id}]"
            )

            append(
                ". priority="
            )

            append(
                policy.priority
            )

            append(
                ", action="
            )

            append(
                policy.action.name
            )

            append(
                ", host="
            )

            append(
                connection.host
            )

            if (
                connection.packageName != null
            ) {

                append(
                    ", package="
                )

                append(
                    connection.packageName
                )
            }
        }
    }

    /**
     * Normalizes package names.
     */
    private fun normalizePackages(
        packages:
            Collection<String>
    ): Set<String> {

        return packages
            .map {
                it.trim()
                    .lowercase()
            }
            .filter {
                it.isNotBlank()
            }
            .toSet()
    }

    /**
     * Wildcard matching.
     */
    private fun matchesWildcard(
        value:
            String,
        pattern:
            String
    ): Boolean {

        val normalizedValue =
            value.trim().lowercase()

        val normalizedPattern =
            pattern.trim().lowercase()

        if (
            normalizedPattern == "*"
        ) {

            return true
        }

        if (
            !normalizedPattern.contains("*")
        ) {

            return normalizedValue ==
                    normalizedPattern
        }

        val regex =
            normalizedPattern
                .split("*")
                .joinToString(
                    separator = ".*"
                ) {
                    Regex.escape(it)
                }
                .toRegex()

        return regex.matches(
            normalizedValue
        )
    }

    /**
     * Loads built-in policies.
     */
    private fun loadBuiltInPolicies() {

        val now =
            System.currentTimeMillis()

        policies.putIfAbsent(
            "SYSTEM_DEFAULT",
            ConnectionPolicy(
                id =
                    "SYSTEM_DEFAULT",

                name =
                    "SentriX Default Policy",

                description =
                    "Default fallback connection policy.",

                type =
                    ConnectionPolicyType.DEFAULT,

                action =
                    configuration.defaultUnknownNetworkAction,

                priority =
                    0,

                enabled =
                    true,

                source =
                    ConnectionPolicySource.SYSTEM,

                createdAt =
                    now,

                updatedAt =
                    now
            )
        )

        policies.putIfAbsent(
            "SYSTEM_BLOCK_HIGH_RISK",
            ConnectionPolicy(
                id =
                    "SYSTEM_BLOCK_HIGH_RISK",

                name =
                    "Block High Risk Connections",

                description =
                    "Blocks connections classified as critical threats.",

                type =
                    ConnectionPolicyType.THREAT_BASED,

                action =
                    FirewallDecision.BLOCK,

                priority =
                    900_000,

                enabled =
                    true,

                minimumThreatLevel =
                    NetworkThreatLevel.HIGH,

                source =
                    ConnectionPolicySource.SYSTEM,

                createdAt =
                    now,

                updatedAt =
                    now
            )
        )
    }

    /**
     * Generates policy ID.
     */
    private fun generatePolicyId():
            String {

        return "POLICY_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(18)
                    .uppercase()
    }

    /**
     * Generates group ID.
     */
    private fun generateGroupId():
            String {

        return "POLICY_GROUP_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(14)
                    .uppercase()
    }

    /**
     * Generates trusted network ID.
     */
    private fun generateTrustedNetworkId():
            String {

        return "TRUSTED_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(14)
                    .uppercase()
    }

    /**
     * Ensures initialization.
     */
    private fun ensureInitialized() {

        check(initialized) {
            "ConnectionPolicyManager has not been initialized."
        }
    }

    /**
     * Coroutine cancellation support.
     */
    private suspend fun checkCancellation() {

        if (
            !kotlinx.coroutines
                .currentCoroutineContext()
                .isActive
        ) {

            throw CancellationException(
                "Connection policy operation was cancelled."
            )
        }
    }

    /**
     * Releases resources.
     */
    fun close() {

        policies.clear()
        groups.clear()
        trustedNetworks.clear()

        initialized =
            false

        Log.i(
            TAG,
            "ConnectionPolicyManager closed."
        )
    }
}

/**
 * High-level connection policy.
 */
data class ConnectionPolicy(

    val id:
        String,

    val name:
        String,

    val description:
        String = "",

    val type:
        ConnectionPolicyType,

    val action:
        FirewallDecision,

    val priority:
        Int = 100,

    val enabled:
        Boolean = true,

    /**
     * Empty means all applications.
     */
    val packageNames:
        Set<String> = emptySet(),

    /**
     * Empty means all network transports.
     */
    val networkTypes:
        Set<NetworkTransportType> = emptySet(),

    /**
     * Empty means all protocols.
     */
    val protocols:
        Set<FirewallProtocol> = emptySet(),

    /**
     * Minimum threat severity required for this policy.
     */
    val minimumThreatLevel:
        NetworkThreatLevel =
        NetworkThreatLevel.UNKNOWN,

    /**
     * Whether connection must belong to a trusted network.
     */
    val trustedNetworkOnly:
        Boolean = false,

    /**
     * Optional time restriction.
     */
    val timeWindow:
        ConnectionPolicyTimeWindow? = null,

    /**
     * Firewall rules associated with this policy.
     */
    val ruleIds:
        List<String> = emptyList(),

    /**
     * Optional policy group.
     */
    val groupId:
        String? = null,

    /**
     * Origin of policy.
     */
    val source:
        ConnectionPolicySource =
        ConnectionPolicySource.USER,

    val createdAt:
        Long =
        System.currentTimeMillis(),

    val updatedAt:
        Long =
        System.currentTimeMillis()
)

/**
 * Policy categories.
 */
enum class ConnectionPolicyType {

    DEFAULT,

    APPLICATION,

    NETWORK,

    PROTOCOL,

    THREAT_BASED,

    TIME_BASED,

    TRUSTED_NETWORK,

    COMBINED,

    CUSTOM
}

/**
 * Policy origin.
 */
enum class ConnectionPolicySource {

    SYSTEM,

    USER,

    ENTERPRISE,

    THREAT_INTELLIGENCE,

    IMPORTED
}

/**
 * Optional time window.
 *
 * Uses minutes from midnight.
 */
data class ConnectionPolicyTimeWindow(

    val startMinute:
        Int,

    val endMinute:
        Int,

    val daysOfWeek:
        Set<Int> =
        setOf(
            1,
            2,
            3,
            4,
            5,
            6,
            7
        )
) {

    init {

        require(
            startMinute in 0..1439
        ) {
            "Start minute must be between 0 and 1439."
        }

        require(
            endMinute in 0..1439
        ) {
            "End minute must be between 0 and 1439."
        }

        require(
            daysOfWeek.all {
                it in 1..7
            }
        ) {
            "Days of week must be between 1 and 7."
        }
    }

    /**
     * Determines whether this time window is currently active.
     */
    fun isActive(
        timestamp:
            Long =
            System.currentTimeMillis()
    ): Boolean {

        val calendar =
            java.util.Calendar
                .getInstance()
                .apply {
                    timeInMillis =
                        timestamp
                }

        val day =
            calendar.get(
                java.util.Calendar.DAY_OF_WEEK
            )

        val normalizedDay =
            when (
                day
            ) {

                java.util.Calendar.SUNDAY ->
                    7

                else ->
                    day - 1
            }

        if (
            normalizedDay !in
            daysOfWeek
        ) {

            return false
        }

        val minute =
            calendar.get(
                java.util.Calendar.HOUR_OF_DAY
            ) * 60 +
                    calendar.get(
                        java.util.Calendar.MINUTE
                    )

        /*
         * Normal window:
         *
         * 09:00 -> 17:00
         */
        if (
            startMinute <=
            endMinute
        ) {

            return minute >=
                    startMinute &&
                    minute <=
                    endMinute
        }

        /*
         * Overnight window:
         *
         * 22:00 -> 06:00
         */
        return minute >=
                startMinute ||
                minute <=
                endMinute
    }
}

/**
 * Trusted network definition.
 */
data class TrustedNetwork(

    val id:
        String,

    val name:
        String,

    val identifier:
        String,

    val transport:
        NetworkTransportType =
        NetworkTransportType.UNKNOWN,

    val enabled:
        Boolean = true,

    val createdAt:
        Long =
        System.currentTimeMillis()
)

/**
 * Policy group.
 */
data class ConnectionPolicyGroup(

    val id:
        String,

    val name:
        String,

    val description:
        String = "",

    val enabled:
        Boolean = true,

    val policyIds:
        List<String> = emptyList(),

    val createdAt:
        Long =
        System.currentTimeMillis(),

    val updatedAt:
        Long =
        System.currentTimeMillis()
)

/**
 * Policy creation request.
 */
data class CreateConnectionPolicyRequest(

    val id:
        String? = null,

    val name:
        String,

    val description:
        String = "",

    val type:
        ConnectionPolicyType,

    val action:
        FirewallDecision,

    val priority:
        Int = 100,

    val enabled:
        Boolean = true,

    val packageNames:
        Set<String> = emptySet(),

    val networkTypes:
        Set<NetworkTransportType> = emptySet(),

    val protocols:
        Set<FirewallProtocol> = emptySet(),

    val minimumThreatLevel:
        NetworkThreatLevel =
        NetworkThreatLevel.UNKNOWN,

    val trustedNetworkOnly:
        Boolean = false,

    val timeWindow:
        ConnectionPolicyTimeWindow? = null,

    val ruleIds:
        List<String> = emptyList(),

    val groupId:
        String? = null,

    val source:
        ConnectionPolicySource =
        ConnectionPolicySource.USER
)

/**
 * Partial policy update request.
 */
data class UpdateConnectionPolicyRequest(

    val name:
        String? = null,

    val description:
        String? = null,

    val type:
        ConnectionPolicyType? = null,

    val action:
        FirewallDecision? = null,

    val priority:
        Int? = null,

    val enabled:
        Boolean? = null,

    val packageNames:
        Set<String>? = null,

    val networkTypes:
        Set<NetworkTransportType>? = null,

    val protocols:
        Set<FirewallProtocol>? = null,

    val minimumThreatLevel:
        NetworkThreatLevel? = null,

    val trustedNetworkOnly:
        Boolean? = null,

    val timeWindow:
        ConnectionPolicyTimeWindow? = null,

    val clearTimeWindow:
        Boolean = false,

    val ruleIds:
        List<String>? = null,

    val groupId:
        String? = null,

    val clearGroup:
        Boolean = false
)

/**
 * Trusted-network creation request.
 */
data class AddTrustedNetworkRequest(

    val id:
        String? = null,

    val name:
        String,

    val identifier:
        String,

    val transport:
        NetworkTransportType =
        NetworkTransportType.UNKNOWN,

    val enabled:
        Boolean = true
)

/**
 * Policy group creation request.
 */
data class CreateConnectionPolicyGroupRequest(

    val id:
        String? = null,

    val name:
        String,

    val description:
        String = "",

    val enabled:
        Boolean = true,

    val policyIds:
        List<String> = emptyList()
)

/**
 * Policy evaluation result.
 */
data class ConnectionPolicyEvaluationResult(

    /**
     * True when an explicit policy matched.
     */
    val matched:
        Boolean,

    /**
     * Matching policy.
     */
    val policy:
        ConnectionPolicy?,

    /**
     * Resulting firewall action.
     */
    val action:
        FirewallDecision,

    /**
     * Human-readable explanation.
     */
    val reason:
        String,

    /**
     * Number of policies examined.
     */
    val evaluatedPolicies:
        Int
)

/**
 * Policy validation result.
 */
data class ConnectionPolicyValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                ConnectionPolicyValidationResult {

            return ConnectionPolicyValidationResult(
                valid =
                    true,
                message =
                    "Connection policy is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                ConnectionPolicyValidationResult {

            return ConnectionPolicyValidationResult(
                valid =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Generic policy operation result.
 */
data class ConnectionPolicyOperationResult(

    val success:
        Boolean,

    val message:
        String,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String
        ):
                ConnectionPolicyOperationResult {

            return ConnectionPolicyOperationResult(
                success =
                    true,
                message =
                    message
            )
        }

        fun failure(
            message:
                String,
            error:
                String? = null
        ):
                ConnectionPolicyOperationResult {

            return ConnectionPolicyOperationResult(
                success =
                    false,
                message =
                    message,
                error =
                    error
            )
        }
    }
}

/**
 * Policy operation result containing a policy.
 */
data class ConnectionPolicyOperationResultWithPolicy(

    val success:
        Boolean,

    val message:
        String,

    val policy:
        ConnectionPolicy? = null,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String,
            policy:
                ConnectionPolicy
        ):
                ConnectionPolicyOperationResultWithPolicy {

            return ConnectionPolicyOperationResultWithPolicy(
                success =
                    true,
                message =
                    message,
                policy =
                    policy
            )
        }

        fun failure(
            message:
                String
        ):
                ConnectionPolicyOperationResultWithPolicy {

            return ConnectionPolicyOperationResultWithPolicy(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Policy operation result containing a trusted network.
 */
data class ConnectionPolicyOperationResultWithTrustedNetwork(

    val success:
        Boolean,

    val message:
        String,

    val trustedNetwork:
        TrustedNetwork? = null,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String,
            trustedNetwork:
                TrustedNetwork
        ):
                ConnectionPolicyOperationResultWithTrustedNetwork {

            return ConnectionPolicyOperationResultWithTrustedNetwork(
                success =
                    true,
                message =
                    message,
                trustedNetwork =
                    trustedNetwork
            )
        }

        fun failure(
            message:
                String
        ):
                ConnectionPolicyOperationResultWithTrustedNetwork {

            return ConnectionPolicyOperationResultWithTrustedNetwork(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Policy operation result containing a group.
 */
data class ConnectionPolicyOperationResultWithGroup(

    val success:
        Boolean,

    val message:
        String,

    val group:
        ConnectionPolicyGroup? = null,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String,
            group:
                ConnectionPolicyGroup
        ):
                ConnectionPolicyOperationResultWithGroup {

            return ConnectionPolicyOperationResultWithGroup(
                success =
                    true,
                message =
                    message,
                group =
                    group
            )
        }

        fun failure(
            message:
                String
        ):
                ConnectionPolicyOperationResultWithGroup {

            return ConnectionPolicyOperationResultWithGroup(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Configuration for ConnectionPolicyManager.
 */
data class ConnectionPolicyManagerConfiguration(

    val minimumPriority:
        Int = 0,

    val maximumPriority:
        Int = 1_000_000,

    val defaultWifiAction:
        FirewallDecision =
        FirewallDecision.ALLOW,

    val defaultCellularAction:
        FirewallDecision =
        FirewallDecision.ALLOW,

    val defaultVpnAction:
        FirewallDecision =
        FirewallDecision.ALLOW,

    val defaultEthernetAction:
        FirewallDecision =
        FirewallDecision.ALLOW,

    val defaultBluetoothAction:
        FirewallDecision =
        FirewallDecision.ALLOW,

    val defaultLowpanAction:
        FirewallDecision =
        FirewallDecision.ALLOW,

    val defaultUnknownNetworkAction:
        FirewallDecision =
        FirewallDecision.MONITOR
)

/**
 * Policy statistics.
 */
data class ConnectionPolicyStatistics(

    val totalPolicies:
        Int,

    val enabledPolicies:
        Int,

    val totalGroups:
        Int,

    val totalTrustedNetworks:
        Int,

    val created:
        Long,

    val updated:
        Long,

    val deleted:
        Long,

    val stateChanges:
        Long,

    val evaluations:
        Long,

    val trustedNetworkOperations:
        Long,

    val validationFailures:
        Long
)

/**
 * Thread-safe policy statistics.
 */
private class ConnectionPolicyStatisticsCounter {

    private var created =
        0L

    private var updated =
        0L

    private var deleted =
        0L

    private var stateChanges =
        0L

    private var evaluations =
        0L

    private var trustedNetworkOperations =
        0L

    private var validationFailures =
        0L

    @Synchronized
    fun incrementCreated() {
        created++
    }

    @Synchronized
    fun incrementUpdated() {
        updated++
    }

    @Synchronized
    fun incrementDeleted() {
        deleted++
    }

    @Synchronized
    fun incrementStateChanges() {
        stateChanges++
    }

    @Synchronized
    fun incrementEvaluations() {
        evaluations++
    }

    @Synchronized
    fun incrementTrustedNetworks() {
        trustedNetworkOperations++
    }

    @Synchronized
    fun incrementValidationFailures() {
        validationFailures++
    }

    @Synchronized
    fun snapshot(
        totalPolicies:
            Int,
        enabledPolicies:
            Int,
        totalGroups:
            Int,
        totalTrustedNetworks:
            Int
    ):
            ConnectionPolicyStatistics {

        return ConnectionPolicyStatistics(

            totalPolicies =
                totalPolicies,

            enabledPolicies =
                enabledPolicies,

            totalGroups =
                totalGroups,

            totalTrustedNetworks =
                totalTrustedNetworks,

            created =
                created,

            updated =
                updated,

            deleted =
                deleted,

            stateChanges =
                stateChanges,

            evaluations =
                evaluations,

            trustedNetworkOperations =
                trustedNetworkOperations,

            validationFailures =
                validationFailures
        )
    }
}
