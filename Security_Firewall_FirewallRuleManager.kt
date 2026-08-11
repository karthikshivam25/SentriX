package com.sentrix.security.firewall

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * FirewallRuleManager
 *
 * Dedicated rule-management component for the SentriX firewall.
 *
 * Responsibilities:
 *
 * - Create firewall rules.
 * - Register firewall rules.
 * - Update firewall rules.
 * - Delete firewall rules.
 * - Enable/disable rules.
 * - Validate rules.
 * - Search/filter rules.
 * - Sort rules by priority.
 * - Group rules.
 * - Import/export rule definitions.
 * - Maintain rule metadata.
 * - Maintain rule lifecycle statistics.
 *
 * It does NOT:
 *
 * - Make runtime network decisions.
 * - Intercept packets.
 * - Start Android VpnService.
 * - Start/stop firewall protection.
 *
 * Runtime evaluation belongs to:
 *
 *     FirewallEngine
 *
 * Lifecycle/orchestration belongs to:
 *
 *     FirewallManager
 *
 * Architecture:
 *
 *                 FirewallRuleManager
 *                         |
 *          ┌──────────────┼──────────────┐
 *          ▼              ▼              ▼
 *       Validate        Store         Metadata
 *          │              │              │
 *          └──────────────┼──────────────┘
 *                         ▼
 *                   FirewallEngine
 */
class FirewallRuleManager(
    context: Context,
    private val configuration:
        FirewallRuleManagerConfiguration =
        FirewallRuleManagerConfiguration()
) {

    companion object {

        private const val TAG =
            "FirewallRuleManager"

        private const val MAX_RULES =
            10_000

        private const val MAX_GROUPS =
            1_000
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * In-memory rule store.
     *
     * A repository/database can replace this later without changing
     * the public manager API.
     */
    private val rules =
        ConcurrentHashMap<
            String,
            FirewallRule
        >()

    /**
     * Rule groups.
     */
    private val groups =
        ConcurrentHashMap<
            String,
            FirewallRuleGroup
        >()

    /**
     * Rule metadata.
     */
    private val metadata =
        ConcurrentHashMap<
            String,
            FirewallRuleMetadata
        >()

    /**
     * Runtime statistics.
     */
    private val statistics =
        FirewallRuleStatistics()

    /**
     * Indicates whether this manager has been initialized.
     */
    @Volatile
    private var initialized =
        false

    /**
     * Initializes the rule manager.
     */
    suspend fun initialize():
            FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized
            ) {

                return@withContext
                    FirewallRuleOperationResult.success(
                        "Firewall rule manager is already initialized."
                    )
            }

            loadBuiltInGroups()

            initialized = true

            Log.i(
                TAG,
                "FirewallRuleManager initialized."
            )

            FirewallRuleOperationResult.success(
                "Firewall rule manager initialized successfully."
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
     * Creates a new firewall rule.
     */
    suspend fun createRule(
        request:
            CreateFirewallRuleRequest
    ): FirewallRuleOperationResultWithRule =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val validation =
                validateCreateRequest(
                    request
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    FirewallRuleOperationResultWithRule.failure(
                        validation.message
                    )
            }

            if (
                rules.size >= MAX_RULES
            ) {

                return@withContext
                    FirewallRuleOperationResultWithRule.failure(
                        "Maximum firewall rule count reached."
                    )
            }

            val ruleId =
                request.id
                    ?.takeIf {
                        it.isNotBlank()
                    }
                    ?: generateRuleId()

            if (
                rules.containsKey(
                    ruleId
                )
            ) {

                return@withContext
                    FirewallRuleOperationResultWithRule.failure(
                        "A firewall rule with this ID already exists."
                    )
            }

            val now =
                System.currentTimeMillis()

            val rule =
                FirewallRule(
                    id =
                        ruleId,

                    name =
                        request.name.trim(),

                    description =
                        request.description
                            .trim(),

                    type =
                        request.type,

                    target =
                        normalizeTarget(
                            request.target
                        ),

                    action =
                        request.action,

                    priority =
                        request.priority
                            .coerceIn(
                                configuration
                                    .minimumPriority,

                                configuration
                                    .maximumPriority
                            ),

                    enabled =
                        request.enabled,

                    source =
                        request.source,

                    packageName =
                        request.packageName
                            ?.trim()
                            ?.takeIf {
                                it.isNotBlank()
                            },

                    port =
                        request.port,

                    protocol =
                        request.protocol,

                    createdAt =
                        now,

                    updatedAt =
                        now
                )

            rules[
                rule.id
            ] =
                rule

            metadata[
                rule.id
            ] =
                FirewallRuleMetadata(
                    ruleId =
                        rule.id,

                    createdBy =
                        request.createdBy,

                    updatedBy =
                        request.createdBy,

                    tags =
                        request.tags,

                    groupId =
                        request.groupId,

                    notes =
                        request.notes,

                    createdAt =
                        now,

                    updatedAt =
                        now
                )

            statistics.incrementCreated()

            Log.d(
                TAG,
                "Firewall rule created: ${rule.id}"
            )

            FirewallRuleOperationResultWithRule.success(
                message =
                    "Firewall rule created successfully.",
                rule =
                    rule
            )
        }

    /**
     * Registers an already-created rule.
     *
     * Useful when restoring rules from persistence.
     */
    suspend fun registerRule(
        rule:
            FirewallRule,
        metadata:
            FirewallRuleMetadata? = null
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val validation =
                validateRule(
                    rule
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    FirewallRuleOperationResult.failure(
                        validation.message
                    )
            }

            if (
                rules.size >= MAX_RULES &&
                !rules.containsKey(rule.id)
            ) {

                return@withContext
                    FirewallRuleOperationResult.failure(
                        "Maximum firewall rule count reached."
                    )
            }

            if (
                rules.containsKey(
                    rule.id
                )
            ) {

                return@withContext
                    FirewallRuleOperationResult.failure(
                        "A firewall rule with this ID already exists."
                    )
            }

            rules[
                rule.id
            ] =
                rule

            this@FirewallRuleManager.metadata[
                rule.id
            ] =
                metadata
                    ?: FirewallRuleMetadata(
                        ruleId =
                            rule.id
                    )

            statistics.incrementCreated()

            FirewallRuleOperationResult.success(
                "Firewall rule registered successfully."
            )
        }

    /**
     * Updates an existing rule.
     */
    suspend fun updateRule(
        ruleId:
            String,
        request:
            UpdateFirewallRuleRequest
    ): FirewallRuleOperationResultWithRule =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val existing =
                rules[
                    ruleId
                ]
                    ?: return@withContext
                        FirewallRuleOperationResultWithRule.failure(
                            "Firewall rule was not found."
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

                    target =
                        request.target
                            ?.let {
                                normalizeTarget(it)
                            }
                            ?: existing.target,

                    action =
                        request.action
                            ?: existing.action,

                    priority =
                        request.priority
                            ?.coerceIn(
                                configuration
                                    .minimumPriority,

                                configuration
                                    .maximumPriority
                            )
                            ?: existing.priority,

                    enabled =
                        request.enabled
                            ?: existing.enabled,

                    packageName =
                        if (
                            request.clearPackageName
                        ) {
                            null
                        } else {
                            request.packageName
                                ?.trim()
                                ?.takeIf {
                                    it.isNotBlank()
                                }
                                ?: existing.packageName
                        },

                    port =
                        if (
                            request.clearPort
                        ) {
                            null
                        } else {
                            request.port
                                ?: existing.port
                        },

                    protocol =
                        request.protocol
                            ?: existing.protocol,

                    updatedAt =
                        System.currentTimeMillis()
                )

            val validation =
                validateRule(
                    updated
                )

            if (
                !validation.valid
            ) {

                statistics.incrementValidationFailures()

                return@withContext
                    FirewallRuleOperationResultWithRule.failure(
                        validation.message
                    )
            }

            rules[
                ruleId
            ] =
                updated

            val existingMetadata =
                metadata[
                    ruleId
                ]
                    ?: FirewallRuleMetadata(
                        ruleId =
                            ruleId
                    )

            metadata[
                ruleId
            ] =
                existingMetadata.copy(
                    updatedBy =
                        request.updatedBy,

                    updatedAt =
                        System.currentTimeMillis(),

                    notes =
                        request.notes
                            ?: existingMetadata.notes,

                    tags =
                        request.tags
                            ?: existingMetadata.tags,

                    groupId =
                        if (
                            request.clearGroup
                        ) {
                            null
                        } else {
                            request.groupId
                                ?: existingMetadata.groupId
                        }
                )

            statistics.incrementUpdated()

            Log.d(
                TAG,
                "Firewall rule updated: $ruleId"
            )

            FirewallRuleOperationResultWithRule.success(
                message =
                    "Firewall rule updated successfully.",
                rule =
                    updated
            )
        }

    /**
     * Deletes a rule.
     */
    suspend fun deleteRule(
        ruleId:
            String
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                ruleId.isBlank()
            ) {

                return@withContext
                    FirewallRuleOperationResult.failure(
                        "Rule ID cannot be blank."
                    )
            }

            val removed =
                rules.remove(
                    ruleId
                )

            if (
                removed == null
            ) {

                return@withContext
                    FirewallRuleOperationResult.failure(
                        "Firewall rule was not found."
                    )
            }

            metadata.remove(
                ruleId
            )

            statistics.incrementDeleted()

            Log.d(
                TAG,
                "Firewall rule deleted: $ruleId"
            )

            FirewallRuleOperationResult.success(
                "Firewall rule deleted successfully."
            )
        }

    /**
     * Enables a rule.
     */
    suspend fun enableRule(
        ruleId:
            String
    ): FirewallRuleOperationResult =
        updateRuleState(
            ruleId =
                ruleId,
            enabled =
                true
        )

    /**
     * Disables a rule.
     */
    suspend fun disableRule(
        ruleId:
            String
    ): FirewallRuleOperationResult =
        updateRuleState(
            ruleId =
                ruleId,
            enabled =
                false
        )

    /**
     * Updates only the enabled state.
     */
    private suspend fun updateRuleState(
        ruleId:
            String,
        enabled:
            Boolean
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val existing =
                rules[
                    ruleId
                ]
                    ?: return@withContext
                        FirewallRuleOperationResult.failure(
                            "Firewall rule was not found."
                        )

            rules[
                ruleId
            ] =
                existing.copy(
                    enabled =
                        enabled,

                    updatedAt =
                        System.currentTimeMillis()
                )

            statistics.incrementStateChanges()

            FirewallRuleOperationResult.success(
                if (enabled) {
                    "Firewall rule enabled."
                } else {
                    "Firewall rule disabled."
                }
            )
        }

    /**
     * Gets a rule by ID.
     */
    fun getRule(
        ruleId:
            String
    ): FirewallRule? {

        return rules[
            ruleId
        ]
    }

    /**
     * Gets metadata for a rule.
     */
    fun getRuleMetadata(
        ruleId:
            String
    ): FirewallRuleMetadata? {

        return metadata[
            ruleId
        ]
    }

    /**
     * Returns all rules.
     */
    fun getAllRules():
            List<FirewallRule> {

        return rules.values
            .sortedWith(
                compareByDescending<FirewallRule> {
                    it.priority
                }.thenBy {
                    it.name
                }
            )
    }

    /**
     * Returns enabled rules.
     */
    fun getEnabledRules():
            List<FirewallRule> {

        return getAllRules()
            .filter {
                it.enabled
            }
    }

    /**
     * Returns disabled rules.
     */
    fun getDisabledRules():
            List<FirewallRule> {

        return getAllRules()
            .filter {
                !it.enabled
            }
    }

    /**
     * Returns rules by action.
     */
    fun getRulesByAction(
        action:
            FirewallDecision
    ): List<FirewallRule> {

        return getAllRules()
            .filter {
                it.action == action
            }
    }

    /**
     * Returns rules by type.
     */
    fun getRulesByType(
        type:
            FirewallRuleType
    ): List<FirewallRule> {

        return getAllRules()
            .filter {
                it.type == type
            }
    }

    /**
     * Returns rules by source.
     */
    fun getRulesBySource(
        source:
            FirewallRuleSource
    ): List<FirewallRule> {

        return getAllRules()
            .filter {
                it.source == source
            }
    }

    /**
     * Searches rules.
     */
    fun searchRules(
        query:
            String
    ): List<FirewallRule> {

        if (
            query.isBlank()
        ) {

            return getAllRules()
        }

        val normalized =
            query
                .trim()
                .lowercase()

        return getAllRules()
            .filter { rule ->

                rule.name
                    .lowercase()
                    .contains(normalized) ||

                        rule.description
                            .lowercase()
                            .contains(normalized) ||

                        rule.target
                            .lowercase()
                            .contains(normalized) ||

                        rule.id
                            .lowercase()
                            .contains(normalized)
            }
    }

    /**
     * Creates a firewall rule group.
     */
    suspend fun createGroup(
        request:
            CreateFirewallRuleGroupRequest
    ): FirewallRuleOperationResultWithGroup =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                request.name.isBlank()
            ) {

                return@withContext
                    FirewallRuleOperationResultWithGroup.failure(
                        "Group name cannot be blank."
                    )
            }

            if (
                groups.size >= MAX_GROUPS
            ) {

                return@withContext
                    FirewallRuleOperationResultWithGroup.failure(
                        "Maximum firewall rule group count reached."
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
                    FirewallRuleOperationResultWithGroup.failure(
                        "Firewall rule group already exists."
                    )
            }

            val group =
                FirewallRuleGroup(
                    id =
                        groupId,

                    name =
                        request.name.trim(),

                    description =
                        request.description
                            .trim(),

                    enabled =
                        request.enabled,

                    ruleIds =
                        request.ruleIds
                            .distinct()
                            .filter {
                                rules.containsKey(it)
                            },

                    createdAt =
                        System.currentTimeMillis(),

                    updatedAt =
                        System.currentTimeMillis()
                )

            groups[
                group.id
            ] =
                group

            FirewallRuleOperationResultWithGroup.success(
                message =
                    "Firewall rule group created.",
                group =
                    group
            )
        }

    /**
     * Adds a rule to a group.
     */
    suspend fun addRuleToGroup(
        groupId:
            String,
        ruleId:
            String
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                !rules.containsKey(
                    ruleId
                )
            ) {

                return@withContext
                    FirewallRuleOperationResult.failure(
                        "Firewall rule was not found."
                    )
            }

            val group =
                groups[
                    groupId
                ]
                    ?: return@withContext
                        FirewallRuleOperationResult.failure(
                            "Firewall rule group was not found."
                        )

            groups[
                groupId
            ] =
                group.copy(
                    ruleIds =
                        (
                            group.ruleIds +
                                    ruleId
                            ).distinct(),

                    updatedAt =
                        System.currentTimeMillis()
                )

            FirewallRuleOperationResult.success(
                "Rule added to firewall group."
            )
        }

    /**
     * Removes a rule from a group.
     */
    suspend fun removeRuleFromGroup(
        groupId:
            String,
        ruleId:
            String
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val group =
                groups[
                    groupId
                ]
                    ?: return@withContext
                        FirewallRuleOperationResult.failure(
                            "Firewall rule group was not found."
                        )

            groups[
                groupId
            ] =
                group.copy(
                    ruleIds =
                        group.ruleIds
                            .filterNot {
                                it == ruleId
                            },

                    updatedAt =
                        System.currentTimeMillis()
                )

            FirewallRuleOperationResult.success(
                "Rule removed from firewall group."
            )
        }

    /**
     * Enables a group.
     */
    suspend fun enableGroup(
        groupId:
            String
    ): FirewallRuleOperationResult {

        return updateGroupState(
            groupId =
                groupId,
            enabled =
                true
        )
    }

    /**
     * Disables a group.
     */
    suspend fun disableGroup(
        groupId:
            String
    ): FirewallRuleOperationResult {

        return updateGroupState(
            groupId =
                groupId,
            enabled =
                false
        )
    }

    /**
     * Updates group state.
     */
    private suspend fun updateGroupState(
        groupId:
            String,
        enabled:
            Boolean
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            val group =
                groups[
                    groupId
                ]
                    ?: return@withContext
                        FirewallRuleOperationResult.failure(
                            "Firewall rule group was not found."
                        )

            groups[
                groupId
            ] =
                group.copy(
                    enabled =
                        enabled,

                    updatedAt =
                        System.currentTimeMillis()
                )

            FirewallRuleOperationResult.success(
                if (enabled) {
                    "Firewall rule group enabled."
                } else {
                    "Firewall rule group disabled."
                }
            )
        }

    /**
     * Gets a group.
     */
    fun getGroup(
        groupId:
            String
    ): FirewallRuleGroup? {

        return groups[
            groupId
        ]
    }

    /**
     * Returns all groups.
     */
    fun getAllGroups():
            List<FirewallRuleGroup> {

        return groups.values
            .sortedBy {
                it.name
            }
    }

    /**
     * Returns rules belonging to a group.
     */
    fun getRulesInGroup(
        groupId:
            String
    ): List<FirewallRule> {

        val group =
            groups[
                groupId
            ]
                ?: return emptyList()

        if (
            !group.enabled
        ) {

            return emptyList()
        }

        return group.ruleIds
            .mapNotNull {
                rules[it]
            }
            .sortedByDescending {
                it.priority
            }
    }

    /**
     * Deletes a group.
     */
    suspend fun deleteGroup(
        groupId:
            String
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val removed =
                groups.remove(
                    groupId
                )

            if (
                removed == null
            ) {

                return@withContext
                    FirewallRuleOperationResult.failure(
                        "Firewall rule group was not found."
                    )
            }

            FirewallRuleOperationResult.success(
                "Firewall rule group deleted."
            )
        }

    /**
     * Imports rules.
     *
     * Existing rules with the same ID are rejected rather than
     * silently overwritten.
     */
    suspend fun importRules(
        importedRules:
            Collection<FirewallRule>
    ): FirewallRuleImportResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val added =
                mutableListOf<FirewallRule>()

            val rejected =
                mutableListOf<FirewallRuleImportError>()

            importedRules.forEach { rule ->

                if (
                    rules.containsKey(
                        rule.id
                    )
                ) {

                    rejected.add(
                        FirewallRuleImportError(
                            ruleId =
                                rule.id,
                            reason =
                                "Rule ID already exists."
                        )
                    )

                    return@forEach
                }

                val validation =
                    validateRule(
                        rule
                    )

                if (
                    !validation.valid
                ) {

                    rejected.add(
                        FirewallRuleImportError(
                            ruleId =
                                rule.id,
                            reason =
                                validation.message
                        )
                    )

                    return@forEach
                }

                if (
                    rules.size +
                    added.size >=
                    MAX_RULES
                ) {

                    rejected.add(
                        FirewallRuleImportError(
                            ruleId =
                                rule.id,
                            reason =
                                "Maximum rule count reached."
                        )
                    )

                    return@forEach
                }

                added.add(
                    rule
                )
            }

            added.forEach { rule ->

                rules[
                    rule.id
                ] =
                    rule

                metadata[
                    rule.id
                ] =
                    FirewallRuleMetadata(
                        ruleId =
                            rule.id
                    )
            }

            statistics.incrementImported(
                added.size
            )

            FirewallRuleImportResult(
                importedCount =
                    added.size,

                rejectedCount =
                    rejected.size,

                importedRules =
                    added,

                rejectedRules =
                    rejected
            )
        }

    /**
     * Exports all rules.
     */
    fun exportRules():
            List<FirewallRule> {

        return getAllRules()
    }

    /**
     * Clears all user/automatic rules.
     *
     * System rules can optionally be retained.
     */
    suspend fun clearRules(
        preserveSystemRules:
            Boolean = true
    ): FirewallRuleOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val toRemove =
                rules.values
                    .filter { rule ->

                        !preserveSystemRules ||
                                rule.source !=
                                FirewallRuleSource.SYSTEM
                    }
                    .map {
                        it.id
                    }

            toRemove.forEach { ruleId ->

                rules.remove(
                    ruleId
                )

                metadata.remove(
                    ruleId
                )
            }

            groups.values
                .forEach { group ->

                    groups[
                        group.id
                    ] =
                        group.copy(
                            ruleIds =
                                group.ruleIds
                                    .filter {
                                        rules.containsKey(it)
                                    },

                            updatedAt =
                                System.currentTimeMillis()
                        )
                }

            FirewallRuleOperationResult.success(
                "${toRemove.size} firewall rules cleared."
            )
        }

    /**
     * Returns manager statistics.
     */
    fun getStatistics():
            FirewallRuleManagerStatistics {

        return statistics.snapshot(
            totalRules =
                rules.size,

            enabledRules =
                rules.values.count {
                    it.enabled
                },

            disabledRules =
                rules.values.count {
                    !it.enabled
                },

            totalGroups =
                groups.size
        )
    }

    /**
     * Validates a rule.
     */
    fun validateRule(
        rule:
            FirewallRule
    ): FirewallRuleValidationResult {

        if (
            rule.id.isBlank()
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule ID cannot be blank."
            )
        }

        if (
            rule.name.isBlank()
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule name cannot be blank."
            )
        }

        if (
            rule.target.isBlank() &&
            rule.type !=
            FirewallRuleType.DEFAULT
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule target cannot be blank."
            )
        }

        if (
            rule.priority <
            configuration.minimumPriority ||
            rule.priority >
            configuration.maximumPriority
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule priority is outside the supported range."
            )
        }

        if (
            rule.port != null &&
            rule.port !in 1..65535
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule port must be between 1 and 65535."
            )
        }

        if (
            rule.type ==
            FirewallRuleType.APPLICATION &&
            rule.packageName.isNullOrBlank() &&
            rule.target.isBlank()
        ) {

            return FirewallRuleValidationResult.invalid(
                "Application rules require a package name or target."
            )
        }

        return FirewallRuleValidationResult.valid()
    }

    /**
     * Validates a creation request.
     */
    private fun validateCreateRequest(
        request:
            CreateFirewallRuleRequest
    ): FirewallRuleValidationResult {

        if (
            request.name.isBlank()
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule name cannot be blank."
            )
        }

        if (
            request.target.isBlank() &&
            request.type !=
            FirewallRuleType.DEFAULT
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule target cannot be blank."
            )
        }

        if (
            request.priority <
            configuration.minimumPriority ||
            request.priority >
            configuration.maximumPriority
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule priority is outside the supported range."
            )
        }

        if (
            request.port != null &&
            request.port !in 1..65535
        ) {

            return FirewallRuleValidationResult.invalid(
                "Rule port must be between 1 and 65535."
            )
        }

        return FirewallRuleValidationResult.valid()
    }

    /**
     * Ensures manager is initialized.
     */
    private fun ensureInitialized() {

        check(initialized) {
            "FirewallRuleManager has not been initialized."
        }
    }

    /**
     * Generates a unique rule ID.
     */
    private fun generateRuleId():
            String {

        return "RULE_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(16)
                    .uppercase()
    }

    /**
     * Generates a unique group ID.
     */
    private fun generateGroupId():
            String {

        return "GROUP_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(16)
                    .uppercase()
    }

    /**
     * Normalizes a rule target.
     */
    private fun normalizeTarget(
        target:
            String
    ): String {

        return target
            .trim()
            .lowercase()
            .removePrefix(
                "https://"
            )
            .removePrefix(
                "http://"
            )
            .trimEnd(
                '/'
            )
    }

    /**
     * Loads built-in rule groups.
     */
    private fun loadBuiltInGroups() {

        groups.putIfAbsent(
            "SYSTEM",
            FirewallRuleGroup(
                id =
                    "SYSTEM",
                name =
                    "System Rules",
                description =
                    "SentriX built-in firewall rules.",
                enabled =
                    true
            )
        )

        groups.putIfAbsent(
            "USER",
            FirewallRuleGroup(
                id =
                    "USER",
                name =
                    "User Rules",
                description =
                    "Firewall rules created by the user.",
                enabled =
                    true
            )
        )

        groups.putIfAbsent(
            "THREAT_INTELLIGENCE",
            FirewallRuleGroup(
                id =
                    "THREAT_INTELLIGENCE",
                name =
                    "Threat Intelligence",
                description =
                    "Rules generated from SentriX threat intelligence.",
                enabled =
                    true
            )
        )
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
                "Firewall rule operation was cancelled."
            )
        }
    }
}

/**
 * Request used to create a firewall rule.
 */
data class CreateFirewallRuleRequest(

    val id:
        String? = null,

    val name:
        String,

    val description:
        String = "",

    val type:
        FirewallRuleType,

    val target:
        String,

    val action:
        FirewallDecision,

    val priority:
        Int = 100,

    val enabled:
        Boolean = true,

    val source:
        FirewallRuleSource =
        FirewallRuleSource.USER,

    val packageName:
        String? = null,

    val port:
        Int? = null,

    val protocol:
        FirewallProtocol =
        FirewallProtocol.ANY,

    val createdBy:
        String? = null,

    val tags:
        Set<String> = emptySet(),

    val groupId:
        String? = null,

    val notes:
        String? = null
)

/**
 * Partial update request.
 */
data class UpdateFirewallRuleRequest(

    val name:
        String? = null,

    val description:
        String? = null,

    val type:
        FirewallRuleType? = null,

    val target:
        String? = null,

    val action:
        FirewallDecision? = null,

    val priority:
        Int? = null,

    val enabled:
        Boolean? = null,

    val packageName:
        String? = null,

    val clearPackageName:
        Boolean = false,

    val port:
        Int? = null,

    val clearPort:
        Boolean = false,

    val protocol:
        FirewallProtocol? = null,

    val updatedBy:
        String? = null,

    val tags:
        Set<String>? = null,

    val groupId:
        String? = null,

    val clearGroup:
        Boolean = false,

    val notes:
        String? = null
)

/**
 * Firewall rule group.
 */
data class FirewallRuleGroup(

    val id:
        String,

    val name:
        String,

    val description:
        String = "",

    val enabled:
        Boolean = true,

    val ruleIds:
        List<String> = emptyList(),

    val createdAt:
        Long =
        System.currentTimeMillis(),

    val updatedAt:
        Long =
        System.currentTimeMillis()
)

/**
 * Rule metadata.
 *
 * Kept separate from FirewallRule so the core rule model remains
 * focused on runtime firewall semantics.
 */
data class FirewallRuleMetadata(

    val ruleId:
        String,

    val createdBy:
        String? = null,

    val updatedBy:
        String? = null,

    val tags:
        Set<String> = emptySet(),

    val groupId:
        String? = null,

    val notes:
        String? = null,

    val createdAt:
        Long =
        System.currentTimeMillis(),

    val updatedAt:
        Long =
        System.currentTimeMillis()
)

/**
 * Request used to create a rule group.
 */
data class CreateFirewallRuleGroupRequest(

    val id:
        String? = null,

    val name:
        String,

    val description:
        String = "",

    val enabled:
        Boolean = true,

    val ruleIds:
        List<String> = emptyList()
)

/**
 * Rule validation result.
 */
data class FirewallRuleValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                FirewallRuleValidationResult {

            return FirewallRuleValidationResult(
                valid =
                    true,
                message =
                    "Rule is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                FirewallRuleValidationResult {

            return FirewallRuleValidationResult(
                valid =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Generic rule operation result.
 */
data class FirewallRuleOperationResult(

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
                FirewallRuleOperationResult {

            return FirewallRuleOperationResult(
                success =
                    true,
                message =
                    message
            )
        }

        fun failure(
            message:
                String
        ):
                FirewallRuleOperationResult {

            return FirewallRuleOperationResult(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Operation result containing a rule.
 */
data class FirewallRuleOperationResultWithRule(

    val success:
        Boolean,

    val message:
        String,

    val rule:
        FirewallRule? = null,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String,
            rule:
                FirewallRule
        ):
                FirewallRuleOperationResultWithRule {

            return FirewallRuleOperationResultWithRule(
                success =
                    true,
                message =
                    message,
                rule =
                    rule
            )
        }

        fun failure(
            message:
                String
        ):
                FirewallRuleOperationResultWithRule {

            return FirewallRuleOperationResultWithRule(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Operation result containing a rule group.
 */
data class FirewallRuleOperationResultWithGroup(

    val success:
        Boolean,

    val message:
        String,

    val group:
        FirewallRuleGroup? = null,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String,
            group:
                FirewallRuleGroup
        ):
                FirewallRuleOperationResultWithGroup {

            return FirewallRuleOperationResultWithGroup(
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
                FirewallRuleOperationResultWithGroup {

            return FirewallRuleOperationResultWithGroup(
                success =
                    false,
                message =
                    message
            )
        }
    }
}

/**
 * Result of importing firewall rules.
 */
data class FirewallRuleImportResult(

    val importedCount:
        Int,

    val rejectedCount:
        Int,

    val importedRules:
        List<FirewallRule>,

    val rejectedRules:
        List<FirewallRuleImportError>
)

/**
 * Describes an imported rule that was rejected.
 */
data class FirewallRuleImportError(

    val ruleId:
        String,

    val reason:
        String
)

/**
 * Rule-manager configuration.
 */
data class FirewallRuleManagerConfiguration(

    val minimumPriority:
        Int = 0,

    val maximumPriority:
        Int = 1_000_000
)

/**
 * Rule manager statistics.
 */
data class FirewallRuleManagerStatistics(

    val totalRules:
        Int,

    val enabledRules:
        Int,

    val disabledRules:
        Int,

    val totalGroups:
        Int,

    val created:
        Long,

    val updated:
        Long,

    val deleted:
        Long,

    val imported:
        Long,

    val stateChanges:
        Long,

    val validationFailures:
        Long
)

/**
 * Thread-safe rule-management statistics.
 */
private class FirewallRuleStatistics {

    private var created =
        0L

    private var updated =
        0L

    private var deleted =
        0L

    private var imported =
        0L

    private var stateChanges =
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
    fun incrementImported(
        count:
            Int
    ) {

        imported += count
    }

    @Synchronized
    fun incrementStateChanges() {
        stateChanges++
    }

    @Synchronized
    fun incrementValidationFailures() {
        validationFailures++
    }

    @Synchronized
    fun snapshot(
        totalRules:
            Int,
        enabledRules:
            Int,
        disabledRules:
            Int,
        totalGroups:
            Int
    ):
            FirewallRuleManagerStatistics {

        return FirewallRuleManagerStatistics(
            totalRules =
                totalRules,

            enabledRules =
                enabledRules,

            disabledRules =
                disabledRules,

            totalGroups =
                totalGroups,

            created =
                created,

            updated =
                updated,

            deleted =
                deleted,

            imported =
                imported,

            stateChanges =
                stateChanges,

            validationFailures =
                validationFailures
        )
    }
}
