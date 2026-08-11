package com.sentrix.security.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNConfigurationManager
 *
 * Central configuration manager for the SentriX VPN subsystem.
 *
 * Responsibilities:
 *
 * - Maintain the active VPN configuration.
 * - Create and manage named VPN profiles.
 * - Validate VPN configuration.
 * - Update individual configuration properties.
 * - Enable/disable security capabilities.
 * - Manage DNS configuration.
 * - Manage routing configuration.
 * - Manage MTU configuration.
 * - Manage VPN security mode.
 * - Track configuration versions.
 * - Maintain configuration-change history.
 * - Expose reactive configuration state.
 *
 * This class does NOT:
 *
 * - Establish the VPN tunnel.
 * - Create the Android VpnService.
 * - Read/write packets.
 * - Perform threat analysis.
 * - Make firewall decisions.
 *
 * Those responsibilities belong to:
 *
 * VPNService
 * VPNEngine
 * VPNManager
 * FirewallEngine
 * VPNTrafficAnalyzer
 *
 * Architecture:
 *
 *                 VPNConfigurationManager
 *                          |
 *              ┌───────────┼────────────┐
 *              ▼           ▼            ▼
 *          Active       Profiles     History
 *          Config
 *              |
 *              ▼
 *        Configuration
 *         Validation
 *
 * Example flow:
 *
 * UI / UseCase
 *      |
 *      v
 * VPNConfigurationManager
 *      |
 *      ├── validate
 *      ├── update
 *      └── publish
 *             |
 *             v
 *         VPNManager
 *             |
 *             v
 *         VPNService
 */
class VPNConfigurationManager(
    context: Context,
    private val managerConfiguration:
        VPNConfigurationManagerSettings =
        VPNConfigurationManagerSettings()
) {

    companion object {

        private const val TAG =
            "VPNConfigurationManager"

        private const val MAX_PROFILES =
            100

        private const val MAX_HISTORY =
            10_000

        private const val MIN_MTU =
            576

        private const val MAX_MTU =
            65_535

        private const val DEFAULT_MTU =
            1500

        private const val MIN_PACKET_SIZE =
            512

        private const val MAX_PACKET_SIZE =
            65_535
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Active configuration.
     */
    private val _activeConfiguration =
        MutableStateFlow(
            managerConfiguration
                .defaultConfiguration
        )

    /**
     * Public active configuration.
     */
    val activeConfiguration:
        StateFlow<VPNConfiguration> =
        _activeConfiguration.asStateFlow()

    /**
     * Named configuration profiles.
     */
    private val profiles =
        ConcurrentHashMap<
            String,
            VPNConfigurationProfile
        >()

    /**
     * Configuration history.
     */
    private val configurationHistory =
        ConcurrentLinkedDeque<
            VPNConfigurationChange
        >()

    /**
     * Configuration statistics.
     */
    private val statistics =
        VPNConfigurationStatisticsCounter()

    /**
     * Current configuration version.
     */
    private val versionCounter =
        AtomicLong(1)

    /**
     * Initializes the configuration manager.
     */
    suspend fun initialize():
            VPNConfigurationOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val default =
                managerConfiguration
                    .defaultConfiguration

            val validation =
                validateConfiguration(
                    default
                )

            if (
                !validation.valid
            ) {

                statistics
                    .incrementValidationFailures()

                return@withContext
                    VPNConfigurationOperationResult.failure(
                        validation.message
                    )
            }

            _activeConfiguration.value =
                default

            statistics
                .incrementInitializations()

            Log.i(
                TAG,
                "VPNConfigurationManager initialized."
            )

            VPNConfigurationOperationResult.success(
                "VPN configuration manager initialized successfully."
            )
        }

    /**
     * Returns the current configuration.
     */
    fun getConfiguration():
            VPNConfiguration {

        return _activeConfiguration.value
    }

    /**
     * Returns the current configuration version.
     */
    fun getConfigurationVersion():
            Long {

        return versionCounter.get()
    }

    /**
     * Replaces the complete active configuration.
     */
    suspend fun updateConfiguration(
        newConfiguration:
            VPNConfiguration,
        reason:
            String =
            "Configuration updated"
    ):
            VPNConfigurationOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val validation =
                validateConfiguration(
                    newConfiguration
                )

            if (
                !validation.valid
            ) {

                statistics
                    .incrementValidationFailures()

                return@withContext
                    VPNConfigurationOperationResult.failure(
                        validation.message
                    )
            }

            val previous =
                _activeConfiguration.value

            if (
                previous == newConfiguration
            ) {

                return@withContext
                    VPNConfigurationOperationResult.success(
                        "VPN configuration is already up to date."
                    )
            }

            _activeConfiguration.value =
                newConfiguration

            val version =
                versionCounter
                    .incrementAndGet()

            recordConfigurationChange(
                previous =
                    previous,

                current =
                    newConfiguration,

                reason =
                    reason,

                version =
                    version
            )

            statistics
                .incrementUpdates()

            Log.i(
                TAG,
                "VPN configuration updated. version=$version"
            )

            VPNConfigurationOperationResult.success(
                "VPN configuration updated successfully."
            )
        }

    /**
     * Updates VPN security mode.
     */
    suspend fun setSecurityMode(
        securityMode:
            VPNSecurityMode,
        reason:
            String =
            "Security mode changed"
    ):
            VPNConfigurationOperationResult {

        return updateConfiguration(
            newConfiguration =
                getConfiguration().copy(
                    securityMode =
                        securityMode
                ),

            reason =
                reason
        )
    }

    /**
     * Updates VPN MTU.
     */
    suspend fun setMtu(
        mtu:
            Int
    ):
            VPNConfigurationOperationResult {

        if (
            mtu !in MIN_MTU..MAX_MTU
        ) {

            return VPNConfigurationOperationResult.failure(
                "VPN MTU must be between " +
                        "$MIN_MTU and $MAX_MTU."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                mtu =
                    mtu
            ),

            reason =
                "VPN MTU changed to $mtu"
        )
    }

    /**
     * Updates local VPN address.
     */
    suspend fun setLocalAddress(
        localAddress:
            String
    ):
            VPNConfigurationOperationResult {

        if (
            localAddress.isBlank()
        ) {

            return VPNConfigurationOperationResult.failure(
                "VPN local address cannot be blank."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                localAddress =
                    localAddress
            ),

            reason =
                "VPN local address changed"
        )
    }

    /**
     * Updates local IPv4 address.
     */
    suspend fun setLocalIpv4Address(
        address:
            String
    ):
            VPNConfigurationOperationResult {

        if (
            address.isBlank()
        ) {

            return VPNConfigurationOperationResult.failure(
                "VPN IPv4 address cannot be blank."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                localIpv4Address =
                    address
            ),

            reason =
                "VPN IPv4 address changed"
        )
    }

    /**
     * Updates local IPv6 address.
     */
    suspend fun setLocalIpv6Address(
        address:
            String?
    ):
            VPNConfigurationOperationResult {

        if (
            address != null &&
            address.isBlank()
        ) {

            return VPNConfigurationOperationResult.failure(
                "VPN IPv6 address cannot be blank."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                localIpv6Address =
                    address
            ),

            reason =
                "VPN IPv6 address changed"
        )
    }

    /**
     * Updates VPN server address.
     */
    suspend fun setServerAddress(
        serverAddress:
            String?
    ):
            VPNConfigurationOperationResult {

        if (
            serverAddress != null &&
            serverAddress.isBlank()
        ) {

            return VPNConfigurationOperationResult.failure(
                "VPN server address cannot be blank."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                serverAddress =
                    serverAddress
            ),

            reason =
                "VPN server address changed"
        )
    }

    /**
     * Replaces the DNS server list.
     */
    suspend fun setDnsServers(
        dnsServers:
            List<String>
    ):
            VPNConfigurationOperationResult {

        val normalized =
            dnsServers
                .map {
                    it.trim()
                }
                .filter {
                    it.isNotBlank()
                }
                .distinct()

        if (
            normalized.isEmpty()
        ) {

            return VPNConfigurationOperationResult.failure(
                "At least one valid DNS server is required."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                dnsServers =
                    normalized
            ),

            reason =
                "VPN DNS servers changed"
        )
    }

    /**
     * Adds one DNS server.
     */
    suspend fun addDnsServer(
        dnsServer:
            String
    ):
            VPNConfigurationOperationResult {

        val normalized =
            dnsServer.trim()

        if (
            normalized.isBlank()
        ) {

            return VPNConfigurationOperationResult.failure(
                "DNS server cannot be blank."
            )
        }

        val current =
            getConfiguration()

        if (
            current.dnsServers
                .any {
                    it.equals(
                        normalized,
                        ignoreCase = true
                    )
                }
        ) {

            return VPNConfigurationOperationResult.success(
                "DNS server already exists."
            )
        }

        return setDnsServers(
            current.dnsServers +
                    normalized
        )
    }

    /**
     * Removes one DNS server.
     */
    suspend fun removeDnsServer(
        dnsServer:
            String
    ):
            VPNConfigurationOperationResult {

        val current =
            getConfiguration()

        val updated =
            current.dnsServers
                .filterNot {
                    it.equals(
                        dnsServer,
                        ignoreCase = true
                    )
                }

        if (
            updated.isEmpty()
        ) {

            return VPNConfigurationOperationResult.failure(
                "VPN must retain at least one DNS server."
            )
        }

        return setDnsServers(
            updated
        )
    }

    /**
     * Enables or disables IPv6.
     */
    suspend fun setIpv6Enabled(
        enabled:
            Boolean
    ):
            VPNConfigurationOperationResult {

        return updateConfiguration(
            getConfiguration().copy(
                enableIpv6 =
                    enabled
            ),

            reason =
                "IPv6 ${if (enabled) "enabled" else "disabled"}"
        )
    }

    /**
     * Enables or disables DNS protection.
     */
    suspend fun setDnsProtectionEnabled(
        enabled:
            Boolean
    ):
            VPNConfigurationOperationResult {

        return updateConfiguration(
            getConfiguration().copy(
                enableDnsProtection =
                    enabled
            ),

            reason =
                "DNS protection " +
                        if (enabled) {
                            "enabled"
                        } else {
                            "disabled"
                        }
        )
    }

    /**
     * Enables or disables traffic inspection.
     */
    suspend fun setTrafficInspectionEnabled(
        enabled:
            Boolean
    ):
            VPNConfigurationOperationResult {

        return updateConfiguration(
            getConfiguration().copy(
                enableTrafficInspection =
                    enabled
            ),

            reason =
                "Traffic inspection " +
                        if (enabled) {
                            "enabled"
                        } else {
                            "disabled"
                        }
        )
    }

    /**
     * Enables or disables threat filtering.
     */
    suspend fun setThreatFilteringEnabled(
        enabled:
            Boolean
    ):
            VPNConfigurationOperationResult {

        return updateConfiguration(
            getConfiguration().copy(
                enableThreatFiltering =
                    enabled
            ),

            reason =
                "Threat filtering " +
                        if (enabled) {
                            "enabled"
                        } else {
                            "disabled"
                        }
        )
    }

    /**
     * Enables or disables firewall integration.
     */
    suspend fun setFirewallIntegrationEnabled(
        enabled:
            Boolean
    ):
            VPNConfigurationOperationResult {

        return updateConfiguration(
            getConfiguration().copy(
                enableFirewallIntegration =
                    enabled
            ),

            reason =
                "Firewall integration " +
                        if (enabled) {
                            "enabled"
                        } else {
                            "disabled"
                        }
        )
    }

    /**
     * Updates the VPN session timeout.
     */
    suspend fun setSessionTimeout(
        timeoutMs:
            Long
    ):
            VPNConfigurationOperationResult {

        if (
            timeoutMs <= 0
        ) {

            return VPNConfigurationOperationResult.failure(
                "VPN session timeout must be greater than zero."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                sessionTimeoutMs =
                    timeoutMs
            ),

            reason =
                "VPN session timeout changed"
        )
    }

    /**
     * Updates maximum packet size.
     */
    suspend fun setMaxPacketSize(
        packetSize:
            Int
    ):
            VPNConfigurationOperationResult {

        if (
            packetSize !in
            MIN_PACKET_SIZE..MAX_PACKET_SIZE
        ) {

            return VPNConfigurationOperationResult.failure(
                "Maximum packet size must be between " +
                        "$MIN_PACKET_SIZE and $MAX_PACKET_SIZE."
            )
        }

        return updateConfiguration(
            getConfiguration().copy(
                maxPacketSize =
                    packetSize
            ),

            reason =
                "VPN maximum packet size changed"
        )
    }

    /**
     * Creates a configuration profile.
     */
    suspend fun createProfile(
        name:
            String,
        configuration:
            VPNConfiguration =
            getConfiguration(),
        description:
            String? =
            null
    ):
            VPNProfileOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val normalizedName =
                name.trim()

            if (
                normalizedName.isBlank()
            ) {

                return@withContext
                    VPNProfileOperationResult.failure(
                        "Profile name cannot be blank."
                    )
            }

            if (
                profiles.size >=
                MAX_PROFILES
            ) {

                return@withContext
                    VPNProfileOperationResult.failure(
                        "Maximum VPN profile count reached."
                    )
            }

            val validation =
                validateConfiguration(
                    configuration
                )

            if (
                !validation.valid
            ) {

                return@withContext
                    VPNProfileOperationResult.failure(
                        validation.message
                    )
            }

            if (
                profiles.values.any {
                    it.name.equals(
                        normalizedName,
                        ignoreCase = true
                    )
                }
            ) {

                return@withContext
                    VPNProfileOperationResult.failure(
                        "A VPN profile with this name already exists."
                    )
            }

            val profile =
                VPNConfigurationProfile(

                    id =
                        generateProfileId(),

                    name =
                        normalizedName,

                    description =
                        description
                            ?.trim()
                            ?.takeIf {
                                it.isNotBlank()
                            },

                    configuration =
                        configuration,

                    createdAt =
                        System.currentTimeMillis(),

                    updatedAt =
                        System.currentTimeMillis()
                )

            profiles[
                profile.id
            ] =
                profile

            statistics
                .incrementProfilesCreated()

            Log.i(
                TAG,
                "VPN profile created: ${profile.name}"
            )

            VPNProfileOperationResult.success(
                profile
            )
        }

    /**
     * Updates an existing profile.
     */
    suspend fun updateProfile(
        profileId:
            String,
        name:
            String? =
            null,
        description:
            String? =
            null,
        configuration:
            VPNConfiguration? =
            null
    ):
            VPNProfileOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val existing =
                profiles[
                    profileId
                ]
                    ?: return@withContext
                        VPNProfileOperationResult.failure(
                            "VPN profile not found."
                        )

            val newName =
                name
                    ?.trim()
                    ?.takeIf {
                        it.isNotBlank()
                    }
                    ?: existing.name

            if (
                profiles.values.any {

                    it.id != profileId &&
                            it.name.equals(
                                newName,
                                ignoreCase = true
                            )
                }
            ) {

                return@withContext
                    VPNProfileOperationResult.failure(
                        "Another VPN profile already uses this name."
                    )
            }

            if (
                configuration != null
            ) {

                val validation =
                    validateConfiguration(
                        configuration
                    )

                if (
                    !validation.valid
                ) {

                    return@withContext
                        VPNProfileOperationResult.failure(
                            validation.message
                        )
                }
            }

            val updated =
                existing.copy(

                    name =
                        newName,

                    description =
                        description
                            ?.trim()
                            ?.takeIf {
                                it.isNotBlank()
                            }
                            ?: existing.description,

                    configuration =
                        configuration
                            ?: existing.configuration,

                    updatedAt =
                        System.currentTimeMillis()
                )

            profiles[
                profileId
            ] =
                updated

            statistics
                .incrementProfilesUpdated()

            VPNProfileOperationResult.success(
                updated
            )
        }

    /**
     * Deletes a profile.
     */
    suspend fun deleteProfile(
        profileId:
            String
    ):
            VPNProfileOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val removed =
                profiles.remove(
                    profileId
                )

            if (
                removed == null
            ) {

                return@withContext
                    VPNProfileOperationResult.failure(
                        "VPN profile not found."
                    )
            }

            statistics
                .incrementProfilesDeleted()

            Log.i(
                TAG,
                "VPN profile deleted: ${removed.name}"
            )

            VPNProfileOperationResult.success(
                "VPN profile deleted successfully."
            )
        }

    /**
     * Returns a profile by ID.
     */
    fun getProfile(
        profileId:
            String
    ):
            VPNConfigurationProfile? {

        return profiles[
            profileId
        ]
    }

    /**
     * Returns all profiles.
     */
    fun getProfiles():
            List<VPNConfigurationProfile> {

        return profiles.values
            .sortedBy {
                it.name.lowercase()
            }
    }

    /**
     * Activates a saved profile.
     */
    suspend fun activateProfile(
        profileId:
            String
    ):
            VPNConfigurationOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val profile =
                profiles[
                    profileId
                ]
                    ?: return@withContext
                        VPNConfigurationOperationResult.failure(
                            "VPN profile not found."
                        )

            val result =
                updateConfiguration(
                    newConfiguration =
                        profile.configuration,

                    reason =
                        "VPN profile '${profile.name}' activated"
                )

            if (
                result.success
            ) {

                statistics
                    .incrementProfileActivations()
            }

            result
        }

    /**
     * Saves the current configuration as a profile.
     */
    suspend fun saveCurrentAsProfile(
        name:
            String,
        description:
            String? =
            null
    ):
            VPNProfileOperationResult {

        return createProfile(
            name =
                name,

            configuration =
                getConfiguration(),

            description =
                description
        )
    }

    /**
     * Resets the active configuration to defaults.
     */
    suspend fun resetToDefaults():
            VPNConfigurationOperationResult {

        return updateConfiguration(
            newConfiguration =
                managerConfiguration
                    .defaultConfiguration,

            reason =
                "VPN configuration reset to defaults"
        )
    }

    /**
     * Creates a high-security configuration.
     */
    suspend fun applyHighSecurityPreset():
            VPNConfigurationOperationResult {

        val current =
            getConfiguration()

        val highSecurity =
            current.copy(

                securityMode =
                    VPNSecurityMode.MAXIMUM,

                enableIpv6 =
                    true,

                enableDnsProtection =
                    true,

                enableTrafficInspection =
                    true,

                enableThreatFiltering =
                    true,

                enableFirewallIntegration =
                    true
            )

        return updateConfiguration(
            newConfiguration =
                highSecurity,

            reason =
                "High-security VPN preset applied"
        )
    }

    /**
     * Creates a balanced configuration.
     */
    suspend fun applyBalancedPreset():
            VPNConfigurationOperationResult {

        val current =
            getConfiguration()

        val balanced =
            current.copy(

                securityMode =
                    VPNSecurityMode.BALANCED,

                enableIpv6 =
                    true,

                enableDnsProtection =
                    true,

                enableTrafficInspection =
                    true,

                enableThreatFiltering =
                    true,

                enableFirewallIntegration =
                    true
            )

        return updateConfiguration(
            newConfiguration =
                balanced,

            reason =
                "Balanced VPN preset applied"
        )
    }

    /**
     * Creates a performance-oriented configuration.
     */
    suspend fun applyPerformancePreset():
            VPNConfigurationOperationResult {

        val current =
            getConfiguration()

        val performance =
            current.copy(

                securityMode =
                    VPNSecurityMode.BASIC,

                enableIpv6 =
                    true,

                enableDnsProtection =
                    true,

                enableTrafficInspection =
                    false,

                enableThreatFiltering =
                    false,

                enableFirewallIntegration =
                    true
            )

        return updateConfiguration(
            newConfiguration =
                performance,

            reason =
                "Performance VPN preset applied"
        )
    }

    /**
     * Validates a complete VPN configuration.
     */
    fun validateConfiguration(
        configuration:
            VPNConfiguration
    ):
            VPNConfigurationValidationResult {

        if (
            configuration.localAddress.isBlank()
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN local address cannot be blank."
            )
        }

        if (
            configuration.localIpv4Address
                .isNullOrBlank()
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN local IPv4 address cannot be blank."
            )
        }

        if (
            configuration.mtu !in
            MIN_MTU..MAX_MTU
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN MTU must be between " +
                        "$MIN_MTU and $MAX_MTU."
            )
        }

        if (
            configuration.maxPacketSize !in
            MIN_PACKET_SIZE..MAX_PACKET_SIZE
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN maximum packet size must be between " +
                        "$MIN_PACKET_SIZE and $MAX_PACKET_SIZE."
            )
        }

        if (
            configuration.sessionTimeoutMs <= 0
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN session timeout must be greater than zero."
            )
        }

        if (
            configuration.dnsServers.isEmpty()
        ) {

            return VPNConfigurationValidationResult.invalid(
                "At least one DNS server must be configured."
            )
        }

        if (
            configuration.dnsServers.any {
                it.isBlank()
            }
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN DNS server list contains a blank entry."
            )
        }

        if (
            configuration.serverAddress
                ?.isBlank() == true
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN server address cannot be blank."
            )
        }

        if (
            !configuration.enableThreatFiltering &&
            configuration.securityMode ==
            VPNSecurityMode.MAXIMUM
        ) {

            return VPNConfigurationValidationResult.invalid(
                "Maximum security mode requires threat filtering."
            )
        }

        if (
            !configuration.enableTrafficInspection &&
            configuration.securityMode ==
            VPNSecurityMode.STRICT
        ) {

            return VPNConfigurationValidationResult.invalid(
                "Strict security mode requires traffic inspection."
            )
        }

        if (
            !configuration.enableDnsProtection &&
            configuration.securityMode ==
            VPNSecurityMode.MAXIMUM
        ) {

            return VPNConfigurationValidationResult.invalid(
                "Maximum security mode requires DNS protection."
            )
        }

        return VPNConfigurationValidationResult.valid()
    }

    /**
     * Returns configuration history.
     */
    fun getConfigurationHistory():
            List<VPNConfigurationChange> {

        return configurationHistory.toList()
    }

    /**
     * Returns recent configuration changes.
     */
    fun getRecentChanges(
        limit:
            Int = 100
    ):
            List<VPNConfigurationChange> {

        require(
            limit > 0
        ) {
            "History limit must be greater than zero."
        }

        return configurationHistory
            .take(
                limit
            )
    }

    /**
     * Searches configuration history.
     */
    fun searchConfigurationHistory(
        query:
            String,
        limit:
            Int = 100
    ):
            List<VPNConfigurationChange> {

        require(
            limit > 0
        ) {
            "History limit must be greater than zero."
        }

        if (
            query.isBlank()
        ) {

            return getRecentChanges(
                limit
            )
        }

        val normalized =
            query
                .trim()
                .lowercase()

        return configurationHistory
            .filter {

                it.id
                    .lowercase()
                    .contains(
                        normalized
                    ) ||

                        it.reason
                            .lowercase()
                            .contains(
                                normalized
                            ) ||

                        it.version
                            .toString()
                            .contains(
                                normalized
                            )
            }
            .take(
                limit
            )
    }

    /**
     * Clears configuration history.
     */
    suspend fun clearConfigurationHistory():
            VPNConfigurationOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val count =
                configurationHistory.size

            configurationHistory.clear()

            statistics
                .incrementHistoryCleared(
                    count
                )

            VPNConfigurationOperationResult.success(
                "VPN configuration history cleared."
            )
        }

    /**
     * Returns configuration statistics.
     */
    fun getStatistics():
            VPNConfigurationStatistics {

        return statistics.snapshot(
            historySize =
                configurationHistory.size,

            profileCount =
                profiles.size,

            currentVersion =
                versionCounter.get()
        )
    }

    /**
     * Records a configuration change.
     */
    private fun recordConfigurationChange(
        previous:
            VPNConfiguration,
        current:
            VPNConfiguration,
        reason:
            String,
        version:
            Long
    ) {

        val change =
            VPNConfigurationChange(

                id =
                    generateChangeId(),

                version =
                    version,

                previousConfiguration =
                    previous,

                newConfiguration =
                    current,

                reason =
                    reason,

                timestamp =
                    System.currentTimeMillis()
            )

        configurationHistory.addFirst(
            change
        )

        while (
            configurationHistory.size >
            MAX_HISTORY
        ) {

            configurationHistory.pollLast()
        }
    }

    /**
     * Generates profile ID.
     */
    private fun generateProfileId():
            String {

        return "VPN_PROFILE_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(20)
                    .uppercase()
    }

    /**
     * Generates configuration change ID.
     */
    private fun generateChangeId():
            String {

        return "VPN_CONFIG_CHANGE_" +
                UUID.randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(20)
                    .uppercase()
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
                "VPN configuration operation was cancelled."
            )
        }
    }

    /**
     * Releases resources.
     */
    fun close() {

        profiles.clear()

        configurationHistory.clear()

        _activeConfiguration.value =
            managerConfiguration
                .defaultConfiguration

        Log.i(
            TAG,
            "VPNConfigurationManager closed."
        )
    }
}

/**
 * Configuration manager settings.
 */
data class VPNConfigurationManagerSettings(

    /**
     * Default VPN configuration.
     */
    val defaultConfiguration:
        VPNConfiguration =
        VPNConfiguration(

            localAddress =
                "10.8.0.2",

            localIpv4Address =
                "10.8.0.2",

            localIpv6Address =
                null,

            serverAddress =
                null,

            dnsServers =
                listOf(
                    "1.1.1.1",
                    "8.8.8.8"
                ),

            mtu =
                1500,

            maxPacketSize =
                32 * 1024,

            sessionTimeoutMs =
                60L *
                        60L *
                        1000L,

            securityMode =
                VPNSecurityMode.BALANCED,

            enableIpv6 =
                true,

            enableDnsProtection =
                true,

            enableTrafficInspection =
                true,

            enableThreatFiltering =
                true,

            enableFirewallIntegration =
                true
        )
)

/**
 * Saved VPN configuration profile.
 */
data class VPNConfigurationProfile(

    /**
     * Unique profile ID.
     */
    val id:
        String,

    /**
     * Human-readable profile name.
     */
    val name:
        String,

    /**
     * Optional description.
     */
    val description:
        String?,

    /**
     * Configuration stored by the profile.
     */
    val configuration:
        VPNConfiguration,

    /**
     * Creation timestamp.
     */
    val createdAt:
        Long,

    /**
     * Last modification timestamp.
     */
    val updatedAt:
        Long
)

/**
 * Represents one configuration change.
 */
data class VPNConfigurationChange(

    /**
     * Unique change ID.
     */
    val id:
        String,

    /**
     * Configuration version.
     */
    val version:
        Long,

    /**
     * Previous configuration.
     */
    val previousConfiguration:
        VPNConfiguration,

    /**
     * New configuration.
     */
    val newConfiguration:
        VPNConfiguration,

    /**
     * Human-readable reason.
     */
    val reason:
        String,

    /**
     * Change timestamp.
     */
    val timestamp:
        Long
)

/**
 * Configuration validation result.
 */
data class VPNConfigurationValidationResult(

    val valid:
        Boolean,

    val message:
        String
) {

    companion object {

        fun valid():
                VPNConfigurationValidationResult {

            return VPNConfigurationValidationResult(
                valid =
                    true,

                message =
                    "VPN configuration is valid."
            )
        }

        fun invalid(
            message:
                String
        ):
                VPNConfigurationValidationResult {

            return VPNConfigurationValidationResult(
                valid =
                    false,

                message =
                    message
            )
        }
    }
}

/**
 * Generic configuration operation result.
 */
data class VPNConfigurationOperationResult(

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
                VPNConfigurationOperationResult {

            return VPNConfigurationOperationResult(
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
                VPNConfigurationOperationResult {

            return VPNConfigurationOperationResult(
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
 * Configuration update result.
 */
typealias VPNConfigurationOperationResultAlias =
    VPNConfigurationOperationResult

/**
 * Profile operation result.
 */
data class VPNProfileOperationResult(

    val success:
        Boolean,

    val profile:
        VPNConfigurationProfile?,

    val message:
        String
) {

    companion object {

        fun success(
            profile:
                VPNConfigurationProfile
        ):
                VPNProfileOperationResult {

            return VPNProfileOperationResult(
                success =
                    true,

                profile =
                    profile,

                message =
                    "VPN profile operation completed successfully."
            )
        }

        fun failure(
            message:
                String
        ):
                VPNProfileOperationResult {

            return VPNProfileOperationResult(
                success =
                    false,

                profile =
                    null,

                message =
                    message
            )
        }
    }
}

/**
 * Configuration manager statistics.
 */
data class VPNConfigurationStatistics(

    val initializations:
        Long,

    val updates:
        Long,

    val validationFailures:
        Long,

    val profilesCreated:
        Long,

    val profilesUpdated:
        Long,

    val profilesDeleted:
        Long,

    val profileActivations:
        Long,

    val historyCleared:
        Long,

    val historySize:
        Int,

    val profileCount:
        Int,

    val currentVersion:
        Long
)

/**
 * Thread-safe configuration statistics.
 */
private class VPNConfigurationStatisticsCounter {

    private val initializations =
        AtomicLong(0)

    private val updates =
        AtomicLong(0)

    private val validationFailures =
        AtomicLong(0)

    private val profilesCreated =
        AtomicLong(0)

    private val profilesUpdated =
        AtomicLong(0)

    private val profilesDeleted =
        AtomicLong(0)

    private val profileActivations =
        AtomicLong(0)

    private val historyCleared =
        AtomicLong(0)

    fun incrementInitializations() {
        initializations.incrementAndGet()
    }

    fun incrementUpdates() {
        updates.incrementAndGet()
    }

    fun incrementValidationFailures() {
        validationFailures.incrementAndGet()
    }

    fun incrementProfilesCreated() {
        profilesCreated.incrementAndGet()
    }

    fun incrementProfilesUpdated() {
        profilesUpdated.incrementAndGet()
    }

    fun incrementProfilesDeleted() {
        profilesDeleted.incrementAndGet()
    }

    fun incrementProfileActivations() {
        profileActivations.incrementAndGet()
    }

    fun incrementHistoryCleared(
        count:
            Int
    ) {

        if (
            count > 0
        ) {

            historyCleared.addAndGet(
                count.toLong()
            )
        }
    }

    fun snapshot(
        historySize:
            Int,
        profileCount:
            Int,
        currentVersion:
            Long
    ):
            VPNConfigurationStatistics {

        return VPNConfigurationStatistics(

            initializations =
                initializations.get(),

            updates =
                updates.get(),

            validationFailures =
                validationFailures.get(),

            profilesCreated =
                profilesCreated.get(),

            profilesUpdated =
                profilesUpdated.get(),

            profilesDeleted =
                profilesDeleted.get(),

            profileActivations =
                profileActivations.get(),

            historyCleared =
                historyCleared.get(),

            historySize =
                historySize,

            profileCount =
                profileCount,

            currentVersion =
                currentVersion
        )
    }
}
