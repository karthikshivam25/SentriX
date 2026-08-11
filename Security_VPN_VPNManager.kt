package com.sentrix.security.vpn

import android.content.Context
import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNManager
 *
 * Central lifecycle and orchestration manager for the SentriX VPN
 * security subsystem.
 *
 * Responsibilities:
 *
 * - Initialize the VPN subsystem.
 * - Start/stop VPN protection.
 * - Maintain VPN protection state.
 * - Manage VPN configuration.
 * - Track VPN sessions.
 * - Track connection statistics.
 * - Coordinate VPN security mode.
 * - Validate VPN configuration.
 * - Handle VPN permission state.
 * - Expose reactive VPN state.
 * - Maintain lifecycle statistics.
 *
 * This class does NOT:
 *
 * - Directly intercept packets.
 * - Implement VPN tunnel I/O.
 * - Perform packet inspection.
 * - Modify raw network packets.
 * - Implement threat analysis.
 *
 * Those responsibilities belong to components such as:
 *
 * VPNService
 * VPNEngine
 * VPNPacketInterceptor
 * VPNTrafficAnalyzer
 *
 * Architecture:
 *
 *                  VPNManager
 *                      |
 *          ┌───────────┼────────────┐
 *          ▼           ▼            ▼
 *      VPNService   VPNEngine   VPNConfiguration
 *          |
 *          ▼
 *    VPN tunnel / traffic
 *
 * SentriX VPNManager should be the main entry point for the
 * rest of the application when it needs to control VPN
 * protection.
 */
class VPNManager(
    context: Context,
    private val configuration:
        VPNManagerConfiguration =
        VPNManagerConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNManager"

        private const val DEFAULT_MTU =
            1500

        private const val MIN_MTU =
            576

        private const val MAX_MTU =
            65535
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Indicates whether manager has been initialized.
     */
    private val initialized =
        AtomicBoolean(false)

    /**
     * Indicates whether VPN protection is currently requested.
     */
    private val protectionRequested =
        AtomicBoolean(false)

    /**
     * Current VPN state.
     */
    private val _state =
        MutableStateFlow(
            VPNManagerState()
        )

    /**
     * Public immutable state.
     */
    val state:
        StateFlow<VPNManagerState> =
        _state.asStateFlow()

    /**
     * VPN session statistics.
     */
    private val statistics =
        VPNManagerStatisticsCounter()

    /**
     * Current VPN configuration.
     */
    @Volatile
    private var currentConfiguration:
        VPNConfiguration =
        VPNConfiguration()

    /**
     * Current VPN session.
     */
    @Volatile
    private var currentSession:
        VPNSession? =
        null

    /**
     * Initializes the VPN manager.
     */
    suspend fun initialize():
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized.get()
            ) {

                return@withContext
                    VPNManagerOperationResult.success(
                        "VPN manager is already initialized."
                    )
            }

            currentConfiguration =
                configuration.defaultVPNConfiguration

            initialized.set(
                true
            )

            updateState {
                it.copy(
                    initialized =
                        true,

                    configuration =
                        currentConfiguration,

                    securityMode =
                        currentConfiguration
                            .securityMode
                )
            }

            Log.i(
                TAG,
                "VPNManager initialized."
            )

            VPNManagerOperationResult.success(
                "VPN manager initialized successfully."
            )
        }

    /**
     * Returns whether manager is initialized.
     */
    fun isInitialized():
            Boolean {

        return initialized.get()
    }

    /**
     * Returns whether VPN protection is requested.
     */
    fun isProtectionRequested():
            Boolean {

        return protectionRequested.get()
    }

    /**
     * Returns whether VPN is currently connected.
     */
    fun isConnected():
            Boolean {

        return state.value.status ==
                VPNStatus.CONNECTED
    }

    /**
     * Returns current VPN status.
     */
    fun getStatus():
            VPNStatus {

        return state.value.status
    }

    /**
     * Checks whether Android VPN permission has been granted.
     *
     * VpnService.prepare() returns:
     *
     * null     -> permission already available
     * Intent   -> user authorization is required
     */
    fun isVpnPermissionGranted():
            Boolean {

        return try {

            VpnService.prepare(
                applicationContext
            ) == null

        } catch (
            exception: Exception
        ) {

            Log.e(
                TAG,
                "Unable to determine VPN permission state.",
                exception
            )

            false
        }
    }

    /**
     * Returns the VPN permission intent when authorization
     * is required.
     */
    fun getVpnPermissionIntent():
            android.content.Intent? {

        return try {

            VpnService.prepare(
                applicationContext
            )

        } catch (
            exception: Exception
        ) {

            Log.e(
                TAG,
                "Unable to prepare VPN permission intent.",
                exception
            )

            null
        }
    }

    /**
     * Requests VPN protection.
     *
     * The actual Android VPN service should be started by
     * the application/service layer after permission has
     * been granted.
     */
    suspend fun startProtection():
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            if (
                !isVpnPermissionGranted()
            ) {

                updateState {
                    it.copy(
                        status =
                            VPNStatus
                                .PERMISSION_REQUIRED,

                        lastError =
                            "VPN permission has not been granted."
                    )
                }

                return@withContext
                    VPNManagerOperationResult.failure(
                        message =
                            "VPN permission is required before starting protection.",

                        code =
                            VPNManagerErrorCode
                                .PERMISSION_REQUIRED
                    )
            }

            val validation =
                validateConfiguration(
                    currentConfiguration
                )

            if (
                !validation.valid
            ) {

                updateState {
                    it.copy(
                        status =
                            VPNStatus.ERROR,

                        lastError =
                            validation.message
                    )
                }

                return@withContext
                    VPNManagerOperationResult.failure(
                        message =
                            validation.message,

                        code =
                            VPNManagerErrorCode
                                .INVALID_CONFIGURATION
                    )
            }

            if (
                state.value.status ==
                VPNStatus.CONNECTED
            ) {

                return@withContext
                    VPNManagerOperationResult.success(
                        "VPN protection is already active."
                    )
            }

            protectionRequested.set(
                true
            )

            updateState {
                it.copy(
                    status =
                        VPNStatus.STARTING,

                    lastError =
                        null
                )
            }

            statistics.incrementStartRequests()

            /*
             * The actual VPNService startup is intentionally
             * delegated to the Android service layer.
             */
            Log.i(
                TAG,
                "VPN protection start requested."
            )

            VPNManagerOperationResult.success(
                "VPN protection start requested."
            )
        }

    /**
     * Requests VPN protection to stop.
     *
     * The actual service stop should be performed by the
     * VPNService/controller layer.
     */
    suspend fun stopProtection(
        reason:
            String =
            "Protection stopped by application."
    ):
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            protectionRequested.set(
                false
            )

            statistics.incrementStopRequests()

            updateState {
                it.copy(
                    status =
                        VPNStatus.STOPPING,

                    lastError =
                        null
                )
            }

            Log.i(
                TAG,
                "VPN protection stop requested: $reason"
            )

            VPNManagerOperationResult.success(
                "VPN protection stop requested."
            )
        }

    /**
     * Called by the VPN service when the tunnel is actually
     * established.
     */
    suspend fun onVpnConnected(
        sessionInfo:
            VPNConnectionInfo
    ):
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val session =
                VPNSession(
                    id =
                        generateSessionId(),

                    startedAt =
                        System.currentTimeMillis(),

                    serverAddress =
                        sessionInfo.serverAddress,

                    localAddress =
                        sessionInfo.localAddress,

                    localIpv4Address =
                        sessionInfo.localIpv4Address,

                    localIpv6Address =
                        sessionInfo.localIpv6Address,

                    dnsServers =
                        sessionInfo.dnsServers,

                    mtu =
                        sessionInfo.mtu,

                    securityMode =
                        currentConfiguration
                            .securityMode
                )

            currentSession =
                session

            protectionRequested.set(
                true
            )

            updateState {
                it.copy(
                    status =
                        VPNStatus.CONNECTED,

                    sessionId =
                        session.id,

                    connectedAt =
                        session.startedAt,

                    disconnectedAt =
                        null,

                    localAddress =
                        session.localAddress,

                    serverAddress =
                        session.serverAddress,

                    dnsServers =
                        session.dnsServers,

                    mtu =
                        session.mtu,

                    securityMode =
                        session.securityMode,

                    lastError =
                        null
                )
            }

            statistics.incrementSuccessfulConnections()

            Log.i(
                TAG,
                "VPN connected. session=${session.id}"
            )

            VPNManagerOperationResult.success(
                "VPN connection established."
            )
        }

    /**
     * Called by VPN service when the tunnel disconnects.
     */
    suspend fun onVpnDisconnected(
        reason:
            String? = null
    ):
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            val disconnectedAt =
                System.currentTimeMillis()

            currentSession?.let {
                statistics.recordSessionDuration(
                    disconnectedAt -
                            it.startedAt
                )
            }

            currentSession =
                null

            protectionRequested.set(
                false
            )

            updateState {
                it.copy(
                    status =
                        VPNStatus.DISCONNECTED,

                    sessionId =
                        null,

                    disconnectedAt =
                        disconnectedAt,

                    lastError =
                        reason
                )
            }

            Log.i(
                TAG,
                "VPN disconnected. reason=$reason"
            )

            VPNManagerOperationResult.success(
                "VPN connection disconnected."
            )
        }

    /**
     * Called by VPN service when an error occurs.
     */
    suspend fun onVpnError(
        error:
            VPNManagerErrorCode,
        message:
            String,
        throwable:
            Throwable? = null
    ):
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            statistics.incrementErrors()

            updateState {
                it.copy(
                    status =
                        VPNStatus.ERROR,

                    lastError =
                        message
                )
            }

            Log.e(
                TAG,
                "VPN error [$error]: $message",
                throwable
            )

            VPNManagerOperationResult.failure(
                message =
                    message,

                code =
                    error
            )
        }

    /**
     * Updates VPN traffic statistics.
     */
    fun updateTrafficStatistics(
        bytesSent:
            Long,
        bytesReceived:
            Long,
        packetsSent:
            Long,
        packetsReceived:
            Long,
        blockedConnections:
            Long = 0,
        allowedConnections:
            Long = 0
    ) {

        if (
            bytesSent < 0 ||
            bytesReceived < 0 ||
            packetsSent < 0 ||
            packetsReceived < 0
        ) {

            return
        }

        statistics.updateTraffic(
            bytesSent =
                bytesSent,

            bytesReceived =
                bytesReceived,

            packetsSent =
                packetsSent,

            packetsReceived =
                packetsReceived
        )

        updateState {

            it.copy(

                bytesSent =
                    bytesSent,

                bytesReceived =
                    bytesReceived,

                packetsSent =
                    packetsSent,

                packetsReceived =
                    packetsReceived,

                blockedConnections =
                    blockedConnections,

                allowedConnections =
                    allowedConnections
            )
        }
    }

    /**
     * Updates active connection counts.
     */
    fun updateConnectionCounts(
        activeConnections:
            Int,
        blockedConnections:
            Long,
        allowedConnections:
            Long
    ) {

        if (
            activeConnections < 0
        ) {

            return
        }

        updateState {
            it.copy(

                activeConnections =
                    activeConnections,

                blockedConnections =
                    blockedConnections,

                allowedConnections =
                    allowedConnections
            )
        }
    }

    /**
     * Changes VPN security mode.
     *
     * The new configuration will be used for the next
     * VPN engine/service configuration.
     */
    suspend fun setSecurityMode(
        securityMode:
            VPNSecurityMode
    ):
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            currentConfiguration =
                currentConfiguration.copy(
                    securityMode =
                        securityMode
                )

            updateState {
                it.copy(
                    securityMode =
                        securityMode,

                    configuration =
                        currentConfiguration
                )
            }

            statistics.incrementConfigurationChanges()

            Log.i(
                TAG,
                "VPN security mode changed to $securityMode."
            )

            VPNManagerOperationResult.success(
                "VPN security mode updated."
            )
        }

    /**
     * Updates the complete VPN configuration.
     */
    suspend fun updateConfiguration(
        newConfiguration:
            VPNConfiguration
    ):
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val validation =
                validateConfiguration(
                    newConfiguration
                )

            if (
                !validation.valid
            ) {

                return@withContext
                    VPNManagerOperationResult.failure(
                        validation.message,
                        VPNManagerErrorCode
                            .INVALID_CONFIGURATION
                    )
            }

            currentConfiguration =
                newConfiguration

            updateState {
                it.copy(
                    configuration =
                        newConfiguration,

                    securityMode =
                        newConfiguration
                            .securityMode
                )
            }

            statistics.incrementConfigurationChanges()

            Log.i(
                TAG,
                "VPN configuration updated."
            )

            VPNManagerOperationResult.success(
                "VPN configuration updated successfully."
            )
        }

    /**
     * Returns current VPN configuration.
     */
    fun getConfiguration():
            VPNConfiguration {

        return currentConfiguration
    }

    /**
     * Returns current VPN session.
     */
    fun getCurrentSession():
            VPNSession? {

        return currentSession
    }

    /**
     * Validates a VPN configuration.
     */
    fun validateConfiguration(
        vpnConfiguration:
            VPNConfiguration
    ):
            VPNConfigurationValidationResult {

        if (
            vpnConfiguration.mtu <
            MIN_MTU ||
            vpnConfiguration.mtu >
            MAX_MTU
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN MTU must be between $MIN_MTU and $MAX_MTU."
            )
        }

        if (
            vpnConfiguration.localAddress.isBlank()
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN local address cannot be blank."
            )
        }

        if (
            vpnConfiguration.sessionTimeoutMs <= 0
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN session timeout must be greater than zero."
            )
        }

        if (
            vpnConfiguration.maxPacketSize <= 0
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN maximum packet size must be greater than zero."
            )
        }

        if (
            vpnConfiguration.dnsServers
                .any {
                    it.isBlank()
                }
        ) {

            return VPNConfigurationValidationResult.invalid(
                "VPN DNS server list contains an invalid entry."
            )
        }

        return VPNConfigurationValidationResult.valid()
    }

    /**
     * Returns current VPN statistics.
     */
    fun getStatistics():
            VPNManagerStatistics {

        return statistics.snapshot()
    }

    /**
     * Returns a complete protection snapshot.
     */
    fun getProtectionSnapshot():
            VPNProtectionSnapshot {

        return VPNProtectionSnapshot(

            state =
                state.value,

            session =
                currentSession,

            statistics =
                getStatistics(),

            configuration =
                currentConfiguration
        )
    }

    /**
     * Handles Android service restart.
     */
    suspend fun onServiceRestarted():
            VPNManagerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            statistics.incrementServiceRestarts()

            updateState {
                it.copy(
                    serviceRestartCount =
                        it.serviceRestartCount + 1,

                    status =
                        if (
                            protectionRequested.get()
                        ) {
                            VPNStatus.STARTING
                        } else {
                            VPNStatus.DISCONNECTED
                        }
                )
            }

            VPNManagerOperationResult.success(
                "VPN service restart registered."
            )
        }

    /**
     * Resets current error.
     */
    fun clearError() {

        updateState {
            it.copy(
                lastError =
                    null
            )
        }
    }

    /**
     * Updates StateFlow atomically.
     */
    private fun updateState(
        transform:
            (VPNManagerState) ->
            VPNManagerState
    ) {

        _state.value =
            transform(
                _state.value
            )
    }

    /**
     * Generates session ID.
     */
    private fun generateSessionId():
            String {

        return "VPN_SESSION_" +
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
     * Ensures initialization.
     */
    private fun ensureInitialized() {

        check(
            initialized.get()
        ) {
            "VPNManager has not been initialized."
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
                "VPN manager operation was cancelled."
            )
        }
    }

    /**
     * Releases manager resources.
     */
    fun close() {

        protectionRequested.set(
            false
        )

        currentSession =
            null

        initialized.set(
            false
        )

        _state.value =
            VPNManagerState()

        Log.i(
            TAG,
            "VPNManager closed."
        )
    }
}

/**
 * Current VPN manager state.
 */
data class VPNManagerState(

    val initialized:
        Boolean = false,

    val status:
        VPNStatus =
        VPNStatus.DISCONNECTED,

    val sessionId:
        String? = null,

    val connectedAt:
        Long? = null,

    val disconnectedAt:
        Long? = null,

    val localAddress:
        String? = null,

    val serverAddress:
        String? = null,

    val dnsServers:
        List<String> =
        emptyList(),

    val mtu:
        Int = 1500,

    val securityMode:
        VPNSecurityMode =
        VPNSecurityMode.BALANCED,

    val activeConnections:
        Int = 0,

    val blockedConnections:
        Long = 0,

    val allowedConnections:
        Long = 0,

    val bytesSent:
        Long = 0,

    val bytesReceived:
        Long = 0,

    val packetsSent:
        Long = 0,

    val packetsReceived:
        Long = 0,

    val serviceRestartCount:
        Int = 0,

    val lastError:
        String? = null,

    val configuration:
        VPNConfiguration =
        VPNConfiguration()
)

/**
 * VPN lifecycle states.
 */
enum class VPNStatus {

    DISCONNECTED,

    PERMISSION_REQUIRED,

    STARTING,

    CONNECTED,

    STOPPING,

    ERROR
}

/**
 * VPN security modes.
 */
enum class VPNSecurityMode {

    /**
     * Basic VPN routing.
     */
    BASIC,

    /**
     * Balanced protection and performance.
     */
    BALANCED,

    /**
     * Strong inspection and protection.
     */
    STRICT,

    /**
     * Maximum security mode.
     */
    MAXIMUM
}

/**
 * VPN configuration.
 */
data class VPNConfiguration(

    /**
     * Local VPN address.
     */
    val localAddress:
        String =
        "10.8.0.2",

    /**
     * Local IPv4 address.
     */
    val localIpv4Address:
        String =
        "10.8.0.2",

    /**
     * Local IPv6 address.
     */
    val localIpv6Address:
        String? =
        null,

    /**
     * VPN server address.
     *
     * Null means local/device VPN mode.
     */
    val serverAddress:
        String? =
        null,

    /**
     * DNS servers used by the VPN.
     */
    val dnsServers:
        List<String> =
        listOf(
            "1.1.1.1",
            "8.8.8.8"
        ),

    /**
     * VPN MTU.
     */
    val mtu:
        Int = 1500,

    /**
     * Maximum packet size accepted by the VPN engine.
     */
    val maxPacketSize:
        Int = 32 * 1024,

    /**
     * VPN session timeout.
     */
    val sessionTimeoutMs:
        Long =
        60L * 60L * 1000L,

    /**
     * Security mode.
     */
    val securityMode:
        VPNSecurityMode =
        VPNSecurityMode.BALANCED,

    /**
     * Whether IPv6 should be supported.
     */
    val enableIpv6:
        Boolean = true,

    /**
     * Whether DNS protection is enabled.
     */
    val enableDnsProtection:
        Boolean = true,

    /**
     * Whether traffic inspection is enabled.
     */
    val enableTrafficInspection:
        Boolean = true,

    /**
     * Whether threat filtering is enabled.
     */
    val enableThreatFiltering:
        Boolean = true,

    /**
     * Whether firewall integration is enabled.
     */
    val enableFirewallIntegration:
        Boolean = true
)

/**
 * Information supplied by the VPN service after
 * successful tunnel establishment.
 */
data class VPNConnectionInfo(

    val serverAddress:
        String? = null,

    val localAddress:
        String,

    val localIpv4Address:
        String? = null,

    val localIpv6Address:
        String? = null,

    val dnsServers:
        List<String> =
        emptyList(),

    val mtu:
        Int = 1500
)

/**
 * Active VPN session.
 */
data class VPNSession(

    val id:
        String,

    val startedAt:
        Long,

    val serverAddress:
        String?,

    val localAddress:
        String,

    val localIpv4Address:
        String?,

    val localIpv6Address:
        String?,

    val dnsServers:
        List<String>,

    val mtu:
        Int,

    val securityMode:
        VPNSecurityMode
)

/**
 * Complete VPN protection snapshot.
 */
data class VPNProtectionSnapshot(

    val state:
        VPNManagerState,

    val session:
        VPNSession?,

    val statistics:
        VPNManagerStatistics,

    val configuration:
        VPNConfiguration
)

/**
 * Manager configuration.
 */
data class VPNManagerConfiguration(

    /**
     * Default VPN configuration.
     */
    val defaultVPNConfiguration:
        VPNConfiguration =
        VPNConfiguration(
            mtu =
                1500
        ),

    /**
     * Whether VPN permission is mandatory.
     */
    val requireVpnPermission:
        Boolean = true
)

/**
 * Manager operation result.
 */
data class VPNManagerOperationResult(

    val success:
        Boolean,

    val message:
        String,

    val code:
        VPNManagerErrorCode? = null
) {

    companion object {

        fun success(
            message:
                String
        ):
                VPNManagerOperationResult {

            return VPNManagerOperationResult(
                success =
                    true,

                message =
                    message
            )
        }

        fun failure(
            message:
                String,
            code:
                VPNManagerErrorCode
        ):
                VPNManagerOperationResult {

            return VPNManagerOperationResult(
                success =
                    false,

                message =
                    message,

                code =
                    code
            )
        }
    }
}

/**
 * VPN manager error categories.
 */
enum class VPNManagerErrorCode {

    NOT_INITIALIZED,

    PERMISSION_REQUIRED,

    INVALID_CONFIGURATION,

    START_FAILED,

    STOP_FAILED,

    SERVICE_UNAVAILABLE,

    CONNECTION_FAILED,

    INTERNAL_ERROR
}

/**
 * VPN configuration validation result.
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
 * VPN manager statistics.
 */
data class VPNManagerStatistics(

    val startRequests:
        Long,

    val stopRequests:
        Long,

    val successfulConnections:
        Long,

    val errors:
        Long,

    val configurationChanges:
        Long,

    val serviceRestarts:
        Long,

    val totalBytesSent:
        Long,

    val totalBytesReceived:
        Long,

    val totalPacketsSent:
        Long,

    val totalPacketsReceived:
        Long,

    val totalSessionDurationMs:
        Long
)

/**
 * Thread-safe VPN statistics counter.
 */
private class VPNManagerStatisticsCounter {

    private val startRequests =
        AtomicLong(0)

    private val stopRequests =
        AtomicLong(0)

    private val successfulConnections =
        AtomicLong(0)

    private val errors =
        AtomicLong(0)

    private val configurationChanges =
        AtomicLong(0)

    private val serviceRestarts =
        AtomicLong(0)

    private val totalBytesSent =
        AtomicLong(0)

    private val totalBytesReceived =
        AtomicLong(0)

    private val totalPacketsSent =
        AtomicLong(0)

    private val totalPacketsReceived =
        AtomicLong(0)

    private val totalSessionDurationMs =
        AtomicLong(0)

    fun incrementStartRequests() {
        startRequests.incrementAndGet()
    }

    fun incrementStopRequests() {
        stopRequests.incrementAndGet()
    }

    fun incrementSuccessfulConnections() {
        successfulConnections.incrementAndGet()
    }

    fun incrementErrors() {
        errors.incrementAndGet()
    }

    fun incrementConfigurationChanges() {
        configurationChanges.incrementAndGet()
    }

    fun incrementServiceRestarts() {
        serviceRestarts.incrementAndGet()
    }

    fun updateTraffic(
        bytesSent:
            Long,
        bytesReceived:
            Long,
        packetsSent:
            Long,
        packetsReceived:
            Long
    ) {

        totalBytesSent.updateAndGet {
            maxOf(
                it,
                bytesSent
            )
        }

        totalBytesReceived.updateAndGet {
            maxOf(
                it,
                bytesReceived
            )
        }

        totalPacketsSent.updateAndGet {
            maxOf(
                it,
                packetsSent
            )
        }

        totalPacketsReceived.updateAndGet {
            maxOf(
                it,
                packetsReceived
            )
        }
    }

    fun recordSessionDuration(
        durationMs:
            Long
    ) {

        if (
            durationMs > 0
        ) {

            totalSessionDurationMs
                .addAndGet(
                    durationMs
                )
        }
    }

    fun snapshot():
            VPNManagerStatistics {

        return VPNManagerStatistics(

            startRequests =
                startRequests.get(),

            stopRequests =
                stopRequests.get(),

            successfulConnections =
                successfulConnections.get(),

            errors =
                errors.get(),

            configurationChanges =
                configurationChanges.get(),

            serviceRestarts =
                serviceRestarts.get(),

            totalBytesSent =
                totalBytesSent.get(),

            totalBytesReceived =
                totalBytesReceived.get(),

            totalPacketsSent =
                totalPacketsSent.get(),

            totalPacketsReceived =
                totalPacketsReceived.get(),

            totalSessionDurationMs =
                totalSessionDurationMs.get()
        )
    }
}
