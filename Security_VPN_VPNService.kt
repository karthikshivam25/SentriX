package com.sentrix.security.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VPNService
 *
 * Android VpnService implementation for SentriX.
 *
 * Responsibilities:
 *
 * - Integrate SentriX with Android VpnService.
 * - Create and maintain the TUN interface.
 * - Start/stop VPN protection.
 * - Maintain foreground-service state.
 * - Notify VPNManager about lifecycle changes.
 * - Configure VPN addresses.
 * - Configure DNS servers.
 * - Configure routes.
 * - Apply VPN security configuration.
 * - Safely close the VPN interface.
 *
 * This class does NOT:
 *
 * - Perform complete packet inspection.
 * - Implement threat intelligence.
 * - Decide whether a domain is malicious.
 * - Implement firewall policy logic.
 * - Store long-term security reports.
 *
 * Those responsibilities belong to:
 *
 * VPNManager
 * VPNEngine
 * VPNTrafficAnalyzer
 * FirewallEngine
 * Security logging components
 *
 * Important Android architecture:
 *
 *                 Android OS
 *                     |
 *                     v
 *               VPNService
 *                     |
 *                     v
 *                TUN Interface
 *                     |
 *                     v
 *                 VPNEngine
 *                     |
 *          ┌──────────┼───────────┐
 *          ▼          ▼           ▼
 *       Firewall   Threat      Traffic
 *       Engine     Engine      Analyzer
 *
 * AndroidManifest requirement:
 *
 * <service
 *     android:name=".security.vpn.VPNService"
 *     android:permission="android.permission.BIND_VPN_SERVICE"
 *     android:exported="false">
 *
 *     <intent-filter>
 *         <action android:name="android.net.VpnService" />
 *     </intent-filter>
 *
 * </service>
 */
class VPNService : VpnService() {

    companion object {

        private const val TAG =
            "SentriXVPNService"

        /**
         * Service action used to start VPN protection.
         */
        const val ACTION_START =
            "com.sentrix.security.vpn.action.START"

        /**
         * Service action used to stop VPN protection.
         */
        const val ACTION_STOP =
            "com.sentrix.security.vpn.action.STOP"

        /**
         * Service action used to restart VPN protection.
         */
        const val ACTION_RESTART =
            "com.sentrix.security.vpn.action.RESTART"

        /**
         * Service action used to update configuration.
         */
        const val ACTION_UPDATE_CONFIGURATION =
            "com.sentrix.security.vpn.action.UPDATE_CONFIGURATION"

        /**
         * Service action used to update security mode.
         */
        const val ACTION_UPDATE_SECURITY_MODE =
            "com.sentrix.security.vpn.action.UPDATE_SECURITY_MODE"

        /**
         * Service action used to pause VPN protection.
         */
        const val ACTION_PAUSE =
            "com.sentrix.security.vpn.action.PAUSE"

        /**
         * Service action used to resume VPN protection.
         */
        const val ACTION_RESUME =
            "com.sentrix.security.vpn.action.RESUME"

        /**
         * Service action used to query status.
         */
        const val ACTION_STATUS =
            "com.sentrix.security.vpn.action.STATUS"

        /**
         * Intent extra containing security mode.
         */
        const val EXTRA_SECURITY_MODE =
            "security_mode"

        /**
         * Notification channel.
         */
        private const val NOTIFICATION_CHANNEL_ID =
            "sentrix_vpn_protection"

        /**
         * Notification ID.
         */
        private const val NOTIFICATION_ID =
            4101

        /**
         * Default VPN address.
         */
        private const val DEFAULT_LOCAL_ADDRESS =
            "10.8.0.2"

        /**
         * Default VPN route.
         */
        private const val DEFAULT_ROUTE =
            "0.0.0.0"

        /**
         * Default route prefix.
         */
        private const val DEFAULT_ROUTE_PREFIX =
            0

        /**
         * Default MTU.
         */
        private const val DEFAULT_MTU =
            1500
    }

    /**
     * Coroutine scope used by the service.
     */
    private val serviceScope =
        CoroutineScope(
            SupervisorJob() +
                    Dispatchers.IO
        )

    /**
     * Indicates whether the VPN interface is currently active.
     */
    private val vpnRunning =
        AtomicBoolean(false)

    /**
     * Indicates whether service has been destroyed.
     */
    private val destroyed =
        AtomicBoolean(false)

    /**
     * TUN interface.
     */
    @Volatile
    private var vpnInterface:
        ParcelFileDescriptor? =
        null

    /**
     * Current VPN configuration.
     */
    @Volatile
    private var vpnConfiguration:
        VPNConfiguration =
        VPNConfiguration()

    /**
     * VPN manager.
     *
     * In a production Clean Architecture application this can
     * be supplied through dependency injection rather than being
     * instantiated directly here.
     */
    private lateinit var vpnManager:
        VPNManager

    /**
     * Optional runtime VPN engine.
     *
     * The actual implementation can be supplied once
     * VPNEngine.kt is introduced.
     */
    @Volatile
    private var vpnEngine:
        VPNRuntimeEngine? =
        null

    override fun onCreate() {
        super.onCreate()

        Log.i(
            TAG,
            "SentriX VPN service created."
        )

        vpnManager =
            VPNManager(
                applicationContext
            )

        serviceScope.launch {

            try {

                vpnManager.initialize()

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "VPN manager initialization failed.",
                    exception
                )
            }
        }
    }

    /**
     * Receives service commands.
     */
    override fun onStartCommand(
        intent:
            Intent?,
        flags:
            Int,
        startId:
            Int
    ):
            Int {

        if (
            destroyed.get()
        ) {

            return START_NOT_STICKY
        }

        val action =
            intent?.action

        Log.d(
            TAG,
            "Received VPN service action: $action"
        )

        when (
            action
        ) {

            ACTION_START ->
                handleStartCommand(
                    intent
                )

            ACTION_STOP ->
                handleStopCommand(
                    intent
                )

            ACTION_RESTART ->
                handleRestartCommand(
                    intent
                )

            ACTION_UPDATE_CONFIGURATION ->
                handleConfigurationUpdate(
                    intent
                )

            ACTION_UPDATE_SECURITY_MODE ->
                handleSecurityModeUpdate(
                    intent
                )

            ACTION_PAUSE ->
                handlePauseCommand()

            ACTION_RESUME ->
                handleResumeCommand()

            ACTION_STATUS ->
                handleStatusRequest()

            null ->
                handleStartCommand(
                    intent
                )

            else -> {

                Log.w(
                    TAG,
                    "Unknown VPN service action: $action"
                )
            }
        }

        return if (
            vpnRunning.get()
        ) {
            START_STICKY
        } else {
            START_NOT_STICKY
        }
    }

    /**
     * Handles VPN start command.
     */
    private fun handleStartCommand(
        intent:
            Intent?
    ) {

        serviceScope.launch {

            try {

                val configuration =
                    readConfiguration(
                        intent
                    )

                vpnConfiguration =
                    configuration

                val validation =
                    vpnManager
                        .validateConfiguration(
                            configuration
                        )

                if (
                    !validation.valid
                ) {

                    Log.e(
                        TAG,
                        "Invalid VPN configuration: " +
                                validation.message
                    )

                    vpnManager.onVpnError(
                        error =
                            VPNManagerErrorCode
                                .INVALID_CONFIGURATION,

                        message =
                            validation.message
                    )

                    stopVpnService(
                        "Invalid configuration"
                    )

                    return@launch
                }

                startVpnForeground()

                vpnManager.updateConfiguration(
                    configuration
                )

                vpnManager.startProtection()

                establishVpnInterface(
                    configuration
                )

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "Failed to start SentriX VPN.",
                    exception
                )

                vpnManager.onVpnError(
                    error =
                        VPNManagerErrorCode
                            .START_FAILED,

                    message =
                        exception.message
                            ?: "Unable to start VPN.",

                    throwable =
                        exception
                )

                closeVpnInterface()

                stopVpnService(
                    "VPN startup failure"
                )
            }
        }
    }

    /**
     * Handles VPN stop command.
     */
    private fun handleStopCommand(
        intent:
            Intent?
    ) {

        serviceScope.launch {

            val reason =
                intent?.getStringExtra(
                    "reason"
                )
                    ?: "VPN stopped by application."

            stopVpn(
                reason
            )
        }
    }

    /**
     * Handles restart command.
     */
    private fun handleRestartCommand(
        intent:
            Intent?
    ) {

        serviceScope.launch {

            try {

                Log.i(
                    TAG,
                    "Restarting SentriX VPN."
                )

                closeVpnInterface()

                vpnManager.onVpnDisconnected(
                    "VPN restart requested."
                )

                val configuration =
                    readConfiguration(
                        intent
                    )

                vpnConfiguration =
                    configuration

                vpnManager.updateConfiguration(
                    configuration
                )

                vpnManager.onServiceRestarted()

                establishVpnInterface(
                    configuration
                )

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "VPN restart failed.",
                    exception
                )

                vpnManager.onVpnError(
                    error =
                        VPNManagerErrorCode
                            .START_FAILED,

                    message =
                        exception.message
                            ?: "VPN restart failed.",

                    throwable =
                        exception
                )
            }
        }
    }

    /**
     * Handles configuration updates.
     */
    private fun handleConfigurationUpdate(
        intent:
            Intent?
    ) {

        serviceScope.launch {

            try {

                val configuration =
                    readConfiguration(
                        intent
                    )

                val validation =
                    vpnManager
                        .validateConfiguration(
                            configuration
                        )

                if (
                    !validation.valid
                ) {

                    Log.w(
                        TAG,
                        "Rejected VPN configuration update: " +
                                validation.message
                    )

                    return@launch
                }

                vpnConfiguration =
                    configuration

                vpnManager.updateConfiguration(
                    configuration
                )

                /*
                 * Configuration changes affecting the TUN
                 * interface generally require rebuilding the
                 * interface.
                 */
                if (
                    vpnRunning.get()
                ) {

                    closeVpnInterface()

                    establishVpnInterface(
                        configuration
                    )
                }

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "VPN configuration update failed.",
                    exception
                )
            }
        }
    }

    /**
     * Handles security-mode updates.
     */
    private fun handleSecurityModeUpdate(
        intent:
            Intent?
    ) {

        serviceScope.launch {

            val modeName =
                intent?.getStringExtra(
                    EXTRA_SECURITY_MODE
                )

            val mode =
                modeName
                    ?.let {
                        runCatching {
                            VPNSecurityMode.valueOf(
                                it
                            )
                        }.getOrNull()
                    }

            if (
                mode == null
            ) {

                Log.w(
                    TAG,
                    "Invalid VPN security mode: $modeName"
                )

                return@launch
            }

            vpnManager.setSecurityMode(
                mode
            )

            vpnConfiguration =
                vpnConfiguration.copy(
                    securityMode =
                        mode
                )

            vpnEngine?.updateSecurityMode(
                mode
            )

            updateNotification()
        }
    }

    /**
     * Pauses traffic inspection.
     *
     * The TUN interface remains available.
     *
     * Whether traffic is allowed or blocked during pause
     * should be determined by VPNEngine policy.
     */
    private fun handlePauseCommand() {

        serviceScope.launch {

            vpnEngine?.pause()

            Log.i(
                TAG,
                "VPN traffic processing paused."
            )

            updateNotification(
                "SentriX VPN protection paused"
            )
        }
    }

    /**
     * Resumes traffic processing.
     */
    private fun handleResumeCommand() {

        serviceScope.launch {

            vpnEngine?.resume()

            Log.i(
                TAG,
                "VPN traffic processing resumed."
            )

            updateNotification(
                "SentriX VPN protection active"
            )
        }
    }

    /**
     * Handles status request.
     *
     * This method currently logs the status. A Binder,
     * BroadcastReceiver or application event stream can
     * later expose the state to UI.
     */
    private fun handleStatusRequest() {

        val currentState =
            vpnManager.state.value

        Log.d(
            TAG,
            "VPN status: ${currentState.status}"
        )
    }

    /**
     * Establishes the Android TUN interface.
     */
    private suspend fun establishVpnInterface(
        configuration:
            VPNConfiguration
    ) {

        if (
            destroyed.get()
        ) {

            return
        }

        if (
            vpnRunning.get()
        ) {

            Log.d(
                TAG,
                "VPN interface is already running."
            )

            return
        }

        Log.i(
            TAG,
            "Establishing VPN interface."
        )

        val builder =
            Builder()

        configureBuilder(
            builder,
            configuration
        )

        val establishedInterface =
            builder.establish()

        if (
            establishedInterface == null
        ) {

            vpnManager.onVpnError(
                error =
                    VPNManagerErrorCode
                        .CONNECTION_FAILED,

                message =
                    "Android failed to establish the VPN interface."
            )

            stopVpnService(
                "Unable to establish VPN interface"
            )

            return
        }

        vpnInterface =
            establishedInterface

        vpnRunning.set(
            true
        )

        val connectionInfo =
            VPNConnectionInfo(

                serverAddress =
                    configuration.serverAddress,

                localAddress =
                    configuration.localAddress,

                localIpv4Address =
                    configuration.localIpv4Address,

                localIpv6Address =
                    configuration.localIpv6Address,

                dnsServers =
                    configuration.dnsServers,

                mtu =
                    configuration.mtu
            )

        vpnManager.onVpnConnected(
            connectionInfo
        )

        createRuntimeEngine(
            establishedInterface,
            configuration
        )

        updateNotification(
            "SentriX VPN protection active"
        )

        Log.i(
            TAG,
            "VPN interface established successfully."
        )
    }

    /**
     * Configures Android VPN Builder.
     */
    private fun configureBuilder(
        builder:
            Builder,
        configuration:
            VPNConfiguration
    ) {

        builder
            .setSession(
                "SentriX Secure VPN"
            )
            .setMtu(
                configuration.mtu
                    .coerceIn(
                        576,
                        65535
                    )
            )

        /*
         * Configure IPv4 address.
         */
        builder.addAddress(
            configuration.localIpv4Address
                ?: configuration.localAddress,
            32
        )

        /*
         * Configure IPv6 when enabled and available.
         */
        if (
            configuration.enableIpv6 &&
            !configuration.localIpv6Address
                .isNullOrBlank()
        ) {

            builder.addAddress(
                configuration.localIpv6Address,
                128
            )
        }

        /*
         * Route all IPv4 traffic through the TUN interface.
         *
         * The VPN engine must then decide how traffic is
         * processed/forwarded.
         */
        builder.addRoute(
            DEFAULT_ROUTE,
            DEFAULT_ROUTE_PREFIX
        )

        /*
         * Configure DNS protection.
         */
        if (
            configuration.enableDnsProtection
        ) {

            configuration.dnsServers
                .filter {
                    it.isNotBlank()
                }
                .distinct()
                .forEach { dnsServer ->

                    try {

                        builder.addDnsServer(
                            dnsServer
                        )

                    } catch (
                        exception: IllegalArgumentException
                    ) {

                        Log.w(
                            TAG,
                            "Invalid DNS server: $dnsServer"
                        )
                    }
                }
        }

        /*
         * Allow SentriX itself to access the network outside
         * the VPN tunnel if required.
         *
         * This should only be enabled when the architecture
         * requires it, because bypassing the VPN can affect
         * traffic visibility.
         */
        if (
            configuration.serverAddress
                .isNullOrBlank()
        ) {

            Log.d(
                TAG,
                "Running in local/device VPN mode."
            )
        }

        /*
         * VPN lock-down mode.
         *
         * Android can prevent network traffic from bypassing
         * the VPN when the surrounding application enables
         * always-on/lockdown behavior.
         *
         * This is intentionally not forced here because it is
         * an OS/user configuration concern.
         */
    }

    /**
     * Creates the runtime VPN engine.
     */
    private fun createRuntimeEngine(
        interfaceDescriptor:
            ParcelFileDescriptor,
        configuration:
            VPNConfiguration
    ) {

        vpnEngine?.close()

        val engine =
            DefaultVPNRuntimeEngine(
                interfaceDescriptor =
                    interfaceDescriptor,

                configuration =
                    configuration
            )

        vpnEngine =
            engine

        serviceScope.launch {

            try {

                engine.start()

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "VPN runtime engine failed.",
                    exception
                )

                vpnManager.onVpnError(
                    error =
                        VPNManagerErrorCode
                            .INTERNAL_ERROR,

                    message =
                        exception.message
                            ?: "VPN runtime engine failed.",

                    throwable =
                        exception
                )

                stopVpnService(
                    "VPN runtime engine failure"
                )
            }
        }
    }

    /**
     * Stops VPN protection.
     */
    private suspend fun stopVpn(
        reason:
            String
    ) {

        try {

            Log.i(
                TAG,
                "Stopping VPN: $reason"
            )

            vpnManager.stopProtection(
                reason
            )

            vpnEngine?.stop()

            vpnEngine?.close()

            vpnEngine =
                null

            closeVpnInterface()

            vpnManager.onVpnDisconnected(
                reason
            )

            stopForeground(
                STOP_FOREGROUND_REMOVE
            )

            stopSelf()

        } catch (
            exception: Exception
        ) {

            Log.e(
                TAG,
                "Failed to stop VPN cleanly.",
                exception
            )

            vpnManager.onVpnError(
                error =
                    VPNManagerErrorCode
                        .STOP_FAILED,

                message =
                    exception.message
                        ?: "Unable to stop VPN.",

                throwable =
                    exception
            )
        }
    }

    /**
     * Stops service without executing the full shutdown
     * lifecycle.
     */
    private fun stopVpnService(
        reason:
            String
    ) {

        Log.w(
            TAG,
            "Stopping VPN service: $reason"
        )

        closeVpnInterface()

        stopForeground(
            STOP_FOREGROUND_REMOVE
        )

        stopSelf()
    }

    /**
     * Safely closes the TUN interface.
     */
    private fun closeVpnInterface() {

        val descriptor =
            vpnInterface

        vpnInterface =
            null

        vpnRunning.set(
            false
        )

        if (
            descriptor == null
        ) {

            return
        }

        try {

            descriptor.close()

        } catch (
            exception: IOException
        ) {

            Log.w(
                TAG,
                "Failed to close VPN interface.",
                exception
            )
        }
    }

    /**
     * Reads VPN configuration from Intent extras.
     *
     * A production implementation can instead retrieve
     * configuration from VPNManager/repository.
     */
    private fun readConfiguration(
        intent:
            Intent?
    ):
            VPNConfiguration {

        val current =
            vpnConfiguration

        if (
            intent == null
        ) {

            return current
        }

        val mtu =
            intent.getIntExtra(
                "mtu",
                current.mtu
            )

        val localAddress =
            intent.getStringExtra(
                "local_address"
            )
                ?: current.localAddress

        val localIpv4 =
            intent.getStringExtra(
                "local_ipv4_address"
            )
                ?: current.localIpv4Address

        val localIpv6 =
            if (
                intent.hasExtra(
                    "local_ipv6_address"
                )
            ) {
                intent.getStringExtra(
                    "local_ipv6_address"
                )
            } else {
                current.localIpv6Address
            }

        val serverAddress =
            if (
                intent.hasExtra(
                    "server_address"
                )
            ) {
                intent.getStringExtra(
                    "server_address"
                )
            } else {
                current.serverAddress
            }

        val securityMode =
            intent.getStringExtra(
                EXTRA_SECURITY_MODE
            )
                ?.let {
                    runCatching {
                        VPNSecurityMode.valueOf(
                            it
                        )
                    }.getOrNull()
                }
                ?: current.securityMode

        return current.copy(

            localAddress =
                localAddress,

            localIpv4Address =
                localIpv4,

            localIpv6Address =
                localIpv6,

            serverAddress =
                serverAddress,

            mtu =
                mtu,

            securityMode =
                securityMode
        )
    }

    /**
     * Starts foreground service mode.
     */
    private fun startVpnForeground() {

        createNotificationChannel()

        val notification =
            createNotification(
                "Starting SentriX VPN protection"
            )

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.Q
        ) {

            startForeground(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo
                    .FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )

        } else {

            startForeground(
                NOTIFICATION_ID,
                notification
            )
        }
    }

    /**
     * Updates VPN notification.
     */
    private fun updateNotification(
        message:
            String =
            "SentriX VPN protection active"
    ) {

        if (
            !vpnRunning.get()
        ) {

            return
        }

        createNotificationChannel()

        val manager =
            getSystemService(
                NotificationManager::class.java
            )
                ?: return

        manager.notify(
            NOTIFICATION_ID,
            createNotification(
                message
            )
        )
    }

    /**
     * Creates VPN foreground notification.
     */
    private fun createNotification(
        message:
            String
    ):
            Notification {

        val launchIntent =
            packageManager
                .getLaunchIntentForPackage(
                    packageName
                )

        val pendingIntent =
            launchIntent?.let {

                PendingIntent.getActivity(
                    this,
                    0,
                    it,
                    PendingIntent.FLAG_UPDATE_CURRENT or
                            PendingIntent.FLAG_IMMUTABLE
                )
            }

        val builder =
            NotificationCompat.Builder(
                this,
                NOTIFICATION_CHANNEL_ID
            )
                .setContentTitle(
                    "SentriX VPN Protection"
                )
                .setContentText(
                    message
                )
                .setSmallIcon(
                    android.R.drawable
                        .ic_lock_lock
                )
                .setOngoing(
                    true
                )
                .setCategory(
                    NotificationCompat
                        .CATEGORY_SERVICE
                )
                .setPriority(
                    NotificationCompat
                        .PRIORITY_LOW
                )

        pendingIntent?.let {
            builder.setContentIntent(
                it
            )
        }

        return builder.build()
    }

    /**
     * Creates Android notification channel.
     */
    private fun createNotificationChannel() {

        if (
            Build.VERSION.SDK_INT <
            Build.VERSION_CODES.O
        ) {

            return
        }

        val manager =
            getSystemService(
                NotificationManager::class.java
            )
                ?: return

        val channel =
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID,

                "SentriX VPN Protection",

                NotificationManager
                    .IMPORTANCE_LOW
            ).apply {

                description =
                    "Shows the status of SentriX VPN security protection."

                setShowBadge(
                    false
                )
            }

        manager.createNotificationChannel(
            channel
        )
    }

    /**
     * Android service binding is intentionally not exposed.
     *
     * SentriX uses command-based service control through
     * explicit intents and VPNManager.
     */
    override fun onBind(
        intent:
            Intent
    ):
            IBinder? {

        return super.onBind(
            intent
        )
    }

    /**
     * Called when Android destroys the service.
     */
    override fun onDestroy() {

        Log.i(
            TAG,
            "SentriX VPN service destroying."
        )

        destroyed.set(
            true
        )

        vpnRunning.set(
            false
        )

        serviceScope.launch {

            try {

                vpnEngine?.stop()

                vpnEngine?.close()

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "VPN engine shutdown failed.",
                    exception
                )
            }
        }

        vpnEngine =
            null

        closeVpnInterface()

        if (
            ::vpnManager.isInitialized
        ) {

            vpnManager.close()
        }

        serviceScope.cancel()

        super.onDestroy()
    }

    /**
     * Called when the system revokes VPN/network state
     * or the service is otherwise removed.
     */
    override fun onRevoke() {

        Log.w(
            TAG,
            "Android revoked the VPN service."
        )

        serviceScope.launch {

            try {

                vpnEngine?.stop()

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "Failed to stop VPN engine after revoke.",
                    exception
                )
            }

            closeVpnInterface()

            if (
                ::vpnManager.isInitialized
            ) {

                vpnManager.onVpnDisconnected(
                    "VPN permission/service revoked by Android."
                )
            }

            stopForeground(
                STOP_FOREGROUND_REMOVE
            )

            stopSelf()
        }

        super.onRevoke()
    }
}

/**
 * Runtime abstraction used by VPNService.
 *
 * The actual packet-processing implementation can later
 * be supplied by VPNEngine.kt.
 */
interface VPNRuntimeEngine {

    /**
     * Starts packet processing.
     */
    suspend fun start()

    /**
     * Stops packet processing.
     */
    suspend fun stop()

    /**
     * Pauses packet processing.
     */
    suspend fun pause()

    /**
     * Resumes packet processing.
     */
    suspend fun resume()

    /**
     * Changes security mode.
     */
    suspend fun updateSecurityMode(
        securityMode:
            VPNSecurityMode
    )

    /**
     * Releases all resources.
     */
    fun close()
}

/**
 * Minimal runtime engine implementation.
 *
 * This is deliberately lightweight.
 *
 * It establishes the architectural contract between
 * VPNService and the future full VPNEngine.
 *
 * It does NOT attempt to implement a complete VPN packet
 * forwarding stack.
 */
private class DefaultVPNRuntimeEngine(
    private val interfaceDescriptor:
        ParcelFileDescriptor,
    private var configuration:
        VPNConfiguration
) : VPNRuntimeEngine {

    companion object {

        private const val TAG =
            "DefaultVPNRuntimeEngine"
    }

    @Volatile
    private var running =
        false

    @Volatile
    private var paused =
        false

    @Volatile
    private var securityMode =
        configuration.securityMode

    override suspend fun start() {

        if (
            running
        ) {

            return
        }

        running =
            true

        paused =
            false

        Log.i(
            TAG,
            "VPN runtime engine started. " +
                    "mode=$securityMode"
        )

        /*
         * IMPORTANT:
         *
         * The actual TUN packet read/write loop should be
         * implemented in VPNEngine.kt.
         *
         * This class only establishes the lifecycle contract.
         */
    }

    override suspend fun stop() {

        running =
            false

        paused =
            false

        Log.i(
            TAG,
            "VPN runtime engine stopped."
        )
    }

    override suspend fun pause() {

        if (
            running
        ) {

            paused =
                true

            Log.i(
                TAG,
                "VPN runtime engine paused."
            )
        }
    }

    override suspend fun resume() {

        if (
            running
        ) {

            paused =
                false

            Log.i(
                TAG,
                "VPN runtime engine resumed."
            )
        }
    }

    override suspend fun updateSecurityMode(
        securityMode:
            VPNSecurityMode
    ) {

        this.securityMode =
            securityMode

        Log.i(
            TAG,
            "VPN security mode changed: $securityMode"
        )
    }

    override fun close() {

        running =
            false

        paused =
            false

        Log.i(
            TAG,
            "VPN runtime engine released."
        )
    }
}
