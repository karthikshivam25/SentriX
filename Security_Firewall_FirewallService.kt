package com.sentrix.security.firewall

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * FirewallService
 *
 * Foreground Android service responsible for running the SentriX
 * firewall protection lifecycle.
 *
 * IMPORTANT:
 *
 * Android does not permit an ordinary background application to
 * transparently inspect all device traffic.
 *
 * For real device-wide traffic interception, this service should
 * ultimately coordinate with Android's VpnService implementation.
 *
 * This service therefore acts as the firewall orchestration/service
 * layer and provides the lifecycle boundary for that implementation.
 *
 * Responsibilities:
 *
 * - Start firewall protection.
 * - Stop firewall protection.
 * - Maintain foreground-service status.
 * - Initialize FirewallManager.
 * - Monitor firewall state.
 * - Process firewall evaluation requests.
 * - Publish firewall status notifications.
 * - Expose a lightweight Binder API for in-process clients.
 * - Handle service lifecycle safely.
 *
 * Architecture:
 *
 * UI / Controller
 *       |
 *       v
 * FirewallService
 *       |
 *       v
 * FirewallManager
 *       |
 *       v
 * FirewallRuleEvaluator
 *       |
 *       v
 * ALLOW / BLOCK / MONITOR / WARN
 *
 * Future production architecture:
 *
 * Android VpnService
 *       |
 *       v
 * FirewallService
 *       |
 *       v
 * FirewallManager
 */
class FirewallService : Service() {

    companion object {

        private const val TAG =
            "SentriXFirewallService"

        /**
         * Foreground notification channel.
         */
        private const val CHANNEL_ID =
            "sentrix_firewall_protection"

        private const val CHANNEL_NAME =
            "SentriX Firewall Protection"

        private const val CHANNEL_DESCRIPTION =
            "Displays the current SentriX firewall protection status."

        /**
         * Notification ID.
         */
        private const val NOTIFICATION_ID =
            4101

        /**
         * Intent actions.
         */
        const val ACTION_START =
            "com.sentrix.security.firewall.START"

        const val ACTION_STOP =
            "com.sentrix.security.firewall.STOP"

        const val ACTION_REFRESH =
            "com.sentrix.security.firewall.REFRESH"

        const val ACTION_EVALUATE =
            "com.sentrix.security.firewall.EVALUATE"

        /**
         * Intent extras.
         */
        const val EXTRA_HOST =
            "com.sentrix.security.firewall.EXTRA_HOST"

        const val EXTRA_PORT =
            "com.sentrix.security.firewall.EXTRA_PORT"

        const val EXTRA_PACKAGE_NAME =
            "com.sentrix.security.firewall.EXTRA_PACKAGE_NAME"

        const val EXTRA_PROTOCOL =
            "com.sentrix.security.firewall.EXTRA_PROTOCOL"

        /**
         * Creates an intent to start firewall protection.
         */
        fun createStartIntent(
            context: Context
        ): Intent {

            return Intent(
                context,
                FirewallService::class.java
            ).apply {

                action =
                    ACTION_START
            }
        }

        /**
         * Creates an intent to stop firewall protection.
         */
        fun createStopIntent(
            context: Context
        ): Intent {

            return Intent(
                context,
                FirewallService::class.java
            ).apply {

                action =
                    ACTION_STOP
            }
        }

        /**
         * Creates an intent to refresh firewall status.
         */
        fun createRefreshIntent(
            context: Context
        ): Intent {

            return Intent(
                context,
                FirewallService::class.java
            ).apply {

                action =
                    ACTION_REFRESH
            }
        }
    }

    /**
     * Service coroutine scope.
     *
     * SupervisorJob prevents failure of one background operation
     * from automatically cancelling unrelated firewall tasks.
     */
    private val serviceScope =
        CoroutineScope(
            SupervisorJob() +
                    Dispatchers.Default
        )

    /**
     * Central firewall manager.
     *
     * Created after service initialization because Android services
     * must obtain their Context from the framework lifecycle.
     */
    private lateinit var firewallManager:
            FirewallManager

    /**
     * Binder exposed to in-process clients.
     */
    private val binder =
        FirewallBinder()

    /**
     * Indicates whether the service is actively protecting.
     */
    @Volatile
    private var protectionRunning =
        false

    /**
     * Indicates whether service initialization completed.
     */
    @Volatile
    private var serviceInitialized =
        false

    /**
     * Last known firewall status.
     */
    @Volatile
    private var lastStatus:
            FirewallStatus? = null

    /**
     * Android service creation.
     */
    override fun onCreate() {

        super.onCreate()

        Log.i(
            TAG,
            "FirewallService created."
        )

        createNotificationChannel()

        firewallManager =
            FirewallManager(
                context = applicationContext
            )

        serviceInitialized =
            true

        Log.i(
            TAG,
            "FirewallService initialized."
        )
    }

    /**
     * Handles service start commands.
     */
    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int
    ): Int {

        Log.d(
            TAG,
            "onStartCommand action=${intent?.action}"
        )

        when (
            intent?.action
        ) {

            ACTION_START ->
                startProtection()

            ACTION_STOP ->
                stopProtection()

            ACTION_REFRESH ->
                refreshStatus()

            ACTION_EVALUATE ->
                evaluateRequestFromIntent(
                    intent
                )

            else ->
                startProtection()
        }

        /*
         * START_STICKY allows Android to recreate the service after
         * process termination when appropriate.
         *
         * The recreated service should NOT automatically assume
         * that a previous firewall session is safe to resume until
         * the manager/state layer confirms the desired policy.
         */
        return START_STICKY
    }

    /**
     * Starts firewall protection.
     */
    private fun startProtection() {

        if (
            !serviceInitialized
        ) {

            Log.e(
                TAG,
                "Cannot start firewall: service not initialized."
            )

            return
        }

        if (
            protectionRunning
        ) {

            Log.d(
                TAG,
                "Firewall protection already running."
            )

            refreshStatus()

            return
        }

        /*
         * Android requires foreground services to display a
         * notification while they are active.
         */
        startForeground(
            NOTIFICATION_ID,
            createProtectionNotification(
                active = true
            )
        )

        serviceScope.launch {

            try {

                val result =
                    firewallManager
                        .startProtection()

                if (
                    result.success
                ) {

                    protectionRunning =
                        true

                    lastStatus =
                        firewallManager
                            .getStatus()

                    updateProtectionNotification(
                        active = true
                    )

                    Log.i(
                        TAG,
                        "Firewall protection started."
                    )

                } else {

                    Log.e(
                        TAG,
                        "Firewall failed to start: " +
                                result.message
                    )

                    protectionRunning =
                        false

                    updateProtectionNotification(
                        active = false
                    )
                }

            } catch (
                exception: CancellationException
            ) {

                throw exception

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "Unexpected firewall start error.",
                    exception
                )

                protectionRunning =
                    false

                updateProtectionNotification(
                    active = false
                )
            }
        }
    }

    /**
     * Stops firewall protection.
     */
    private fun stopProtection() {

        if (
            !serviceInitialized
        ) {

            stopSelf()
            return
        }

        serviceScope.launch {

            try {

                val result =
                    firewallManager
                        .stopProtection()

                if (
                    result.success
                ) {

                    protectionRunning =
                        false

                    lastStatus =
                        firewallManager
                            .getStatus()

                    Log.i(
                        TAG,
                        "Firewall protection stopped."
                    )

                } else {

                    Log.e(
                        TAG,
                        "Firewall stop failed: " +
                                result.message
                    )
                }

            } catch (
                exception: CancellationException
            ) {

                throw exception

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "Unexpected firewall stop error.",
                    exception
                )
            } finally {

                /*
                 * Stop foreground mode and remove the service.
                 */
                stopForeground(
                    STOP_FOREGROUND_REMOVE
                )

                stopSelf()
            }
        }
    }

    /**
     * Refreshes the cached firewall status.
     */
    private fun refreshStatus() {

        if (
            !serviceInitialized
        ) {
            return
        }

        serviceScope.launch {

            lastStatus =
                withContext(
                    Dispatchers.Default
                ) {
                    firewallManager
                        .getStatus()
                }

            updateProtectionNotification(
                active =
                    protectionRunning
            )
        }
    }

    /**
     * Evaluates a request passed through an Intent.
     *
     * This is primarily useful for internal testing or controlled
     * application-level integrations.
     */
    private fun evaluateRequestFromIntent(
        intent: Intent
    ) {

        val host =
            intent.getStringExtra(
                EXTRA_HOST
            )

        if (
            host.isNullOrBlank()
        ) {

            Log.w(
                TAG,
                "Firewall evaluation request missing host."
            )

            return
        }

        val port =
            if (
                intent.hasExtra(
                    EXTRA_PORT
                )
            ) {

                intent.getIntExtra(
                    EXTRA_PORT,
                    -1
                ).takeIf {
                    it > 0
                }

            } else {
                null
            }

        val packageName =
            intent.getStringExtra(
                EXTRA_PACKAGE_NAME
            )

        val protocol =
            intent.getStringExtra(
                EXTRA_PROTOCOL
            )?.let {

                try {

                    FirewallProtocol
                        .valueOf(
                            it.uppercase()
                        )

                } catch (
                    _: IllegalArgumentException
                ) {

                    FirewallProtocol.ANY
                }

            } ?: FirewallProtocol.ANY

        val request =
            FirewallNetworkRequest(
                host =
                    host,
                port =
                    port,
                packageName =
                    packageName,
                protocol =
                    protocol
            )

        serviceScope.launch {

            try {

                val result =
                    firewallManager
                        .evaluate(
                            request
                        )

                Log.i(
                    TAG,
                    "Firewall evaluation: " +
                            "host=$host, " +
                            "decision=${result.decision}, " +
                            "reason=${result.reason}"
                )

            } catch (
                exception: CancellationException
            ) {

                throw exception

            } catch (
                exception: Exception
            ) {

                Log.e(
                    TAG,
                    "Firewall evaluation failed.",
                    exception
                )
            }
        }
    }

    /**
     * Creates the foreground notification channel.
     */
    private fun createNotificationChannel() {

        if (
            Build.VERSION.SDK_INT <
            Build.VERSION_CODES.O
        ) {
            return
        }

        val notificationManager =
            getSystemService(
                NotificationManager::class.java
            )

        val channel =
            NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager
                    .IMPORTANCE_LOW
            ).apply {

                description =
                    CHANNEL_DESCRIPTION

                setShowBadge(false)

                /*
                 * Firewall protection status does not normally
                 * require sound/vibration.
                 */
                enableVibration(false)
                setSound(
                    null,
                    null
                )
            }

        notificationManager
            .createNotificationChannel(
                channel
            )
    }

    /**
     * Creates firewall foreground notification.
     */
    private fun createProtectionNotification(
        active: Boolean
    ): Notification {

        val title =
            if (active) {

                "SentriX Firewall Active"

            } else {

                "SentriX Firewall Inactive"
            }

        val text =
            if (active) {

                "Network protection is active."

            } else {

                "Network protection is currently inactive."
            }

        val launchIntent =
            packageManager
                .getLaunchIntentForPackage(
                    packageName
                )

        val pendingIntent =
            launchIntent?.let {

                PendingIntent.getActivity(
                    this,
                    1001,
                    it,
                    PendingIntent.FLAG_UPDATE_CURRENT or
                            PendingIntent.FLAG_IMMUTABLE
                )

            }

        val builder =
            NotificationCompat.Builder(
                this,
                CHANNEL_ID
            )
                .setSmallIcon(
                    android.R.drawable.ic_lock_lock
                )
                .setContentTitle(
                    title
                )
                .setContentText(
                    text
                )
                .setOngoing(
                    active
                )
                .setOnlyAlertOnce(
                    true
                )
                .setPriority(
                    NotificationCompat
                        .PRIORITY_LOW
                )

        if (
            pendingIntent != null
        ) {

            builder.setContentIntent(
                pendingIntent
            )
        }

        return builder.build()
    }

    /**
     * Updates the foreground notification.
     */
    private fun updateProtectionNotification(
        active: Boolean
    ) {

        if (
            !serviceInitialized
        ) {
            return
        }

        val notificationManager =
            getSystemService(
                NotificationManager::class.java
            )

        notificationManager.notify(
            NOTIFICATION_ID,
            createProtectionNotification(
                active = active
            )
        )
    }

    /**
     * Returns Binder interface.
     */
    override fun onBind(
        intent: Intent?
    ): IBinder {

        return binder
    }

    /**
     * Called when the service is destroyed.
     */
    override fun onDestroy() {

        Log.i(
            TAG,
            "FirewallService destroying."
        )

        /*
         * We intentionally stop protection here so the manager
         * does not continue believing the firewall is active after
         * the Android service has gone away.
         */
        if (
            serviceInitialized &&
            protectionRunning
        ) {

            serviceScope.launch {

                try {

                    firewallManager
                        .stopProtection()

                } catch (
                    exception: Exception
                ) {

                    Log.e(
                        TAG,
                        "Failed to stop firewall during destruction.",
                        exception
                    )
                }
            }
        }

        serviceScope.cancel()

        protectionRunning =
            false

        serviceInitialized =
            false

        super.onDestroy()

        Log.i(
            TAG,
            "FirewallService destroyed."
        )
    }

    /**
     * Service Binder.
     *
     * This is intended for components running in the same
     * application process.
     */
    inner class FirewallBinder :
        android.os.Binder() {

        /**
         * Returns the underlying service.
         */
        fun getService():
                FirewallService {

            return this@FirewallService
        }

        /**
         * Returns current firewall status.
         */
        fun getStatus():
                FirewallStatus? {

            return lastStatus
                ?: if (
                    serviceInitialized
                ) {

                    firewallManager
                        .getStatus()

                } else {
                    null
                }
        }

        /**
         * Returns whether firewall protection is active.
         */
        fun isProtectionActive():
                Boolean {

            return protectionRunning
        }

        /**
         * Evaluates a network request.
         */
        suspend fun evaluate(
            request: FirewallNetworkRequest
        ): FirewallEvaluationResult {

            return firewallManager
                .evaluate(
                    request
                )
        }

        /**
         * Returns firewall statistics.
         */
        fun getStatistics():
                FirewallStatistics? {

            return if (
                serviceInitialized
            ) {

                firewallManager
                    .getStatistics()

            } else {
                null
            }
        }
    }
}

/**
 * Utility class for interacting with FirewallService.
 *
 * Keeps service-start logic out of Activities/Fragments/ViewModels.
 */
object FirewallServiceController {

    /**
     * Starts the firewall service.
     */
    fun start(
        context: Context
    ) {

        val intent =
            FirewallService
                .createStartIntent(
                    context
                )

        if (
            android.os.Build.VERSION.SDK_INT >=
            android.os.Build.VERSION_CODES.O
        ) {

            context.startForegroundService(
                intent
            )

        } else {

            context.startService(
                intent
            )
        }
    }

    /**
     * Stops the firewall service.
     */
    fun stop(
        context: Context
    ) {

        context.startService(
            FirewallService
                .createStopIntent(
                    context
                )
        )
    }

    /**
     * Requests a status refresh.
     */
    fun refresh(
        context: Context
    ) {

        context.startService(
            FirewallService
                .createRefreshIntent(
                    context
                )
        )
    }

    /**
     * Requests evaluation of a network destination.
     */
    fun evaluate(
        context: Context,
        host: String,
        port: Int? = null,
        packageName: String? = null,
        protocol: FirewallProtocol =
            FirewallProtocol.ANY
    ) {

        val intent =
            Intent(
                context,
                FirewallService::class.java
            ).apply {

                action =
                    FirewallService
                        .ACTION_EVALUATE

                putExtra(
                    FirewallService
                        .EXTRA_HOST,
                    host
                )

                port?.let {
                    putExtra(
                        FirewallService
                            .EXTRA_PORT,
                        it
                    )
                }

                packageName?.let {
                    putExtra(
                        FirewallService
                            .EXTRA_PACKAGE_NAME,
                        it
                    )
                }

                putExtra(
                    FirewallService
                        .EXTRA_PROTOCOL,
                    protocol.name
                )
            }

        if (
            android.os.Build.VERSION.SDK_INT >=
            android.os.Build.VERSION_CODES.O
        ) {

            context.startForegroundService(
                intent
            )

        } else {

            context.startService(
                intent
            )
        }
    }
}
