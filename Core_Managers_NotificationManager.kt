package com.sentrix.core.managers

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager as AndroidNotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.sentrix.core.enums.AlertPriority

/**
 * NotificationManager
 *
 * Responsibilities:
 * - Create notification channels
 * - Send security alerts
 * - Send threat notifications
 * - Manage notification priorities
 * - Clear notifications
 * - Support SentriX real-time protection events
 */
class NotificationManager(
    private val context: Context
) {

    init {
        createNotificationChannels()
    }

    /**
     * Create all SentriX notification channels.
     */
    private fun createNotificationChannels() {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val securityChannel = NotificationChannel(
            CHANNEL_SECURITY,
            "Security Alerts",
            AndroidNotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Critical security notifications and alerts."
        }

        val scanChannel = NotificationChannel(
            CHANNEL_SCAN,
            "Scan Results",
            AndroidNotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Scan progress and result notifications."
        }

        val systemChannel = NotificationChannel(
            CHANNEL_SYSTEM,
            "System Events",
            AndroidNotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "General SentriX system notifications."
        }

        val manager =
            context.getSystemService(
                Context.NOTIFICATION_SERVICE
            ) as AndroidNotificationManager

        manager.createNotificationChannel(securityChannel)
        manager.createNotificationChannel(scanChannel)
        manager.createNotificationChannel(systemChannel)
    }

    /**
     * Send a security alert notification.
     */
    fun sendSecurityAlert(
        title: String,
        message: String,
        priority: AlertPriority = AlertPriority.HIGH,
        pendingIntent: PendingIntent? = null
    ) {

        if (!canPostNotifications()) {
            return
        }

        val notification = NotificationCompat.Builder(
            context,
            CHANNEL_SECURITY
        )
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(message)
            )
            .setAutoCancel(true)
            .setPriority(
                mapPriority(priority)
            )
            .apply {
                pendingIntent?.let {
                    setContentIntent(it)
                }
            }
            .build()

        NotificationManagerCompat.from(context)
            .notify(
                System.currentTimeMillis().toInt(),
                notification
            )
    }

    /**
     * Send scan notification.
     */
    fun sendScanNotification(
        title: String,
        message: String
    ) {

        if (!canPostNotifications()) {
            return
        }

        val notification = NotificationCompat.Builder(
            context,
            CHANNEL_SCAN
        )
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentTitle(title)
            .setContentText(message)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(context)
            .notify(
                System.currentTimeMillis().toInt(),
                notification
            )
    }

    /**
     * Send general system notification.
     */
    fun sendSystemNotification(
        title: String,
        message: String
    ) {

        if (!canPostNotifications()) {
            return
        }

        val notification = NotificationCompat.Builder(
            context,
            CHANNEL_SYSTEM
        )
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(message)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(context)
            .notify(
                System.currentTimeMillis().toInt(),
                notification
            )
    }

    /**
     * Cancel specific notification.
     */
    fun cancelNotification(
        notificationId: Int
    ) {
        NotificationManagerCompat
            .from(context)
            .cancel(notificationId)
    }

    /**
     * Clear all SentriX notifications.
     */
    fun clearAllNotifications() {
        NotificationManagerCompat
            .from(context)
            .cancelAll()
    }

    /**
     * Create launch PendingIntent.
     */
    fun createLaunchIntent(
        activityClass: Class<*>
    ): PendingIntent {

        val intent = Intent(
            context,
            activityClass
        )

        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or
                    PendingIntent.FLAG_IMMUTABLE
        )
    }

    /**
     * Map SentriX priority to Android priority.
     */
    private fun mapPriority(
        priority: AlertPriority
    ): Int {

        return when (priority) {

            AlertPriority.LOW ->
                NotificationCompat.PRIORITY_LOW

            AlertPriority.MEDIUM ->
                NotificationCompat.PRIORITY_DEFAULT

            AlertPriority.HIGH ->
                NotificationCompat.PRIORITY_HIGH

            AlertPriority.CRITICAL ->
                NotificationCompat.PRIORITY_MAX
        }
    }

    /**
     * Notification permission check.
     */
    private fun canPostNotifications(): Boolean {

        return if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        ) {

            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED

        } else {
            true
        }
    }

    companion object {

        const val CHANNEL_SECURITY =
            "sentrix_security_channel"

        const val CHANNEL_SCAN =
            "sentrix_scan_channel"

        const val CHANNEL_SYSTEM =
            "sentrix_system_channel"
    }
}
