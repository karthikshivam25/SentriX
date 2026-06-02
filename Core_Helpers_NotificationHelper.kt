package com.sentrix.core.helpers

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.sentrix.R

object NotificationHelper {

    // Channel IDs
    const val SECURITY_CHANNEL_ID = "sentrix_security_channel"
    const val SCAN_CHANNEL_ID = "sentrix_scan_channel"
    const val VPN_CHANNEL_ID = "sentrix_vpn_channel"

    // Notification IDs
    const val SECURITY_NOTIFICATION_ID = 1001
    const val SCAN_NOTIFICATION_ID = 1002
    const val VPN_NOTIFICATION_ID = 1003

    /**
     * Create notification channels
     */
    fun createNotificationChannels(context: Context) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            val securityChannel = NotificationChannel(
                SECURITY_CHANNEL_ID,
                "Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Security threat and malware alerts"
                enableVibration(true)
                enableLights(true)
            }

            val scanChannel = NotificationChannel(
                SCAN_CHANNEL_ID,
                "Scan Status",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Background scan progress and updates"
            }

            val vpnChannel = NotificationChannel(
                VPN_CHANNEL_ID,
                "VPN Protection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN connection and protection status"
            }

            val manager =
                context.getSystemService(NotificationManager::class.java)

            manager.createNotificationChannel(securityChannel)
            manager.createNotificationChannel(scanChannel)
            manager.createNotificationChannel(vpnChannel)
        }
    }

    /**
     * Show security alert notification
     */
    fun showSecurityAlert(
        context: Context,
        title: String,
        message: String,
        pendingIntent: PendingIntent? = null
    ) {

        val notification = NotificationCompat.Builder(
            context,
            SECURITY_CHANNEL_ID
        )
            .setSmallIcon(R.drawable.ic_security_alert)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .apply {
                pendingIntent?.let {
                    setContentIntent(it)
                }
            }
            .build()

        NotificationManagerCompat.from(context)
            .notify(
                SECURITY_NOTIFICATION_ID,
                notification
            )
    }

    /**
     * Show scan progress notification
     */
    fun showScanProgress(
        context: Context,
        progress: Int,
        maxProgress: Int = 100
    ) {

        val notification = NotificationCompat.Builder(
            context,
            SCAN_CHANNEL_ID
        )
            .setSmallIcon(R.drawable.ic_scan)
            .setContentTitle("Scanning Device")
            .setContentText("Security scan in progress...")
            .setProgress(maxProgress, progress, false)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .build()

        NotificationManagerCompat.from(context)
            .notify(
                SCAN_NOTIFICATION_ID,
                notification
            )
    }

    /**
     * Complete scan notification
     */
    fun showScanCompleted(
        context: Context,
        threatsFound: Int
    ) {

        val message = if (threatsFound > 0) {
            "$threatsFound threats detected during scan."
        } else {
            "No threats detected. Device is secure."
        }

        val notification = NotificationCompat.Builder(
            context,
            SCAN_CHANNEL_ID
        )
            .setSmallIcon(R.drawable.ic_scan_complete)
            .setContentTitle("Scan Completed")
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(context)
            .notify(
                SCAN_NOTIFICATION_ID,
                notification
            )
    }

    /**
     * Show VPN protection notification
     */
    fun showVpnStatus(
        context: Context,
        isConnected: Boolean
    ) {

        val title = if (isConnected) {
            "VPN Protection Active"
        } else {
            "VPN Disconnected"
        }

        val message = if (isConnected) {
            "Your network traffic is secured."
        } else {
            "Your connection is currently unprotected."
        }

        val notification = NotificationCompat.Builder(
            context,
            VPN_CHANNEL_ID
        )
            .setSmallIcon(
                if (isConnected) {
                    R.drawable.ic_vpn_connected
                } else {
                    R.drawable.ic_vpn_disconnected
                }
            )
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(isConnected)
            .build()

        NotificationManagerCompat.from(context)
            .notify(
                VPN_NOTIFICATION_ID,
                notification
            )
    }

    /**
     * Show generic notification
     */
    fun showNotification(
        context: Context,
        channelId: String,
        notificationId: Int,
        title: String,
        message: String,
        smallIcon: Int,
        pendingIntent: PendingIntent? = null
    ) {

        val builder = NotificationCompat.Builder(
            context,
            channelId
        )
            .setSmallIcon(smallIcon)
            .setContentTitle(title)
            .setContentText(message)
            .setAutoCancel(true)

        pendingIntent?.let {
            builder.setContentIntent(it)
        }

        NotificationManagerCompat.from(context)
            .notify(notificationId, builder.build())
    }

    /**
     * Cancel notification
     */
    fun cancelNotification(
        context: Context,
        notificationId: Int
    ) {

        NotificationManagerCompat.from(context)
            .cancel(notificationId)
    }

    /**
     * Cancel all notifications
     */
    fun cancelAllNotifications(context: Context) {

        NotificationManagerCompat.from(context)
            .cancelAll()
    }

    /**
     * Build foreground service notification
     */
    fun buildForegroundNotification(
        context: Context,
        title: String,
        message: String,
        icon: Int
    ): Notification {

        return NotificationCompat.Builder(
            context,
            SCAN_CHANNEL_ID
        )
            .setSmallIcon(icon)
            .setContentTitle(title)
            .setContentText(message)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
