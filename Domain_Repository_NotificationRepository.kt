package com.sentrix.domain.repositories

import com.sentrix.domain.models.Notification
import com.sentrix.domain.models.NotificationPriority
import com.sentrix.domain.models.NotificationStatus
import com.sentrix.domain.models.NotificationType

/**
 * NotificationRepository
 *
 * Repository responsible for
 * managing notifications within
 * the SentriX cybersecurity
 * platform.
 *
 * Used by:
 * - NotificationManager
 * - SecurityDashboard
 * - ThreatAnalysisEngine
 * - CyberDefenseManager
 * - AlertDeliveryService
 *
 * Responsibilities:
 * - Send notifications
 * - Store notification history
 * - Manage notification status
 * - Deliver security alerts
 * - Track notification events
 */
interface NotificationRepository {

    /**
     * Sends notification.
     *
     * @param notification Notification.
     *
     * @return Success status.
     */
    suspend fun sendNotification(
        notification: Notification
    ): Boolean

    /**
     * Retrieves all
     * notifications.
     *
     * @return Notification list.
     */
    suspend fun getNotifications():
        List<Notification>

    /**
     * Retrieves notification
     * by identifier.
     *
     * @param notificationId Notification ID.
     *
     * @return Notification.
     */
    suspend fun getNotificationById(
        notificationId: String
    ): Notification?

    /**
     * Saves notification.
     *
     * @param notification Notification.
     */
    suspend fun saveNotification(
        notification: Notification
    )

    /**
     * Updates notification.
     *
     * @param notification Notification.
     */
    suspend fun updateNotification(
        notification: Notification
    )

    /**
     * Deletes notification.
     *
     * @param notificationId Notification ID.
     */
    suspend fun deleteNotification(
        notificationId: String
    )

    /**
     * Retrieves unread
     * notifications.
     *
     * @return Notification list.
     */
    suspend fun getUnreadNotifications():
        List<Notification>

    /**
     * Retrieves notifications
     * by priority.
     *
     * @param priority Priority level.
     *
     * @return Notification list.
     */
    suspend fun getNotificationsByPriority(
        priority: NotificationPriority
    ): List<Notification>

    /**
     * Marks notification
     * as read.
     *
     * @param notificationId Notification ID.
     */
    suspend fun markAsRead(
        notificationId: String
    )

    /**
     * Retrieves total
     * notification count.
     *
     * @return Notification count.
     */
    suspend fun getNotificationCount():
        Int
}

/**
 * Notification
 *
 * Represents a system
 * notification.
 */
data class Notification(

    /**
     * Notification identifier.
     */
    val notificationId: String,

    /**
     * Notification title.
     */
    val title: String,

    /**
     * Notification message.
     */
    val message: String,

    /**
     * Notification type.
     */
    val type:
        NotificationType,

    /**
     * Notification priority.
     */
    val priority:
        NotificationPriority,

    /**
     * Notification status.
     */
    val status:
        NotificationStatus,

    /**
     * Creation timestamp.
     */
    val createdAt: Long
)

/**
 * Notification types.
 */
enum class NotificationType {

    /**
     * Security alert.
     */
    SECURITY_ALERT,

    /**
     * Threat detection.
     */
    THREAT_DETECTED,

    /**
     * Malware detection.
     */
    MALWARE_DETECTED,

    /**
     * Scan completed.
     */
    SCAN_COMPLETED,

    /**
     * Firewall event.
     */
    FIREWALL_EVENT,

    /**
     * VPN event.
     */
    VPN_EVENT,

    /**
     * System event.
     */
    SYSTEM_EVENT,

    /**
     * Recommendation.
     */
    RECOMMENDATION
}

/**
 * Notification priority.
 */
enum class NotificationPriority {

    /**
     * Low priority.
     */
    LOW,

    /**
     * Medium priority.
     */
    MEDIUM,

    /**
     * High priority.
     */
    HIGH,

    /**
     * Critical priority.
     */
    CRITICAL
}

/**
 * Notification status.
 */
enum class NotificationStatus {

    /**
     * Notification pending.
     */
    PENDING,

    /**
     * Notification delivered.
     */
    DELIVERED,

    /**
     * Notification read.
     */
    READ,

    /**
     * Notification failed.
     */
    FAILED
}
