package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.NotificationEntity

import kotlinx.coroutines.flow.Flow

/**
 * NotificationDao
 *
 * Data Access Object responsible
 * for managing notifications
 * within the SentriX platform.
 *
 * Responsibilities:
 * - Store notifications
 * - Retrieve notification history
 * - Track unread notifications
 * - Manage alert visibility
 * - Support notification analytics
 */
@Dao
interface NotificationDao {

    /**
     * Inserts notification.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertNotification(
        notification: NotificationEntity
    )

    /**
     * Inserts multiple notifications.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertNotifications(
        notifications:
            List<NotificationEntity>
    )

    /**
     * Updates notification.
     */
    @Update
    suspend fun updateNotification(
        notification: NotificationEntity
    )

    /**
     * Deletes notification.
     */
    @Delete
    suspend fun deleteNotification(
        notification: NotificationEntity
    )

    /**
     * Retrieves all notifications.
     */
    @Query(
        """
        SELECT *
        FROM notifications
        ORDER BY createdAt DESC
        """
    )
    fun getAllNotifications():
        Flow<List<NotificationEntity>>

    /**
     * Retrieves notification by id.
     */
    @Query(
        """
        SELECT *
        FROM notifications
        WHERE notificationId = :notificationId
        LIMIT 1
        """
    )
    suspend fun getNotificationById(
        notificationId: String
    ): NotificationEntity?

    /**
     * Retrieves unread notifications.
     */
    @Query(
        """
        SELECT *
        FROM notifications
        WHERE isRead = 0
        ORDER BY createdAt DESC
        """
    )
    fun getUnreadNotifications():
        Flow<List<NotificationEntity>>

    /**
     * Retrieves notifications by type.
     */
    @Query(
        """
        SELECT *
        FROM notifications
        WHERE notificationType = :type
        ORDER BY createdAt DESC
        """
    )
    fun getNotificationsByType(
        type: String
    ): Flow<List<NotificationEntity>>

    /**
     * Counts all notifications.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM notifications
        """
    )
    suspend fun getNotificationCount():
        Int

    /**
     * Counts unread notifications.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM notifications
        WHERE isRead = 0
        """
    )
    suspend fun getUnreadNotificationCount():
        Int

    /**
     * Marks notification as read.
     */
    @Query(
        """
        UPDATE notifications
        SET isRead = 1
        WHERE notificationId = :notificationId
        """
    )
    suspend fun markAsRead(
        notificationId: String
    )

    /**
     * Marks all notifications as read.
     */
    @Query(
        """
        UPDATE notifications
        SET isRead = 1
        """
    )
    suspend fun markAllAsRead()

    /**
     * Deletes all notifications.
     */
    @Query(
        """
        DELETE FROM notifications
        """
    )
    suspend fun clearNotifications()
}
