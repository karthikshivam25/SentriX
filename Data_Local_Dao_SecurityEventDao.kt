package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.SecurityEventEntity

import kotlinx.coroutines.flow.Flow

/**
 * SecurityEventDao
 *
 * Data Access Object responsible
 * for managing security events
 * within the SentriX platform.
 *
 * Responsibilities:
 * - Store security events
 * - Retrieve event history
 * - Track security incidents
 * - Support threat investigations
 * - Provide security analytics
 */
@Dao
interface SecurityEventDao {

    /**
     * Inserts security event.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertSecurityEvent(
        event: SecurityEventEntity
    )

    /**
     * Inserts multiple events.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertSecurityEvents(
        events: List<SecurityEventEntity>
    )

    /**
     * Updates event.
     */
    @Update
    suspend fun updateSecurityEvent(
        event: SecurityEventEntity
    )

    /**
     * Deletes event.
     */
    @Delete
    suspend fun deleteSecurityEvent(
        event: SecurityEventEntity
    )

    /**
     * Retrieves all events.
     */
    @Query(
        """
        SELECT *
        FROM security_events
        ORDER BY eventTimestamp DESC
        """
    )
    fun getAllSecurityEvents():
        Flow<List<SecurityEventEntity>>

    /**
     * Retrieves event by id.
     */
    @Query(
        """
        SELECT *
        FROM security_events
        WHERE eventId = :eventId
        LIMIT 1
        """
    )
    suspend fun getSecurityEventById(
        eventId: String
    ): SecurityEventEntity?

    /**
     * Retrieves latest events.
     */
    @Query(
        """
        SELECT *
        FROM security_events
        ORDER BY eventTimestamp DESC
        LIMIT :limit
        """
    )
    suspend fun getRecentSecurityEvents(
        limit: Int = 20
    ): List<SecurityEventEntity>

    /**
     * Retrieves events by type.
     */
    @Query(
        """
        SELECT *
        FROM security_events
        WHERE eventType = :eventType
        ORDER BY eventTimestamp DESC
        """
    )
    fun getEventsByType(
        eventType: String
    ): Flow<List<SecurityEventEntity>>

    /**
     * Retrieves events by severity.
     */
    @Query(
        """
        SELECT *
        FROM security_events
        WHERE severity = :severity
        ORDER BY eventTimestamp DESC
        """
    )
    fun getEventsBySeverity(
        severity: String
    ): Flow<List<SecurityEventEntity>>

    /**
     * Counts all events.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM security_events
        """
    )
    suspend fun getSecurityEventCount():
        Int

    /**
     * Counts critical events.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM security_events
        WHERE severity = 'CRITICAL'
        """
    )
    suspend fun getCriticalEventCount():
        Int

    /**
     * Deletes all events.
     */
    @Query(
        """
        DELETE FROM security_events
        """
    )
    suspend fun clearSecurityEvents()
}
