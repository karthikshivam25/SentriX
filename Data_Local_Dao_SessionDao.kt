package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.SessionEntity

import kotlinx.coroutines.flow.Flow

/**
 * SessionDao
 *
 * Data Access Object responsible
 * for managing user sessions
 * within the SentriX platform.
 *
 * Responsibilities:
 * - Store user sessions
 * - Track active sessions
 * - Manage login history
 * - Support authentication
 * - Monitor session security
 */
@Dao
interface SessionDao {

    /**
     * Inserts session.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertSession(
        session: SessionEntity
    )

    /**
     * Inserts multiple sessions.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertSessions(
        sessions: List<SessionEntity>
    )

    /**
     * Updates session.
     */
    @Update
    suspend fun updateSession(
        session: SessionEntity
    )

    /**
     * Deletes session.
     */
    @Delete
    suspend fun deleteSession(
        session: SessionEntity
    )

    /**
     * Retrieves all sessions.
     */
    @Query(
        """
        SELECT *
        FROM sessions
        ORDER BY loginTimestamp DESC
        """
    )
    fun getAllSessions():
        Flow<List<SessionEntity>>

    /**
     * Retrieves session by id.
     */
    @Query(
        """
        SELECT *
        FROM sessions
        WHERE sessionId = :sessionId
        LIMIT 1
        """
    )
    suspend fun getSessionById(
        sessionId: String
    ): SessionEntity?

    /**
     * Retrieves active session.
     */
    @Query(
        """
        SELECT *
        FROM sessions
        WHERE isActive = 1
        LIMIT 1
        """
    )
    suspend fun getActiveSession():
        SessionEntity?

    /**
     * Retrieves active sessions.
     */
    @Query(
        """
        SELECT *
        FROM sessions
        WHERE isActive = 1
        ORDER BY loginTimestamp DESC
        """
    )
    fun getActiveSessions():
        Flow<List<SessionEntity>>

    /**
     * Retrieves sessions for user.
     */
    @Query(
        """
        SELECT *
        FROM sessions
        WHERE userId = :userId
        ORDER BY loginTimestamp DESC
        """
    )
    fun getSessionsByUser(
        userId: String
    ): Flow<List<SessionEntity>>

    /**
     * Counts all sessions.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM sessions
        """
    )
    suspend fun getSessionCount():
        Int

    /**
     * Counts active sessions.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM sessions
        WHERE isActive = 1
        """
    )
    suspend fun getActiveSessionCount():
        Int

    /**
     * Marks session inactive.
     */
    @Query(
        """
        UPDATE sessions
        SET isActive = 0,
            logoutTimestamp = :logoutTimestamp
        WHERE sessionId = :sessionId
        """
    )
    suspend fun endSession(
        sessionId: String,
        logoutTimestamp: Long
    )

    /**
     * Ends all sessions.
     */
    @Query(
        """
        UPDATE sessions
        SET isActive = 0
        """
    )
    suspend fun endAllSessions()

    /**
     * Deletes all sessions.
     */
    @Query(
        """
        DELETE FROM sessions
        """
    )
    suspend fun clearSessions()
}
