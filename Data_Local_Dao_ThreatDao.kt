package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.ThreatEntity

import kotlinx.coroutines.flow.Flow

/**
 * ThreatDao
 *
 * Data Access Object responsible
 * for managing threat records
 * within the SentriX database.
 *
 * Responsibilities:
 * - Insert threats
 * - Update threats
 * - Delete threats
 * - Retrieve threat history
 * - Retrieve active threats
 * - Count threats by severity
 */
@Dao
interface ThreatDao {

    /**
     * Inserts a threat.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertThreat(
        threat: ThreatEntity
    )

    /**
     * Inserts multiple threats.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertThreats(
        threats: List<ThreatEntity>
    )

    /**
     * Updates threat information.
     */
    @Update
    suspend fun updateThreat(
        threat: ThreatEntity
    )

    /**
     * Deletes a threat.
     */
    @Delete
    suspend fun deleteThreat(
        threat: ThreatEntity
    )

    /**
     * Retrieves all threats.
     */
    @Query(
        """
        SELECT *
        FROM threats
        ORDER BY detectedAt DESC
        """
    )
    fun getAllThreats():
        Flow<List<ThreatEntity>>

    /**
     * Retrieves threat by id.
     */
    @Query(
        """
        SELECT *
        FROM threats
        WHERE threatId = :threatId
        LIMIT 1
        """
    )
    suspend fun getThreatById(
        threatId: String
    ): ThreatEntity?

    /**
     * Retrieves active threats.
     */
    @Query(
        """
        SELECT *
        FROM threats
        WHERE isResolved = 0
        ORDER BY detectedAt DESC
        """
    )
    fun getActiveThreats():
        Flow<List<ThreatEntity>>

    /**
     * Retrieves resolved threats.
     */
    @Query(
        """
        SELECT *
        FROM threats
        WHERE isResolved = 1
        ORDER BY detectedAt DESC
        """
    )
    fun getResolvedThreats():
        Flow<List<ThreatEntity>>

    /**
     * Counts all threats.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM threats
        """
    )
    suspend fun getThreatCount():
        Int

    /**
     * Counts active threats.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM threats
        WHERE isResolved = 0
        """
    )
    suspend fun getActiveThreatCount():
        Int

    /**
     * Counts critical threats.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM threats
        WHERE threatLevel = 'CRITICAL'
        """
    )
    suspend fun getCriticalThreatCount():
        Int

    /**
     * Deletes all threats.
     */
    @Query(
        """
        DELETE FROM threats
        """
    )
    suspend fun clearThreats()

    /**
     * Retrieves latest threats.
     */
    @Query(
        """
        SELECT *
        FROM threats
        ORDER BY detectedAt DESC
        LIMIT :limit
        """
    )
    suspend fun getRecentThreats(
        limit: Int = 10
    ): List<ThreatEntity>
}
