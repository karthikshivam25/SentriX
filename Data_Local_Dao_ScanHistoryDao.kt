package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.ScanHistoryEntity

import kotlinx.coroutines.flow.Flow

/**
 * ScanHistoryDao
 *
 * Data Access Object responsible
 * for managing scan history
 * information within SentriX.
 *
 * Responsibilities:
 * - Store scan results
 * - Retrieve scan history
 * - Track scan statistics
 * - Manage scan records
 * - Support security analytics
 */
@Dao
interface ScanHistoryDao {

    /**
     * Inserts scan record.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertScanHistory(
        scanHistory: ScanHistoryEntity
    )

    /**
     * Inserts multiple scan records.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertScanHistories(
        scanHistories:
            List<ScanHistoryEntity>
    )

    /**
     * Updates scan record.
     */
    @Update
    suspend fun updateScanHistory(
        scanHistory: ScanHistoryEntity
    )

    /**
     * Deletes scan record.
     */
    @Delete
    suspend fun deleteScanHistory(
        scanHistory: ScanHistoryEntity
    )

    /**
     * Retrieves all scan history.
     */
    @Query(
        """
        SELECT *
        FROM scan_history
        ORDER BY scanStartedAt DESC
        """
    )
    fun getAllScanHistory():
        Flow<List<ScanHistoryEntity>>

    /**
     * Retrieves scan by id.
     */
    @Query(
        """
        SELECT *
        FROM scan_history
        WHERE scanId = :scanId
        LIMIT 1
        """
    )
    suspend fun getScanById(
        scanId: String
    ): ScanHistoryEntity?

    /**
     * Retrieves latest scan.
     */
    @Query(
        """
        SELECT *
        FROM scan_history
        ORDER BY scanStartedAt DESC
        LIMIT 1
        """
    )
    suspend fun getLatestScan():
        ScanHistoryEntity?

    /**
     * Retrieves recent scans.
     */
    @Query(
        """
        SELECT *
        FROM scan_history
        ORDER BY scanStartedAt DESC
        LIMIT :limit
        """
    )
    suspend fun getRecentScans(
        limit: Int = 10
    ): List<ScanHistoryEntity>

    /**
     * Retrieves scans by type.
     */
    @Query(
        """
        SELECT *
        FROM scan_history
        WHERE scanType = :scanType
        ORDER BY scanStartedAt DESC
        """
    )
    fun getScansByType(
        scanType: String
    ): Flow<List<ScanHistoryEntity>>

    /**
     * Counts total scans.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM scan_history
        """
    )
    suspend fun getScanCount():
        Int

    /**
     * Counts completed scans.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM scan_history
        WHERE scanStatus = 'COMPLETED'
        """
    )
    suspend fun getCompletedScanCount():
        Int

    /**
     * Calculates total threats found.
     */
    @Query(
        """
        SELECT SUM(threatsDetected)
        FROM scan_history
        """
    )
    suspend fun getTotalThreatsDetected():
        Int?

    /**
     * Deletes all scan history.
     */
    @Query(
        """
        DELETE FROM scan_history
        """
    )
    suspend fun clearScanHistory()
}
