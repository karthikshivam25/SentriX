package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.SecurityReportEntity

import kotlinx.coroutines.flow.Flow

/**
 * SecurityReportDao
 *
 * Data Access Object responsible
 * for managing security reports
 * within the SentriX platform.
 *
 * Responsibilities:
 * - Store security reports
 * - Retrieve report history
 * - Manage generated reports
 * - Support compliance reporting
 * - Enable security analytics
 */
@Dao
interface SecurityReportDao {

    /**
     * Inserts security report.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertSecurityReport(
        report: SecurityReportEntity
    )

    /**
     * Inserts multiple reports.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertSecurityReports(
        reports: List<SecurityReportEntity>
    )

    /**
     * Updates report.
     */
    @Update
    suspend fun updateSecurityReport(
        report: SecurityReportEntity
    )

    /**
     * Deletes report.
     */
    @Delete
    suspend fun deleteSecurityReport(
        report: SecurityReportEntity
    )

    /**
     * Retrieves all reports.
     */
    @Query(
        """
        SELECT *
        FROM security_reports
        ORDER BY generatedAt DESC
        """
    )
    fun getAllSecurityReports():
        Flow<List<SecurityReportEntity>>

    /**
     * Retrieves report by id.
     */
    @Query(
        """
        SELECT *
        FROM security_reports
        WHERE reportId = :reportId
        LIMIT 1
        """
    )
    suspend fun getSecurityReportById(
        reportId: String
    ): SecurityReportEntity?

    /**
     * Retrieves latest report.
     */
    @Query(
        """
        SELECT *
        FROM security_reports
        ORDER BY generatedAt DESC
        LIMIT 1
        """
    )
    suspend fun getLatestSecurityReport():
        SecurityReportEntity?

    /**
     * Retrieves reports by type.
     */
    @Query(
        """
        SELECT *
        FROM security_reports
        WHERE reportType = :reportType
        ORDER BY generatedAt DESC
        """
    )
    fun getReportsByType(
        reportType: String
    ): Flow<List<SecurityReportEntity>>

    /**
     * Retrieves recent reports.
     */
    @Query(
        """
        SELECT *
        FROM security_reports
        ORDER BY generatedAt DESC
        LIMIT :limit
        """
    )
    suspend fun getRecentReports(
        limit: Int = 10
    ): List<SecurityReportEntity>

    /**
     * Counts total reports.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM security_reports
        """
    )
    suspend fun getReportCount():
        Int

    /**
     * Retrieves reports generated
     * within a date range.
     */
    @Query(
        """
        SELECT *
        FROM security_reports
        WHERE generatedAt
        BETWEEN :startDate
        AND :endDate
        ORDER BY generatedAt DESC
        """
    )
    suspend fun getReportsBetweenDates(
        startDate: Long,
        endDate: Long
    ): List<SecurityReportEntity>

    /**
     * Deletes all reports.
     */
    @Query(
        """
        DELETE FROM security_reports
        """
    )
    suspend fun clearSecurityReports()
}
