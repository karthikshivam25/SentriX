package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.PrivacyAuditEntity

import kotlinx.coroutines.flow.Flow

/**
 * PrivacyAuditDao
 *
 * Data Access Object responsible
 * for managing privacy audit
 * records within SentriX.
 *
 * Responsibilities:
 * - Store privacy audits
 * - Retrieve audit history
 * - Monitor privacy risks
 * - Track data exposure events
 * - Support compliance reporting
 * - Generate privacy analytics
 */
@Dao
interface PrivacyAuditDao {

    /**
     * Inserts privacy audit.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertPrivacyAudit(
        audit: PrivacyAuditEntity
    )

    /**
     * Inserts multiple audits.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertPrivacyAudits(
        audits: List<PrivacyAuditEntity>
    )

    /**
     * Updates audit.
     */
    @Update
    suspend fun updatePrivacyAudit(
        audit: PrivacyAuditEntity
    )

    /**
     * Deletes audit.
     */
    @Delete
    suspend fun deletePrivacyAudit(
        audit: PrivacyAuditEntity
    )

    /**
     * Retrieves all audits.
     */
    @Query(
        """
        SELECT *
        FROM privacy_audits
        ORDER BY auditTimestamp DESC
        """
    )
    fun getAllPrivacyAudits():
        Flow<List<PrivacyAuditEntity>>

    /**
     * Retrieves audit by id.
     */
    @Query(
        """
        SELECT *
        FROM privacy_audits
        WHERE auditId = :auditId
        LIMIT 1
        """
    )
    suspend fun getPrivacyAuditById(
        auditId: String
    ): PrivacyAuditEntity?

    /**
     * Retrieves latest audit.
     */
    @Query(
        """
        SELECT *
        FROM privacy_audits
        ORDER BY auditTimestamp DESC
        LIMIT 1
        """
    )
    suspend fun getLatestPrivacyAudit():
        PrivacyAuditEntity?

    /**
     * Retrieves audits by risk level.
     */
    @Query(
        """
        SELECT *
        FROM privacy_audits
        WHERE riskLevel = :riskLevel
        ORDER BY auditTimestamp DESC
        """
    )
    fun getAuditsByRiskLevel(
        riskLevel: String
    ): Flow<List<PrivacyAuditEntity>>

    /**
     * Retrieves unresolved audits.
     */
    @Query(
        """
        SELECT *
        FROM privacy_audits
        WHERE isResolved = 0
        ORDER BY auditTimestamp DESC
        """
    )
    fun getUnresolvedAudits():
        Flow<List<PrivacyAuditEntity>>

    /**
     * Counts total audits.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM privacy_audits
        """
    )
    suspend fun getAuditCount():
        Int

    /**
     * Counts high-risk audits.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM privacy_audits
        WHERE riskLevel = 'HIGH'
        OR riskLevel = 'CRITICAL'
        """
    )
    suspend fun getHighRiskAuditCount():
        Int

    /**
     * Calculates average
     * privacy score.
     */
    @Query(
        """
        SELECT AVG(privacyScore)
        FROM privacy_audits
        """
    )
    suspend fun getAveragePrivacyScore():
        Double?

    /**
     * Deletes all audits.
     */
    @Query(
        """
        DELETE FROM privacy_audits
        """
    )
    suspend fun clearPrivacyAudits()
}
