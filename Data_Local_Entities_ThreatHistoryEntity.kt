package com.sentrix.data.local.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * ThreatHistoryEntity
 *
 * Represents a historical record
 * of a detected threat within
 * the SentriX platform.
 *
 * Responsibilities:
 * - Store historical threats
 * - Track threat lifecycle
 * - Support threat analytics
 * - Enable incident investigations
 * - Generate security reports
 */
@Entity(
    tableName = "threat_history"
)
data class ThreatHistoryEntity(

    /**
     * Unique history record id.
     */
    @PrimaryKey
    val historyId: String,

    /**
     * Associated threat id.
     */
    val threatId: String,

    /**
     * Threat name.
     */
    val threatName: String,

    /**
     * Threat category.
     */
    val threatCategory: String,

    /**
     * Threat severity level.
     */
    val threatLevel: String,

    /**
     * Threat source.
     */
    val threatSource: String,

    /**
     * Risk score.
     */
    val riskScore: Int,

    /**
     * Threat description.
     */
    val description: String,

    /**
     * Affected resource.
     */
    val affectedResource: String?,

    /**
     * Detection engine.
     */
    val detectionEngine: String,

    /**
     * Threat status.
     */
    val threatStatus: String,

    /**
     * Resolution action taken.
     */
    val resolutionAction: String?,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Resolution timestamp.
     */
    val resolvedAt: Long?,

    /**
     * Investigation timestamp.
     */
    val investigatedAt: Long?,

    /**
     * Indicates whether
     * the threat was resolved.
     */
    val isResolved: Boolean,

    /**
     * Indicates whether
     * the threat was quarantined.
     */
    val isQuarantined: Boolean,

    /**
     * Indicates whether
     * the threat was removed.
     */
    val isRemoved: Boolean,

    /**
     * Analyst notes.
     */
    val notes: String?,

    /**
     * Record creation timestamp.
     */
    val createdAt: Long,

    /**
     * Last update timestamp.
     */
    val updatedAt: Long?
)
