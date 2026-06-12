package com.sentrix.data.local.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * ThreatEntity
 *
 * Represents a detected threat
 * within the SentriX platform.
 *
 * Responsibilities:
 * - Store threat information
 * - Track threat severity
 * - Monitor remediation status
 * - Support threat analytics
 * - Enable incident investigations
 */
@Entity(
    tableName = "threats"
)
data class ThreatEntity(

    /**
     * Unique threat identifier.
     */
    @PrimaryKey
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
     * Affected file path.
     */
    val affectedFile: String?,

    /**
     * Malware family name.
     */
    val malwareFamily: String?,

    /**
     * Detection engine.
     */
    val detectionEngine: String,

    /**
     * Indicates whether
     * the threat is active.
     */
    val isActive: Boolean,

    /**
     * Indicates whether
     * the threat has been resolved.
     */
    val isResolved: Boolean,

    /**
     * Recommended action.
     */
    val recommendedAction: String,

    /**
     * Threat detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Threat resolution timestamp.
     */
    val resolvedAt: Long?,

    /**
     * Last updated timestamp.
     */
    val updatedAt: Long?
)
