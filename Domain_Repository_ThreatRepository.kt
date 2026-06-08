package com.sentrix.domain.repositories

import com.sentrix.domain.models.ThreatIndicator
import com.sentrix.domain.models.ThreatLevel

/**
 * ThreatRepository
 *
 * Repository responsible for
 * managing threat information
 * within the SentriX platform.
 *
 * Used by:
 * - ThreatAnalysisEngine
 * - ThreatDetectionService
 * - SecurityDashboard
 * - CyberDefenseManager
 * - ThreatHistoryManager
 *
 * Responsibilities:
 * - Retrieve threats
 * - Store threats
 * - Update threat status
 * - Remove threats
 * - Provide threat analytics
 */
interface ThreatRepository {

    /**
     * Retrieves all threats.
     *
     * @return List of threats.
     */
    suspend fun getThreats():
        List<ThreatRecord>

    /**
     * Retrieves threat
     * by identifier.
     *
     * @param threatId Threat ID.
     *
     * @return Threat record.
     */
    suspend fun getThreatById(
        threatId: String
    ): ThreatRecord?

    /**
     * Saves a threat.
     *
     * @param threat Threat record.
     */
    suspend fun saveThreat(
        threat: ThreatRecord
    )

    /**
     * Updates a threat.
     *
     * @param threat Threat record.
     */
    suspend fun updateThreat(
        threat: ThreatRecord
    )

    /**
     * Deletes a threat.
     *
     * @param threatId Threat ID.
     */
    suspend fun deleteThreat(
        threatId: String
    )

    /**
     * Retrieves active threats.
     *
     * @return Active threats.
     */
    suspend fun getActiveThreats():
        List<ThreatRecord>

    /**
     * Retrieves threats
     * by severity level.
     *
     * @param threatLevel Severity.
     *
     * @return Threat list.
     */
    suspend fun getThreatsByLevel(
        threatLevel: ThreatLevel
    ): List<ThreatRecord>

    /**
     * Retrieves threat count.
     *
     * @return Total threats.
     */
    suspend fun getThreatCount():
        Int
}

/**
 * ThreatRecord
 *
 * Represents a detected
 * cybersecurity threat.
 */
data class ThreatRecord(

    /**
     * Threat identifier.
     */
    val threatId: String,

    /**
     * Threat name.
     */
    val threatName: String,

    /**
     * Threat description.
     */
    val description: String,

    /**
     * Threat category.
     */
    val category:
        ThreatCategory,

    /**
     * Threat severity.
     */
    val threatLevel:
        ThreatLevel,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Resolution status.
     */
    val isResolved: Boolean
)

/**
 * Threat categories.
 */
enum class ThreatCategory {

    /**
     * Malware threat.
     */
    MALWARE,

    /**
     * Phishing attack.
     */
    PHISHING,

    /**
     * Network intrusion.
     */
    INTRUSION,

    /**
     * Scam activity.
     */
    SCAM,

    /**
     * Spyware threat.
     */
    SPYWARE,

    /**
     * Ransomware attack.
     */
    RANSOMWARE,

    /**
     * Data exposure.
     */
    DATA_EXPOSURE,

    /**
     * Suspicious activity.
     */
    SUSPICIOUS_ACTIVITY
}
