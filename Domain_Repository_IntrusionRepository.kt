package com.sentrix.domain.repositories

import com.sentrix.domain.models.IntrusionEvent
import com.sentrix.domain.models.IntrusionSeverity
import com.sentrix.domain.models.IntrusionType

/**
 * IntrusionRepository
 *
 * Repository responsible for
 * managing intrusion detection
 * and intrusion events within
 * the SentriX cybersecurity
 * platform.
 *
 * Used by:
 * - IntrusionDetectionEngine
 * - ThreatAnalysisEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 * - IncidentResponseManager
 *
 * Responsibilities:
 * - Store intrusion events
 * - Retrieve intrusion records
 * - Analyze intrusion attempts
 * - Track attack patterns
 * - Support incident response
 */
interface IntrusionRepository {

    /**
     * Retrieves all
     * intrusion events.
     *
     * @return Intrusion list.
     */
    suspend fun getIntrusions():
        List<IntrusionEvent>

    /**
     * Retrieves intrusion
     * by identifier.
     *
     * @param intrusionId Intrusion ID.
     *
     * @return Intrusion event.
     */
    suspend fun getIntrusionById(
        intrusionId: String
    ): IntrusionEvent?

    /**
     * Saves intrusion event.
     *
     * @param intrusion Intrusion event.
     */
    suspend fun saveIntrusion(
        intrusion: IntrusionEvent
    )

    /**
     * Updates intrusion event.
     *
     * @param intrusion Intrusion event.
     */
    suspend fun updateIntrusion(
        intrusion: IntrusionEvent
    )

    /**
     * Deletes intrusion event.
     *
     * @param intrusionId Intrusion ID.
     */
    suspend fun deleteIntrusion(
        intrusionId: String
    )

    /**
     * Retrieves active
     * intrusion attempts.
     *
     * @return Active intrusions.
     */
    suspend fun getActiveIntrusions():
        List<IntrusionEvent>

    /**
     * Retrieves intrusions
     * by severity.
     *
     * @param severity Intrusion severity.
     *
     * @return Intrusion list.
     */
    suspend fun getIntrusionsBySeverity(
        severity: IntrusionSeverity
    ): List<IntrusionEvent>

    /**
     * Retrieves intrusions
     * by attack type.
     *
     * @param type Intrusion type.
     *
     * @return Intrusion list.
     */
    suspend fun getIntrusionsByType(
        type: IntrusionType
    ): List<IntrusionEvent>

    /**
     * Retrieves total
     * intrusion count.
     *
     * @return Intrusion count.
     */
    suspend fun getIntrusionCount():
        Int
}

/**
 * IntrusionEvent
 *
 * Represents an intrusion
 * detection event.
 */
data class IntrusionEvent(

    /**
     * Intrusion identifier.
     */
    val intrusionId: String,

    /**
     * Attack source.
     */
    val sourceIp: String,

    /**
     * Target destination.
     */
    val destinationIp: String,

    /**
     * Intrusion type.
     */
    val intrusionType:
        IntrusionType,

    /**
     * Intrusion severity.
     */
    val severity:
        IntrusionSeverity,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Event description.
     */
    val description: String,

    /**
     * Resolution status.
     */
    val isResolved: Boolean
)

/**
 * Intrusion types.
 */
enum class IntrusionType {

    /**
     * Brute force attack.
     */
    BRUTE_FORCE,

    /**
     * Port scanning attack.
     */
    PORT_SCAN,

    /**
     * Denial of service.
     */
    DOS_ATTACK,

    /**
     * Distributed denial
     * of service.
     */
    DDOS_ATTACK,

    /**
     * SQL injection.
     */
    SQL_INJECTION,

    /**
     * Remote code execution.
     */
    REMOTE_CODE_EXECUTION,

    /**
     * Privilege escalation.
     */
    PRIVILEGE_ESCALATION,

    /**
     * Unauthorized access.
     */
    UNAUTHORIZED_ACCESS
}

/**
 * Intrusion severity.
 */
enum class IntrusionSeverity {

    /**
     * Low severity.
     */
    LOW,

    /**
     * Medium severity.
     */
    MEDIUM,

    /**
     * High severity.
     */
    HIGH,

    /**
     * Critical severity.
     */
    CRITICAL
}
