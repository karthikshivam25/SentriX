package com.sentrix.domain.repositories

import com.sentrix.domain.models.ProtectionEvent
import com.sentrix.domain.models.ProtectionStatus
import com.sentrix.domain.models.ThreatIndicator

/**
 * RealtimeProtectionRepository
 *
 * Repository responsible for
 * managing real-time protection
 * services within the SentriX
 * cybersecurity platform.
 *
 * Used by:
 * - StartRealtimeProtectionUseCase
 * - StopRealtimeProtectionUseCase
 * - ThreatDetectionEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Enable protection
 * - Disable protection
 * - Monitor threats
 * - Store protection events
 * - Track protection status
 */
interface RealtimeProtectionRepository {

    /**
     * Starts real-time protection.
     *
     * @return Success status.
     */
    suspend fun startProtection():
        Boolean

    /**
     * Stops real-time protection.
     *
     * @return Success status.
     */
    suspend fun stopProtection():
        Boolean

    /**
     * Retrieves current
     * protection status.
     *
     * @return Protection status.
     */
    suspend fun getProtectionStatus():
        ProtectionStatus

    /**
     * Checks whether
     * protection is active.
     *
     * @return Active status.
     */
    suspend fun isProtectionEnabled():
        Boolean

    /**
     * Retrieves detected threats.
     *
     * @return Threat list.
     */
    suspend fun getDetectedThreats():
        List<ThreatIndicator>

    /**
     * Saves protection event.
     *
     * @param event Protection event.
     */
    suspend fun saveProtectionEvent(
        event: ProtectionEvent
    )

    /**
     * Retrieves protection history.
     *
     * @return Protection events.
     */
    suspend fun getProtectionHistory():
        List<ProtectionEvent>

    /**
     * Retrieves latest
     * protection event.
     *
     * @return Protection event.
     */
    suspend fun getLatestEvent():
        ProtectionEvent?
}

/**
 * ProtectionEvent
 *
 * Represents a real-time
 * protection event.
 */
data class ProtectionEvent(

    /**
     * Event identifier.
     */
    val eventId: String,

    /**
     * Event title.
     */
    val title: String,

    /**
     * Event description.
     */
    val description: String,

    /**
     * Threat information.
     */
    val threat:
        ThreatIndicator?,

    /**
     * Event timestamp.
     */
    val occurredAt: Long,

    /**
     * Protection action taken.
     */
    val actionTaken: String
)

/**
 * Protection status.
 */
enum class ProtectionStatus {

    /**
     * Protection enabled.
     */
    ENABLED,

    /**
     * Protection disabled.
     */
    DISABLED,

    /**
     * Protection starting.
     */
    STARTING,

    /**
     * Protection stopped.
     */
    STOPPED,

    /**
     * Protection error.
     */
    ERROR
}
