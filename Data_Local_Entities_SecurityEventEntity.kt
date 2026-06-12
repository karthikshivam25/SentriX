package com.sentrix.data.local.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * SecurityEventEntity
 *
 * Represents a security-related
 * event recorded within the
 * SentriX platform.
 *
 * Responsibilities:
 * - Track security incidents
 * - Monitor system activities
 * - Record threat detections
 * - Support auditing
 * - Enable forensic analysis
 */
@Entity(
    tableName = "security_events"
)
data class SecurityEventEntity(

    /**
     * Unique event identifier.
     */
    @PrimaryKey
    val eventId: String,

    /**
     * Event title.
     */
    val eventTitle: String,

    /**
     * Event description.
     */
    val eventDescription: String,

    /**
     * Event type.
     *
     * THREAT_DETECTED
     * MALWARE_FOUND
     * PHISHING_BLOCKED
     * LOGIN_SUCCESS
     * LOGIN_FAILED
     * VPN_CONNECTED
     * VPN_DISCONNECTED
     * SCAN_COMPLETED
     * FIREWALL_ALERT
     */
    val eventType: String,

    /**
     * Event severity.
     *
     * LOW
     * MEDIUM
     * HIGH
     * CRITICAL
     */
    val severity: String,

    /**
     * Event source.
     *
     * SCANNER
     * FIREWALL
     * VPN
     * AUTHENTICATION
     * REALTIME_PROTECTION
     * SYSTEM
     */
    val source: String,

    /**
     * Associated user id.
     */
    val userId: String?,

    /**
     * Associated device id.
     */
    val deviceId: String?,

    /**
     * Related threat id.
     */
    val threatId: String?,

    /**
     * Related scan id.
     */
    val scanId: String?,

    /**
     * IP address involved.
     */
    val ipAddress: String?,

    /**
     * Event location.
     */
    val location: String?,

    /**
     * Event status.
     *
     * OPEN
     * INVESTIGATING
     * RESOLVED
     * CLOSED
     */
    val status: String,

    /**
     * Indicates whether
     * action is required.
     */
    val actionRequired: Boolean,

    /**
     * Indicates whether
     * event is resolved.
     */
    val isResolved: Boolean,

    /**
     * Resolution notes.
     */
    val resolutionNotes: String?,

    /**
     * Additional metadata.
     */
    val metadata: String?,

    /**
     * Event occurrence timestamp.
     */
    val eventTimestamp: Long,

    /**
     * Resolution timestamp.
     */
    val resolvedAt: Long?,

    /**
     * Record creation timestamp.
     */
    val createdAt: Long,

    /**
     * Last update timestamp.
     */
    val updatedAt: Long?
)
