package com.sentrix.domain.repositories

import com.sentrix.domain.models.SessionInfo
import com.sentrix.domain.models.SessionStatus
import com.sentrix.domain.models.SessionType

/**
 * SessionRepository
 *
 * Repository responsible for
 * managing user sessions within
 * the SentriX cybersecurity
 * platform.
 *
 * Used by:
 * - AuthenticationManager
 * - SecurityDashboard
 * - CyberDefenseManager
 * - SessionMonitoringService
 * - AccessControlEngine
 *
 * Responsibilities:
 * - Create sessions
 * - Manage active sessions
 * - Validate session status
 * - Track session history
 * - Support secure authentication
 */
interface SessionRepository {

    /**
     * Creates a new session.
     *
     * @param session Session information.
     *
     * @return Created session.
     */
    suspend fun createSession(
        session: SessionInfo
    ): SessionInfo

    /**
     * Retrieves all sessions.
     *
     * @return Session list.
     */
    suspend fun getSessions():
        List<SessionInfo>

    /**
     * Retrieves session
     * by identifier.
     *
     * @param sessionId Session ID.
     *
     * @return Session information.
     */
    suspend fun getSessionById(
        sessionId: String
    ): SessionInfo?

    /**
     * Retrieves active sessions.
     *
     * @return Active session list.
     */
    suspend fun getActiveSessions():
        List<SessionInfo>

    /**
     * Updates session.
     *
     * @param session Session information.
     */
    suspend fun updateSession(
        session: SessionInfo
    )

    /**
     * Terminates session.
     *
     * @param sessionId Session ID.
     *
     * @return Success status.
     */
    suspend fun terminateSession(
        sessionId: String
    ): Boolean

    /**
     * Terminates all sessions.
     *
     * @return Success status.
     */
    suspend fun terminateAllSessions():
        Boolean

    /**
     * Validates session.
     *
     * @param sessionId Session ID.
     *
     * @return Validation result.
     */
    suspend fun validateSession(
        sessionId: String
    ): Boolean

    /**
     * Retrieves total
     * session count.
     *
     * @return Session count.
     */
    suspend fun getSessionCount():
        Int
}

/**
 * SessionInfo
 *
 * Represents user
 * session information.
 */
data class SessionInfo(

    /**
     * Session identifier.
     */
    val sessionId: String,

    /**
     * User identifier.
     */
    val userId: String,

    /**
     * Session type.
     */
    val sessionType:
        SessionType,

    /**
     * Session status.
     */
    val status:
        SessionStatus,

    /**
     * Device information.
     */
    val deviceName: String,

    /**
     * IP address.
     */
    val ipAddress: String,

    /**
     * Session creation time.
     */
    val createdAt: Long,

    /**
     * Last activity time.
     */
    val lastActivityAt: Long
)

/**
 * Session types.
 */
enum class SessionType {

    /**
     * Mobile session.
     */
    MOBILE,

    /**
     * Web session.
     */
    WEB,

    /**
     * Desktop session.
     */
    DESKTOP,

    /**
     * API session.
     */
    API
}

/**
 * Session status.
 */
enum class SessionStatus {

    /**
     * Session active.
     */
    ACTIVE,

    /**
     * Session expired.
     */
    EXPIRED,

    /**
     * Session terminated.
     */
    TERMINATED,

    /**
     * Session suspended.
     */
    SUSPENDED
}
