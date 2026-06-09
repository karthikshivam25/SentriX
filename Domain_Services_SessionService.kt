package com.sentrix.domain.services

import com.sentrix.domain.models.UserSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

/**
 * Service responsible for session management.
 *
 * This service handles session creation,
 * validation, expiration checks,
 * and session lifecycle operations.
 */
class SessionService {

    /**
     * Creates a new user session.
     */
    suspend fun createSession(
        userId: String
    ): UserSession = withContext(Dispatchers.Default) {

        UserSession(
            sessionId = UUID.randomUUID().toString(),
            userId = userId,
            loginTimestamp = System.currentTimeMillis(),
            isActive = true
        )
    }

    /**
     * Terminates a session.
     */
    suspend fun terminateSession(
        session: UserSession
    ): UserSession = withContext(Dispatchers.Default) {

        session.copy(
            isActive = false
        )
    }

    /**
     * Refreshes an active session.
     */
    suspend fun refreshSession(
        session: UserSession
    ): UserSession = withContext(Dispatchers.Default) {

        session.copy(
            loginTimestamp = System.currentTimeMillis()
        )
    }

    /**
     * Validates whether a session is active.
     */
    suspend fun validateSession(
        session: UserSession
    ): Boolean = withContext(Dispatchers.Default) {

        session.isActive
    }

    /**
     * Checks whether a session has expired.
     *
     * Default timeout:
     * 24 hours
     */
    suspend fun isSessionExpired(
        session: UserSession,
        timeoutMillis: Long = 24 * 60 * 60 * 1000L
    ): Boolean = withContext(Dispatchers.Default) {

        val currentTime = System.currentTimeMillis()

        currentTime - session.loginTimestamp >
                timeoutMillis
    }

    /**
     * Returns active sessions.
     */
    suspend fun getActiveSessions(
        sessions: List<UserSession>
    ): List<UserSession> = withContext(Dispatchers.Default) {

        sessions.filter {
            it.isActive
        }
    }

    /**
     * Returns inactive sessions.
     */
    suspend fun getInactiveSessions(
        sessions: List<UserSession>
    ): List<UserSession> = withContext(Dispatchers.Default) {

        sessions.filter {
            !it.isActive
        }
    }

    /**
     * Returns expired sessions.
     */
    suspend fun getExpiredSessions(
        sessions: List<UserSession>
    ): List<UserSession> = withContext(Dispatchers.Default) {

        sessions.filter {
            isSessionExpired(it)
        }
    }

    /**
     * Returns valid sessions.
     */
    suspend fun getValidSessions(
        sessions: List<UserSession>
    ): List<UserSession> = withContext(Dispatchers.Default) {

        sessions.filter {
            it.isActive &&
            !isSessionExpired(it)
        }
    }

    /**
     * Counts active sessions.
     */
    suspend fun getActiveSessionCount(
        sessions: List<UserSession>
    ): Int = withContext(Dispatchers.Default) {

        sessions.count {
            it.isActive
        }
    }

    /**
     * Counts expired sessions.
     */
    suspend fun getExpiredSessionCount(
        sessions: List<UserSession>
    ): Int = withContext(Dispatchers.Default) {

        sessions.count {
            isSessionExpired(it)
        }
    }

    /**
     * Generates session summary.
     */
    suspend fun generateSessionSummary(
        sessions: List<UserSession>
    ): String = withContext(Dispatchers.Default) {

        val activeCount =
            getActiveSessionCount(sessions)

        val expiredCount =
            getExpiredSessionCount(sessions)

        buildString {

            appendLine("SentriX Session Summary")
            appendLine("=======================")
            appendLine("Total Sessions: ${sessions.size}")
            appendLine("Active Sessions: $activeCount")
            appendLine("Expired Sessions: $expiredCount")
            appendLine(
                "Valid Sessions: ${
                    getValidSessions(sessions).size
                }"
            )
        }
    }

    /**
     * Cleans up inactive and expired sessions.
     */
    suspend fun cleanupSessions(
        sessions: List<UserSession>
    ): List<UserSession> = withContext(Dispatchers.Default) {

        sessions.filter {
            it.isActive &&
            !isSessionExpired(it)
        }
    }

    /**
     * Determines whether a user
     * currently has an active session.
     */
    suspend fun hasActiveSession(
        userId: String,
        sessions: List<UserSession>
    ): Boolean = withContext(Dispatchers.Default) {

        sessions.any {
            it.userId == userId &&
            it.isActive &&
            !isSessionExpired(it)
        }
    }
}
