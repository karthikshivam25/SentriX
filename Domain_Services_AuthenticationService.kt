package com.sentrix.domain.services

import com.sentrix.domain.models.User
import com.sentrix.domain.models.UserSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

/**
 * Service responsible for authentication
 * and session management.
 *
 * This service handles login validation,
 * session creation, logout operations,
 * and user authentication checks.
 */
class AuthenticationService {

    /**
     * Authenticates a user.
     *
     * Returns true if credentials are valid.
     */
    suspend fun authenticate(
        username: String,
        password: String,
        user: User
    ): Boolean = withContext(Dispatchers.Default) {

        username == user.username &&
        password == user.password
    }

    /**
     * Creates a user session.
     */
    suspend fun createSession(
        user: User
    ): UserSession = withContext(Dispatchers.Default) {

        UserSession(
            sessionId = UUID.randomUUID().toString(),
            userId = user.userId,
            loginTimestamp = System.currentTimeMillis(),
            isActive = true
        )
    }

    /**
     * Terminates a user session.
     */
    suspend fun logout(
        session: UserSession
    ): UserSession = withContext(Dispatchers.Default) {

        session.copy(
            isActive = false
        )
    }

    /**
     * Validates session state.
     */
    suspend fun validateSession(
        session: UserSession
    ): Boolean = withContext(Dispatchers.Default) {

        session.isActive
    }

    /**
     * Checks if user is authenticated.
     */
    suspend fun isAuthenticated(
        session: UserSession?
    ): Boolean = withContext(Dispatchers.Default) {

        session?.isActive == true
    }

    /**
     * Generates authentication token.
     *
     * Simple UUID token for demo purposes.
     */
    suspend fun generateToken(): String =
        withContext(Dispatchers.Default) {

            UUID.randomUUID().toString()
        }

    /**
     * Refreshes user session.
     */
    suspend fun refreshSession(
        session: UserSession
    ): UserSession = withContext(Dispatchers.Default) {

        session.copy(
            loginTimestamp = System.currentTimeMillis()
        )
    }

    /**
     * Determines whether session has expired.
     *
     * Default timeout = 24 hours.
     */
    suspend fun isSessionExpired(
        session: UserSession,
        timeoutMillis: Long = 24 * 60 * 60 * 1000L
    ): Boolean = withContext(Dispatchers.Default) {

        System.currentTimeMillis() -
                session.loginTimestamp >
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
     * Generates authentication summary.
     */
    suspend fun generateAuthenticationSummary(
        sessions: List<UserSession>
    ): String = withContext(Dispatchers.Default) {

        val activeSessions = sessions.count {
            it.isActive
        }

        val inactiveSessions = sessions.count {
            !it.isActive
        }

        buildString {

            appendLine("SentriX Authentication Summary")
            appendLine("==============================")
            appendLine("Total Sessions: ${sessions.size}")
            appendLine("Active Sessions: $activeSessions")
            appendLine("Inactive Sessions: $inactiveSessions")
        }
    }

    /**
     * Determines whether a user account
     * can access protected resources.
     */
    suspend fun canAccessProtectedResources(
        session: UserSession?
    ): Boolean = withContext(Dispatchers.Default) {

        session != null &&
        session.isActive &&
        !isSessionExpired(session)
    }
}
