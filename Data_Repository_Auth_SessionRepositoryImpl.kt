package com.sentrix.data.repository.auth

import com.sentrix.data.local.dao.SessionDao
import com.sentrix.data.local.entities.SessionEntity
import com.sentrix.domain.models.Session
import com.sentrix.domain.repository.SessionRepository
import com.sentrix.core.exceptions.AuthenticationException
import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.UnknownException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Session Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.auth
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Manages the lifecycle of the currently authenticated SentriX
 * session.
 *
 * This repository is intentionally separated from
 * AuthRepositoryImpl.
 *
 * AuthRepository:
 * ------------------------------------------------------------
 * Handles authentication operations such as:
 *
 * - Login
 * - Registration
 * - Token refresh
 * - Logout
 *
 * SessionRepository:
 * ------------------------------------------------------------
 * Handles local/current session state such as:
 *
 * - Get current session
 * - Check authentication state
 * - Save session
 * - Update session
 * - Clear session
 * - Check session expiry
 * - Retrieve access token
 * - Retrieve refresh token
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Domain
 *     │
 *     ▼
 * SessionRepository
 *     │
 *     ▼
 * SessionRepositoryImpl
 *     │
 *     ▼
 * SessionDao
 *     │
 *     ▼
 * SessionEntity
 *
 * Important:
 * ------------------------------------------------------------
 * Room entities never leave the Data layer.
 *
 * Domain models never depend on Room.
 */
@Singleton
class SessionRepositoryImpl @Inject constructor(
    private val sessionDao: SessionDao
) : SessionRepository {

    /**
     * Retrieves the currently active session.
     *
     * This is a local database operation.
     */
    override suspend fun getCurrentSession(): Result<Session?> {

        return try {

            val entity = sessionDao.getCurrentSession()

            /**
             * No active session means the user is not
             * authenticated on this device.
             */
            if (entity == null) {
                Result.success(null)
            } else {
                Result.success(
                    entity.toDomain()
                )
            }

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Determines whether a valid session currently exists.
     *
     * A session is considered authenticated only when:
     *
     * 1. A session exists.
     * 2. The session is marked active.
     * 3. The access token is not empty.
     * 4. The session has not expired.
     */
    override suspend fun isAuthenticated(): Result<Boolean> {

        return try {

            val session = sessionDao.getCurrentSession()

                ?: return Result.success(false)

            /**
             * Verify that the session is active.
             */
            if (!session.isActive) {
                return Result.success(false)
            }

            /**
             * Verify that a usable access token exists.
             */
            if (session.accessToken.isBlank()) {
                return Result.success(false)
            }

            /**
             * Verify token/session expiry.
             */
            if (isExpired(session.expiresAt)) {

                /**
                 * Mark the expired session inactive.
                 *
                 * We do not immediately delete it because
                 * another authentication component may still
                 * need the refresh token.
                 */
                sessionDao.updateSessionStatus(
                    sessionId = session.sessionId,
                    isActive = false
                )

                return Result.success(false)
            }

            Result.success(true)

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Saves a new authenticated session.
     *
     * Existing active sessions are removed before inserting
     * the new session.
     */
    override suspend fun saveSession(
        session: Session
    ): Result<Unit> {

        return try {

            /**
             * Convert Domain model into Room entity.
             */
            val entity = session.toEntity()

            /**
             * Only one active SentriX session is maintained
             * locally for this device.
             */
            sessionDao.deleteCurrentSession()

            /**
             * Persist the new session.
             */
            sessionDao.insertSession(entity)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Updates the existing session.
     *
     * This is primarily useful after token refresh.
     */
    override suspend fun updateSession(
        session: Session
    ): Result<Unit> {

        return try {

            val existingSession =
                sessionDao.getCurrentSession()
                    ?: return Result.failure(
                        AuthenticationException(
                            "No active session exists."
                        )
                    )

            /**
             * Preserve the existing database identity while
             * updating authentication information.
             */
            val updatedEntity = existingSession.copy(
                sessionId = session.sessionId,
                userId = session.user.id,
                accessToken = session.accessToken,
                refreshToken = session.refreshToken,
                expiresAt = session.expiresAt,
                isActive = true
            )

            sessionDao.updateSession(updatedEntity)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Retrieves the access token belonging to the current
     * session.
     *
     * This method is intentionally read-only.
     */
    override suspend fun getAccessToken(): Result<String?> {

        return try {

            val session =
                sessionDao.getCurrentSession()

            if (session == null || !session.isActive) {
                return Result.success(null)
            }

            /**
             * Do not return an expired access token.
             */
            if (isExpired(session.expiresAt)) {
                return Result.success(null)
            }

            Result.success(
                session.accessToken.takeIf {
                    it.isNotBlank()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Retrieves the refresh token belonging to the current
     * session.
     *
     * This should be consumed only by the authentication/
     * token-refresh infrastructure.
     */
    override suspend fun getRefreshToken(): Result<String?> {

        return try {

            val session =
                sessionDao.getCurrentSession()

            if (session == null || !session.isActive) {
                return Result.success(null)
            }

            Result.success(
                session.refreshToken.takeIf {
                    it.isNotBlank()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Determines whether the current access/session token
     * has expired.
     */
    override suspend fun isSessionExpired(): Result<Boolean> {

        return try {

            val session =
                sessionDao.getCurrentSession()

            /**
             * No session is treated as expired.
             */
            if (session == null) {
                return Result.success(true)
            }

            Result.success(
                isExpired(session.expiresAt)
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Returns the remaining lifetime of the current session
     * in milliseconds.
     *
     * A value of zero means that the session has already
     * expired or does not exist.
     */
    override suspend fun getSessionRemainingTime(): Result<Long> {

        return try {

            val session =
                sessionDao.getCurrentSession()

            if (session == null) {
                return Result.success(0L)
            }

            val remaining =
                session.expiresAt - System.currentTimeMillis()

            Result.success(
                remaining.coerceAtLeast(0L)
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Invalidates the current session.
     *
     * Instead of immediately deleting the record, the session
     * is marked inactive.
     *
     * This can be useful for:
     *
     * - Security auditing
     * - Session history
     * - Logout tracking
     * - Incident investigation
     */
    override suspend fun invalidateSession(): Result<Unit> {

        return try {

            val session =
                sessionDao.getCurrentSession()

            if (session == null) {
                return Result.success(Unit)
            }

            sessionDao.updateSessionStatus(
                sessionId = session.sessionId,
                isActive = false
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Completely removes the current session from local
     * storage.
     *
     * This is stronger than invalidateSession().
     */
    override suspend fun clearSession(): Result<Unit> {

        return try {

            sessionDao.deleteCurrentSession()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSessionException(exception)
            )
        }
    }

    /**
     * Checks whether the session expiry timestamp is in
     * the past.
     *
     * expiresAt is expected to be represented as epoch
     * milliseconds.
     */
    private fun isExpired(
        expiresAt: Long
    ): Boolean {

        return System.currentTimeMillis() >= expiresAt
    }

    /**
     * Converts Room SessionEntity into the Domain Session.
     *
     * Database implementation details remain inside Data.
     */
    private fun SessionEntity.toDomain(): Session {

        return Session(
            sessionId = sessionId,
            user = com.sentrix.domain.models.User(
                id = userId,

                /**
                 * User profile information may be retrieved
                 * from the UserRepository when required.
                 *
                 * Session storage should remain focused on
                 * authentication/session information.
                 */
                name = "",
                email = ""
            ),
            accessToken = accessToken,
            refreshToken = refreshToken,
            expiresAt = expiresAt
        )
    }

    /**
     * Converts Domain Session into a Room entity.
     */
    private fun Session.toEntity(): SessionEntity {

        return SessionEntity(
            sessionId = sessionId,
            userId = user.id,
            accessToken = accessToken,
            refreshToken = refreshToken,
            expiresAt = expiresAt,
            isActive = true
        )
    }

    /**
     * Converts Data-layer exceptions into application-level
     * exceptions.
     *
     * This prevents database/infrastructure exceptions from
     * leaking into higher layers.
     */
    private fun mapSessionException(
        exception: Exception
    ): Exception {

        return when (exception) {

            is IOException -> {
                NetworkException(
                    message = "Unable to access SentriX session data.",
                    cause = exception
                )
            }

            is AuthenticationException -> {
                exception
            }

            else -> {
                UnknownException(
                    message = "An unexpected session error occurred.",
                    cause = exception
                )
            }
        }
    }
}
