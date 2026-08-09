package com.sentrix.data.repository.auth

import com.sentrix.data.local.dao.SessionDao
import com.sentrix.data.local.entities.SessionEntity
import com.sentrix.data.remote.api.AuthApiService
import com.sentrix.data.remote.dto.AuthResponseDto
import com.sentrix.data.remote.dto.LoginRequestDto
import com.sentrix.data.remote.dto.RefreshTokenRequestDto
import com.sentrix.data.remote.dto.RegisterRequestDto
import com.sentrix.domain.models.User
import com.sentrix.domain.models.Session
import com.sentrix.domain.repository.AuthRepository
import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.AuthenticationException
import com.sentrix.core.exceptions.UnknownException
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Authentication Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.auth
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete implementation of the Domain AuthRepository.
 *
 * This class acts as the bridge between:
 *
 * Domain Layer
 *      ↓
 * AuthRepository
 *      ↓
 * AuthRepositoryImpl
 *      ↓
 * Remote API / Local Database
 *
 * The Domain layer only knows about AuthRepository.
 * It does NOT know about:
 *
 * - Retrofit
 * - AuthApiService
 * - Room
 * - DTOs
 * - Entity classes
 * - HTTP exceptions
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Domain
 *     ↓
 * Repository Interface
 *     ↓
 * Data Repository Implementation
 *     ↓
 * ┌──────────────────────┐
 * │ Remote API           │
 * │ Local Database       │
 * │ DTO / Entity Mapper  │
 * └──────────────────────┘
 *
 * Enterprise considerations:
 * ------------------------------------------------------------
 * - Single responsibility
 * - Dependency inversion
 * - Explicit error mapping
 * - Token/session persistence
 * - DTO isolation
 * - Entity isolation
 * - No Android UI dependencies
 * - Injectable with Hilt/Dagger
 * - Thread-safe repository design
 */
@Singleton
class AuthRepositoryImpl @Inject constructor(
    private val authApiService: AuthApiService,
    private val sessionDao: SessionDao
) : AuthRepository {

    /**
     * Authenticates an existing SentriX user.
     *
     * Flow:
     *
     * 1. Send credentials to authentication API.
     * 2. Receive authentication response.
     * 3. Convert DTO into Domain model.
     * 4. Persist session information locally.
     * 5. Return domain-level session.
     *
     * Sensitive information such as passwords should never
     * be stored locally.
     */
    override suspend fun login(
        email: String,
        password: String
    ): Result<Session> {

        return try {

            /**
             * Build the request DTO.
             *
             * The DTO belongs to the Data layer and therefore
             * never escapes into the Domain layer.
             */
            val request = LoginRequestDto(
                email = email,
                password = password
            )

            /**
             * Execute remote authentication.
             */
            val response = authApiService.login(request)

            /**
             * Validate the response.
             */
            validateAuthenticationResponse(response)

            /**
             * Convert API response into Domain model.
             */
            val session = response.toDomainSession()

            /**
             * Persist the authenticated session locally.
             *
             * The password is deliberately NOT stored.
             */
            persistSession(response)

            Result.success(session)

        } catch (exception: Exception) {

            Result.failure(
                mapAuthenticationException(exception)
            )
        }
    }

    /**
     * Registers a new SentriX account.
     */
    override suspend fun register(
        name: String,
        email: String,
        password: String
    ): Result<Session> {

        return try {

            val request = RegisterRequestDto(
                name = name,
                email = email,
                password = password
            )

            /**
             * Execute registration request.
             */
            val response = authApiService.register(request)

            /**
             * Validate server response.
             */
            validateAuthenticationResponse(response)

            /**
             * Convert DTO to Domain model.
             */
            val session = response.toDomainSession()

            /**
             * Store the newly created session.
             */
            persistSession(response)

            Result.success(session)

        } catch (exception: Exception) {

            Result.failure(
                mapAuthenticationException(exception)
            )
        }
    }

    /**
     * Refreshes an expired access token.
     *
     * Refresh tokens should ideally be stored in secure
     * storage rather than ordinary preferences.
     */
    override suspend fun refreshToken(
        refreshToken: String
    ): Result<Session> {

        return try {

            val request = RefreshTokenRequestDto(
                refreshToken = refreshToken
            )

            /**
             * Request a new access token.
             */
            val response = authApiService.refreshToken(request)

            validateAuthenticationResponse(response)

            /**
             * Convert refreshed authentication information
             * into the Domain session.
             */
            val session = response.toDomainSession()

            /**
             * Replace the existing local session with the
             * refreshed credentials.
             */
            persistSession(response)

            Result.success(session)

        } catch (exception: Exception) {

            Result.failure(
                mapAuthenticationException(exception)
            )
        }
    }

    /**
     * Logs the current user out.
     *
     * Logout should perform both:
     *
     * 1. Remote logout, where supported.
     * 2. Local session cleanup.
     *
     * Local cleanup is important even if the remote server
     * cannot be reached.
     */
    override suspend fun logout(): Result<Unit> {

        return try {

            /**
             * Attempt remote logout.
             *
             * Depending on the backend implementation,
             * this may invalidate the server-side session.
             */
            try {
                authApiService.logout()
            } catch (exception: Exception) {

                /**
                 * Remote logout failure is intentionally not
                 * allowed to prevent local credential cleanup.
                 *
                 * The local session must still be removed.
                 */
            }

            /**
             * Remove local authentication state.
             */
            sessionDao.deleteCurrentSession()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapAuthenticationException(exception)
            )
        }
    }

    /**
     * Returns the currently authenticated session.
     *
     * This operation is intentionally local.
     *
     * It allows the application to determine whether a user
     * is already authenticated without making a network call.
     */
    override suspend fun getCurrentSession(): Result<Session?> {

        return try {

            val entity = sessionDao.getCurrentSession()

            /**
             * No local session means that the user is not
             * currently authenticated on this device.
             */
            if (entity == null) {
                return Result.success(null)
            }

            /**
             * Convert Room entity into Domain model.
             */
            Result.success(
                entity.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAuthenticationException(exception)
            )
        }
    }

    /**
     * Determines whether the device currently has a local
     * authenticated session.
     */
    override suspend fun isAuthenticated(): Result<Boolean> {

        return try {

            Result.success(
                sessionDao.getCurrentSession() != null
            )

        } catch (exception: Exception) {

            Result.failure(
                mapAuthenticationException(exception)
            )
        }
    }

    /**
     * Persists authentication information locally.
     *
     * IMPORTANT:
     * ------------------------------------------------------------
     * Never persist:
     *
     * - password
     * - OTP
     * - PIN
     * - raw authentication credentials
     *
     * The actual SessionDao implementation should use secure
     * storage for sensitive tokens where possible.
     */
    private suspend fun persistSession(
        response: AuthResponseDto
    ) {

        val sessionEntity = SessionEntity(
            sessionId = response.sessionId,
            userId = response.user.id,
            accessToken = response.accessToken,
            refreshToken = response.refreshToken,
            expiresAt = response.expiresAt,
            isActive = true
        )

        /**
         * Remove an existing active session before inserting
         * the new one.
         *
         * This guarantees that only one active authentication
         * session is represented locally.
         */
        sessionDao.deleteCurrentSession()

        sessionDao.insertSession(sessionEntity)
    }

    /**
     * Validates the basic authentication response.
     *
     * Even when Retrofit returns HTTP 200, application-level
     * validation is still useful.
     */
    private fun validateAuthenticationResponse(
        response: AuthResponseDto
    ) {

        if (response.accessToken.isBlank()) {
            throw AuthenticationException(
                "Authentication succeeded without an access token."
            )
        }

        if (response.refreshToken.isBlank()) {
            throw AuthenticationException(
                "Authentication succeeded without a refresh token."
            )
        }

        if (response.sessionId.isBlank()) {
            throw AuthenticationException(
                "Authentication succeeded without a session ID."
            )
        }
    }

    /**
     * Converts infrastructure-specific exceptions into
     * SentriX application exceptions.
     *
     * This prevents Retrofit/OkHttp exceptions from leaking
     * into the Domain layer.
     */
    private fun mapAuthenticationException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * No internet / socket / DNS / connection failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX server.",
                    cause = exception
                )
            }

            /**
             * HTTP errors returned by the backend.
             */
            is HttpException -> {

                when (exception.code()) {

                    /**
                     * Unauthorized.
                     */
                    401 -> AuthenticationException(
                        "Authentication failed. Please verify your credentials."
                    )

                    /**
                     * Forbidden.
                     */
                    403 -> AuthenticationException(
                        "Access to this account is currently forbidden."
                    )

                    /**
                     * Not found.
                     */
                    404 -> ServerException(
                        "Authentication service was not found."
                    )

                    /**
                     * Rate limited.
                     */
                    429 -> ServerException(
                        "Too many authentication attempts. Please try again later."
                    )

                    /**
                     * Server-side failure.
                     */
                    in 500..599 -> ServerException(
                        "SentriX authentication server is currently unavailable."
                    )

                    /**
                     * Other HTTP errors.
                     */
                    else -> ServerException(
                        "Authentication request failed with HTTP ${exception.code()}."
                    )
                }
            }

            /**
             * Already mapped authentication error.
             */
            is AuthenticationException -> {
                exception
            }

            /**
             * Unknown/unexpected failure.
             */
            else -> {
                UnknownException(
                    message = "An unexpected authentication error occurred.",
                    cause = exception
                )
            }
        }
    }
}


/**
 * Converts AuthResponseDto into the Domain Session model.
 *
 * DTO → Domain mapping belongs to the Data layer.
 */
private fun AuthResponseDto.toDomainSession(): Session {

    return Session(
        sessionId = sessionId,
        user = User(
            id = user.id,
            name = user.name,
            email = user.email
        ),
        accessToken = accessToken,
        refreshToken = refreshToken,
        expiresAt = expiresAt
    )
}


/**
 * Converts Room SessionEntity into the Domain Session model.
 *
 * Database entities must never leak into the Domain layer.
 */
private fun SessionEntity.toDomain(): Session {

    return Session(
        sessionId = sessionId,
        user = User(
            id = userId,
            name = "",
            email = ""
        ),
        accessToken = accessToken,
        refreshToken = refreshToken,
        expiresAt = expiresAt
    )
}
