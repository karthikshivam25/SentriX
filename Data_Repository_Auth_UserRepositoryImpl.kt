package com.sentrix.data.repository.auth

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.UserDao
import com.sentrix.data.local.entities.UserEntity
import com.sentrix.data.remote.api.UserApiService
import com.sentrix.data.remote.dto.UpdateUserProfileRequestDto
import com.sentrix.data.remote.dto.UserDto
import com.sentrix.domain.models.User
import com.sentrix.domain.repository.UserRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - User Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.auth
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Provides the concrete Data-layer implementation of the
 * Domain UserRepository.
 *
 * Main responsibilities:
 *
 * - Retrieve the current user.
 * - Retrieve a user by ID.
 * - Refresh user information from the backend.
 * - Update user profile.
 * - Cache user information locally.
 * - Remove cached user information.
 * - Convert DTOs into Domain models.
 * - Convert Room entities into Domain models.
 * - Convert infrastructure exceptions into application
 *   exceptions.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * DOMAIN
 *    │
 *    ▼
 * UserRepository
 *    │
 *    ▼
 * DATA
 *    │
 *    ▼
 * UserRepositoryImpl
 *    │
 *    ├──────────────► UserApiService
 *    │                    │
 *    │                    ▼
 *    │                 UserDto
 *    │
 *    └──────────────► UserDao
 *                         │
 *                         ▼
 *                    UserEntity
 *
 * Security:
 * ------------------------------------------------------------
 * This repository must NOT:
 *
 * - Store passwords.
 * - Store OTPs.
 * - Handle authentication tokens directly.
 * - Log sensitive user information.
 * - Expose Retrofit DTOs to Domain.
 * - Expose Room entities to Domain.
 *
 * Authentication/session responsibilities remain with:
 *
 * - AuthRepositoryImpl
 * - SessionRepositoryImpl
 */
@Singleton
class UserRepositoryImpl @Inject constructor(
    private val userApiService: UserApiService,
    private val userDao: UserDao
) : UserRepository {

    /**
     * Retrieves the currently authenticated user's profile.
     *
     * Strategy:
     *
     * 1. Try to retrieve the user from the local cache.
     * 2. Return the cached user when available.
     *
     * This operation is intentionally local-first so that
     * SentriX can display user information even when the
     * network is temporarily unavailable.
     */
    override suspend fun getCurrentUser(): Result<User?> {

        return try {

            val entity = userDao.getCurrentUser()

            if (entity == null) {
                Result.success(null)
            } else {
                Result.success(
                    entity.toDomain()
                )
            }

        } catch (exception: Exception) {

            Result.failure(
                mapUserException(exception)
            )
        }
    }

    /**
     * Retrieves the current user directly from the SentriX
     * backend.
     *
     * The returned user is also stored in the local cache.
     *
     * This method should be used when fresh server-side
     * information is required.
     */
    override suspend fun refreshCurrentUser(): Result<User> {

        return try {

            /**
             * Execute the authenticated user-profile request.
             */
            val response = userApiService.getCurrentUser()

            /**
             * Convert Data DTO into Domain model.
             */
            val user = response.toDomain()

            /**
             * Cache the latest server representation.
             */
            cacheUser(response)

            Result.success(user)

        } catch (exception: Exception) {

            Result.failure(
                mapUserException(exception)
            )
        }
    }

    /**
     * Retrieves a user by their unique SentriX user ID.
     *
     * This operation is normally used by security,
     * administrative or relationship-related features where
     * another user's profile is required.
     */
    override suspend fun getUserById(
        userId: String
    ): Result<User?> {

        return try {

            /**
             * Validate the identifier before performing
             * unnecessary network/database operations.
             */
            if (userId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "User ID cannot be blank."
                    )
                )
            }

            val response =
                userApiService.getUserById(userId)

            val user = response.toDomain()

            /**
             * Cache the retrieved user.
             *
             * Whether this should be done for every user or
             * only the current user can be changed according
             * to the SentriX privacy policy.
             */
            cacheUser(response)

            Result.success(user)

        } catch (exception: Exception) {

            Result.failure(
                mapUserException(exception)
            )
        }
    }

    /**
     * Updates the current user's profile.
     *
     * Only profile information should be accepted here.
     *
     * Authentication credentials such as:
     *
     * - Password
     * - Refresh token
     * - Access token
     * - OTP
     *
     * must never be updated through this method.
     */
    override suspend fun updateProfile(
        name: String?,
        email: String?,
        phoneNumber: String?,
        profileImageUrl: String?
    ): Result<User> {

        return try {

            /**
             * Build a Data-layer request DTO.
             */
            val request = UpdateUserProfileRequestDto(
                name = name,
                email = email,
                phoneNumber = phoneNumber,
                profileImageUrl = profileImageUrl
            )

            /**
             * Send the profile update to the backend.
             */
            val response =
                userApiService.updateProfile(request)

            /**
             * Convert the response into a Domain model.
             */
            val user = response.toDomain()

            /**
             * Update local cache with the server's final
             * representation.
             */
            cacheUser(response)

            Result.success(user)

        } catch (exception: Exception) {

            Result.failure(
                mapUserException(exception)
            )
        }
    }

    /**
     * Saves/caches a user locally.
     *
     * This method is useful when authentication or another
     * remote operation already returned user information.
     */
    override suspend fun cacheUser(
        user: User
    ): Result<Unit> {

        return try {

            val entity = user.toEntity()

            /**
             * Replace the existing cached representation.
             */
            userDao.insertOrUpdate(entity)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapUserException(exception)
            )
        }
    }

    /**
     * Deletes the locally cached current user.
     *
     * This should normally be called during:
     *
     * - Logout
     * - Account removal
     * - Session invalidation
     * - Security reset
     */
    override suspend fun clearCurrentUser(): Result<Unit> {

        return try {

            userDao.deleteCurrentUser()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapUserException(exception)
            )
        }
    }

    /**
     * Checks whether a cached user exists locally.
     */
    override suspend fun hasCachedUser(): Result<Boolean> {

        return try {

            Result.success(
                userDao.getCurrentUser() != null
            )

        } catch (exception: Exception) {

            Result.failure(
                mapUserException(exception)
            )
        }
    }

    /**
     * Converts a remote UserDto into a Domain User.
     *
     * DTOs belong exclusively to the Data layer.
     */
    private fun UserDto.toDomain(): User {

        return User(
            id = id,
            name = name,
            email = email
        )
    }

    /**
     * Converts a Domain User into a Room entity.
     *
     * Domain models should never be persisted directly by Room.
     */
    private fun User.toEntity(): UserEntity {

        return UserEntity(
            id = id,
            name = name,
            email = email,
            isCurrentUser = true
        )
    }

    /**
     * Stores a remote UserDto in the local database.
     *
     * Keeping this operation centralized prevents duplicate
     * mapping logic throughout the repository.
     */
    private suspend fun cacheUser(
        userDto: UserDto
    ) {

        userDao.insertOrUpdate(
            userDto.toEntity()
        )
    }

    /**
     * Converts a UserDto directly into a Room entity.
     *
     * This avoids unnecessary Domain-layer conversion when
     * the repository only needs to update the cache.
     */
    private fun UserDto.toEntity(): UserEntity {

        return UserEntity(
            id = id,
            name = name,
            email = email,
            isCurrentUser = true
        )
    }

    /**
     * Converts a Room UserEntity into the Domain User model.
     */
    private fun UserEntity.toDomain(): User {

        return User(
            id = id,
            name = name,
            email = email
        )
    }

    /**
     * Converts infrastructure-level exceptions into
     * SentriX application exceptions.
     *
     * Domain/business logic should not need to understand
     * Retrofit, OkHttp or Android database exceptions.
     */
    private fun mapUserException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX server.",
                    cause = exception
                )
            }

            /**
             * HTTP-level server failures.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The user profile request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access this user."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested user could not be found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "The supplied user information conflicts with an existing account."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Too many requests. Please try again later."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX user service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "User request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve application-level exceptions.
             */
            is NetworkException,
            is ServerException -> {
                exception
            }

            /**
             * Unexpected repository/database failure.
             */
            else -> {
                UnknownException(
                    message = "An unexpected user repository error occurred.",
                    cause = exception
                )
            }
        }
    }
}
