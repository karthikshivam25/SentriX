package com.sentrix.domain.repositories

import com.sentrix.domain.models.User
import com.sentrix.domain.models.UserRole
import com.sentrix.domain.models.UserStatus

/**
 * UserRepository
 *
 * Repository responsible for
 * managing user information
 * within the SentriX
 * cybersecurity platform.
 *
 * Used by:
 * - AuthenticationManager
 * - UserManagementService
 * - SessionManager
 * - SecurityDashboard
 * - AccessControlEngine
 *
 * Responsibilities:
 * - Manage user accounts
 * - Retrieve user information
 * - Update user profiles
 * - Handle user status
 * - Support authentication
 */
interface UserRepository {

    /**
     * Retrieves all users.
     *
     * @return User list.
     */
    suspend fun getUsers():
        List<User>

    /**
     * Retrieves user
     * by identifier.
     *
     * @param userId User ID.
     *
     * @return User information.
     */
    suspend fun getUserById(
        userId: String
    ): User?

    /**
     * Retrieves user
     * by email.
     *
     * @param email User email.
     *
     * @return User information.
     */
    suspend fun getUserByEmail(
        email: String
    ): User?

    /**
     * Saves user.
     *
     * @param user User information.
     */
    suspend fun saveUser(
        user: User
    )

    /**
     * Updates user.
     *
     * @param user User information.
     */
    suspend fun updateUser(
        user: User
    )

    /**
     * Deletes user.
     *
     * @param userId User ID.
     */
    suspend fun deleteUser(
        userId: String
    )

    /**
     * Retrieves active users.
     *
     * @return Active user list.
     */
    suspend fun getActiveUsers():
        List<User>

    /**
     * Retrieves users
     * by role.
     *
     * @param role User role.
     *
     * @return User list.
     */
    suspend fun getUsersByRole(
        role: UserRole
    ): List<User>

    /**
     * Retrieves total
     * user count.
     *
     * @return User count.
     */
    suspend fun getUserCount():
        Int
}

/**
 * User
 *
 * Represents a SentriX user.
 */
data class User(

    /**
     * User identifier.
     */
    val userId: String,

    /**
     * Full name.
     */
    val fullName: String,

    /**
     * Email address.
     */
    val email: String,

    /**
     * User role.
     */
    val role:
        UserRole,

    /**
     * Account status.
     */
    val status:
        UserStatus,

    /**
     * Registration timestamp.
     */
    val createdAt: Long,

    /**
     * Last login timestamp.
     */
    val lastLoginAt: Long?
)

/**
 * User roles.
 */
enum class UserRole {

    /**
     * System administrator.
     */
    ADMIN,

    /**
     * Security analyst.
     */
    SECURITY_ANALYST,

    /**
     * Security operator.
     */
    SECURITY_OPERATOR,

    /**
     * Standard user.
     */
    USER,

    /**
     * Guest user.
     */
    GUEST
}

/**
 * User account status.
 */
enum class UserStatus {

    /**
     * Account active.
     */
    ACTIVE,

    /**
     * Account inactive.
     */
    INACTIVE,

    /**
     * Account suspended.
     */
    SUSPENDED,

    /**
     * Account locked.
     */
    LOCKED
}
