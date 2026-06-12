package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.UserEntity

import kotlinx.coroutines.flow.Flow

/**
 * UserDao
 *
 * Data Access Object responsible
 * for managing user information
 * within the SentriX database.
 *
 * Responsibilities:
 * - Create user records
 * - Update user information
 * - Delete users
 * - Retrieve user profiles
 * - Manage account data
 * - Support authentication
 */
@Dao
interface UserDao {

    /**
     * Inserts a user.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertUser(
        user: UserEntity
    )

    /**
     * Inserts multiple users.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertUsers(
        users: List<UserEntity>
    )

    /**
     * Updates user information.
     */
    @Update
    suspend fun updateUser(
        user: UserEntity
    )

    /**
     * Deletes user.
     */
    @Delete
    suspend fun deleteUser(
        user: UserEntity
    )

    /**
     * Retrieves all users.
     */
    @Query(
        """
        SELECT *
        FROM users
        ORDER BY createdAt DESC
        """
    )
    fun getAllUsers():
        Flow<List<UserEntity>>

    /**
     * Retrieves user by id.
     */
    @Query(
        """
        SELECT *
        FROM users
        WHERE userId = :userId
        LIMIT 1
        """
    )
    suspend fun getUserById(
        userId: String
    ): UserEntity?

    /**
     * Retrieves user by email.
     */
    @Query(
        """
        SELECT *
        FROM users
        WHERE email = :email
        LIMIT 1
        """
    )
    suspend fun getUserByEmail(
        email: String
    ): UserEntity?

    /**
     * Retrieves currently
     * logged-in user.
     */
    @Query(
        """
        SELECT *
        FROM users
        WHERE isLoggedIn = 1
        LIMIT 1
        """
    )
    suspend fun getCurrentUser():
        UserEntity?

    /**
     * Counts users.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM users
        """
    )
    suspend fun getUserCount():
        Int

    /**
     * Checks if user exists.
     */
    @Query(
        """
        SELECT EXISTS(
            SELECT 1
            FROM users
            WHERE userId = :userId
        )
        """
    )
    suspend fun userExists(
        userId: String
    ): Boolean

    /**
     * Updates login status.
     */
    @Query(
        """
        UPDATE users
        SET isLoggedIn = :isLoggedIn
        WHERE userId = :userId
        """
    )
    suspend fun updateLoginStatus(
        userId: String,
        isLoggedIn: Boolean
    )

    /**
     * Removes all users.
     */
    @Query(
        """
        DELETE FROM users
        """
    )
    suspend fun clearUsers()
}
