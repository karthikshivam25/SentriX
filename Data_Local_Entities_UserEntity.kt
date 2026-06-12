package com.sentrix.data.local.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * UserEntity
 *
 * Represents a SentriX user
 * stored in the local database.
 *
 * Responsibilities:
 * - Store user profile data
 * - Track authentication status
 * - Support user preferences
 * - Manage account information
 */
@Entity(
    tableName = "users"
)
data class UserEntity(

    /**
     * Unique user identifier.
     */
    @PrimaryKey
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
     * Mobile number.
     */
    val phoneNumber: String?,

    /**
     * Profile image URL.
     */
    val profileImageUrl: String?,

    /**
     * User role.
     */
    val role: String,

    /**
     * Account status.
     */
    val accountStatus: String,

    /**
     * Security score.
     */
    val securityScore: Int,

    /**
     * Privacy score.
     */
    val privacyScore: Int,

    /**
     * Two-factor authentication status.
     */
    val isTwoFactorEnabled: Boolean,

    /**
     * Email verification status.
     */
    val isEmailVerified: Boolean,

    /**
     * Login status.
     */
    val isLoggedIn: Boolean,

    /**
     * Account creation timestamp.
     */
    val createdAt: Long,

    /**
     * Last login timestamp.
     */
    val lastLoginAt: Long?,

    /**
     * Last profile update timestamp.
     */
    val updatedAt: Long?
)
