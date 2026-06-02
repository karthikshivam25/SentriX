package com.sentrix.core.enums

/**
 * Represents user access roles in SentriX
 */
enum class UserRole(
    val level: Int,
    val displayName: String,
    val description: String
) {

    GUEST(
        level = 0,
        displayName = "Guest",
        description = "Limited access user with restricted functionality"
    ),

    USER(
        level = 1,
        displayName = "User",
        description = "Standard authenticated user"
    ),

    PREMIUM_USER(
        level = 2,
        displayName = "Premium User",
        description = "User with premium security and advanced features"
    ),

    MODERATOR(
        level = 3,
        displayName = "Moderator",
        description = "User with monitoring and management permissions"
    ),

    SECURITY_ANALYST(
        level = 4,
        displayName = "Security Analyst",
        description = "Access to advanced threat analysis and reports"
    ),

    ADMIN(
        level = 5,
        displayName = "Administrator",
        description = "Full administrative control over the system"
    ),

    SUPER_ADMIN(
        level = 6,
        displayName = "Super Administrator",
        description = "Highest privileged role with unrestricted access"
    ),

    SYSTEM(
        level = 7,
        displayName = "System",
        description = "Internal system-level operations and automation"
    );

    /**
     * Returns true if role has administrative privileges
     */
    fun isAdmin(): Boolean {
        return this == ADMIN ||
               this == SUPER_ADMIN
    }

    /**
     * Returns true if role has elevated security privileges
     */
    fun hasSecurityPrivileges(): Boolean {
        return this == SECURITY_ANALYST ||
               this == ADMIN ||
               this == SUPER_ADMIN
    }

    /**
     * Returns true if role can manage users
     */
    fun canManageUsers(): Boolean {
        return this == MODERATOR ||
               this == ADMIN ||
               this == SUPER_ADMIN
    }

    /**
     * Returns true if role has premium access
     */
    fun hasPremiumAccess(): Boolean {
        return this == PREMIUM_USER ||
               this == SECURITY_ANALYST ||
               this == ADMIN ||
               this == SUPER_ADMIN
    }

    companion object {

        /**
         * Returns UserRole from access level
         */
        fun fromLevel(level: Int): UserRole {
            return values().find { it.level == level } ?: GUEST
        }
    }
}
