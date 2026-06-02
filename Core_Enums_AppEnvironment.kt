package com.sentrix.core.enums

/**
 * Represents application runtime environments
 */
enum class AppEnvironment(
    val displayName: String,
    val description: String
) {

    DEVELOPMENT(
        displayName = "Development",
        description = "Environment used for active development and debugging"
    ),

    TESTING(
        displayName = "Testing",
        description = "Environment used for QA testing and validation"
    ),

    STAGING(
        displayName = "Staging",
        description = "Pre-production environment for final verification"
    ),

    PRODUCTION(
        displayName = "Production",
        description = "Live environment used by end users"
    ),

    DEMO(
        displayName = "Demo",
        description = "Environment used for demonstrations and presentations"
    ),

    SANDBOX(
        displayName = "Sandbox",
        description = "Isolated environment for experimentation and simulations"
    ),

    MAINTENANCE(
        displayName = "Maintenance",
        description = "Environment temporarily under maintenance or updates"
    ),

    OFFLINE(
        displayName = "Offline",
        description = "Environment running without network connectivity"
    );

    /**
     * Returns true if environment is safe for testing/debugging
     */
    fun isNonProduction(): Boolean {
        return this == DEVELOPMENT ||
               this == TESTING ||
               this == STAGING ||
               this == SANDBOX ||
               this == DEMO
    }

    /**
     * Returns true if debugging features should be enabled
     */
    fun allowsDebugging(): Boolean {
        return this == DEVELOPMENT ||
               this == TESTING ||
               this == SANDBOX
    }

    /**
     * Returns true if environment is user-facing
     */
    fun isLiveEnvironment(): Boolean {
        return this == PRODUCTION
    }

    /**
     * Returns true if environment is temporarily unavailable
     */
    fun isRestricted(): Boolean {
        return this == MAINTENANCE ||
               this == OFFLINE
    }
}
