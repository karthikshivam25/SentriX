package com.sentrix.core.enums

/**
 * Represents application theme modes
 */
enum class ThemeMode(
    val displayName: String,
    val description: String
) {

    LIGHT(
        displayName = "Light",
        description = "Bright theme optimized for daytime usage"
    ),

    DARK(
        displayName = "Dark",
        description = "Dark theme optimized for low-light environments"
    ),

    AMOLED(
        displayName = "AMOLED",
        description = "Pure black theme for AMOLED displays and battery saving"
    ),

    SYSTEM_DEFAULT(
        displayName = "System Default",
        description = "Automatically follows device system theme"
    ),

    DYNAMIC(
        displayName = "Dynamic",
        description = "Theme adapts dynamically based on wallpaper and system colors"
    ),

    CYBERPUNK(
        displayName = "Cyberpunk",
        description = "Neon futuristic security-inspired visual theme"
    ),

    MINIMAL(
        displayName = "Minimal",
        description = "Clean and distraction-free interface theme"
    );

    /**
     * Returns true if the theme uses dark styling
     */
    fun isDarkTheme(): Boolean {
        return this == DARK ||
               this == AMOLED ||
               this == CYBERPUNK
    }

    /**
     * Returns true if the theme is adaptive
     */
    fun isDynamicTheme(): Boolean {
        return this == SYSTEM_DEFAULT ||
               this == DYNAMIC
    }

    /**
     * Returns true if the theme is battery efficient
     */
    fun isBatteryEfficient(): Boolean {
        return this == AMOLED ||
               this == DARK
    }
}
