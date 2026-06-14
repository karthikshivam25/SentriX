package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import androidx.appcompat.app.AppCompatDelegate
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ThemePreferences
 *
 * Manages theme and appearance-related settings
 * throughout the SentriX application.
 *
 * Responsibilities:
 * - Dark mode settings
 * - Theme mode selection
 * - Dynamic color settings
 * - Font scaling preferences
 * - Dashboard appearance settings
 * - Security dashboard theme customization
 *
 * Used By:
 * - Settings Screen
 * - Dashboard
 * - Theme Manager
 * - App Startup Configuration
 */
@Singleton
class ThemePreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_theme_preferences"

        // Theme Mode
        private const val KEY_THEME_MODE =
            "theme_mode"

        // Dynamic Colors (Material You)
        private const val KEY_DYNAMIC_COLORS =
            "dynamic_colors"

        // AMOLED Dark Theme
        private const val KEY_AMOLED_THEME =
            "amoled_theme"

        // Font Scale
        private const val KEY_FONT_SCALE =
            "font_scale"

        // Dashboard Animations
        private const val KEY_DASHBOARD_ANIMATIONS =
            "dashboard_animations"

        // Security Status Glow Effects
        private const val KEY_SECURITY_EFFECTS =
            "security_effects"
    }

    /**
     * SharedPreferences instance.
     */
    private val preferences: SharedPreferences =
        context.getSharedPreferences(
            PREF_NAME,
            Context.MODE_PRIVATE
        )

    /**
     * Supported theme modes.
     */
    enum class ThemeMode {
        LIGHT,
        DARK,
        SYSTEM
    }

    // =====================================================
    // Theme Mode
    // =====================================================

    fun setThemeMode(mode: ThemeMode) {
        preferences.edit()
            .putString(KEY_THEME_MODE, mode.name)
            .apply()
    }

    fun getThemeMode(): ThemeMode {

        val value = preferences.getString(
            KEY_THEME_MODE,
            ThemeMode.SYSTEM.name
        ) ?: ThemeMode.SYSTEM.name

        return ThemeMode.valueOf(value)
    }

    /**
     * Apply selected theme mode.
     */
    fun applyTheme() {
        when (getThemeMode()) {

            ThemeMode.LIGHT ->
                AppCompatDelegate.setDefaultNightMode(
                    AppCompatDelegate.MODE_NIGHT_NO
                )

            ThemeMode.DARK ->
                AppCompatDelegate.setDefaultNightMode(
                    AppCompatDelegate.MODE_NIGHT_YES
                )

            ThemeMode.SYSTEM ->
                AppCompatDelegate.setDefaultNightMode(
                    AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
                )
        }
    }

    // =====================================================
    // Dynamic Colors
    // =====================================================

    fun setDynamicColorsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DYNAMIC_COLORS, enabled)
            .apply()
    }

    fun isDynamicColorsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_DYNAMIC_COLORS,
            true
        )
    }

    // =====================================================
    // AMOLED Theme
    // =====================================================

    fun setAmoledThemeEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_AMOLED_THEME, enabled)
            .apply()
    }

    fun isAmoledThemeEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_AMOLED_THEME,
            false
        )
    }

    // =====================================================
    // Font Scaling
    // =====================================================

    /**
     * Supported values:
     * 0.85f - Small
     * 1.0f  - Default
     * 1.15f - Large
     * 1.30f - Extra Large
     */
    fun setFontScale(scale: Float) {
        preferences.edit()
            .putFloat(KEY_FONT_SCALE, scale)
            .apply()
    }

    fun getFontScale(): Float {
        return preferences.getFloat(
            KEY_FONT_SCALE,
            1.0f
        )
    }

    // =====================================================
    // Dashboard Animations
    // =====================================================

    fun setDashboardAnimationsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DASHBOARD_ANIMATIONS, enabled)
            .apply()
    }

    fun areDashboardAnimationsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_DASHBOARD_ANIMATIONS,
            true
        )
    }

    // =====================================================
    // Security Effects
    // =====================================================

    /**
     * Enables visual effects such as:
     * - Security score glow
     * - Threat pulse animations
     * - Dashboard status effects
     */
    fun setSecurityEffectsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SECURITY_EFFECTS, enabled)
            .apply()
    }

    fun areSecurityEffectsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_SECURITY_EFFECTS,
            true
        )
    }

    // =====================================================
    // Utility Methods
    // =====================================================

    /**
     * Clears all stored theme preferences.
     */
    fun clear() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Restores default appearance settings.
     */
    fun resetToDefaults() {
        preferences.edit()
            .clear()
            .apply()
    }
}
