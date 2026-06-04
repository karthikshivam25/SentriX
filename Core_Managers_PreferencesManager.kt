package com.sentrix.core.managers

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * PreferencesManager
 *
 * Responsibilities:
 * - Application preferences storage
 * - User settings management
 * - Security preferences
 * - Theme configuration
 * - Feature flags
 * - Persistent key-value storage
 */
class PreferencesManager(
    context: Context
) {

    private val preferences: SharedPreferences =
        context.getSharedPreferences(
            PREF_NAME,
            Context.MODE_PRIVATE
        )

    private val _themeMode =
        MutableStateFlow(getThemeMode())

    val themeMode: StateFlow<String> =
        _themeMode.asStateFlow()

    /**
     * Save String value.
     */
    fun putString(
        key: String,
        value: String
    ) {
        preferences.edit {
            putString(key, value)
        }
    }

    /**
     * Retrieve String value.
     */
    fun getString(
        key: String,
        defaultValue: String = ""
    ): String {
        return preferences.getString(
            key,
            defaultValue
        ) ?: defaultValue
    }

    /**
     * Save Int value.
     */
    fun putInt(
        key: String,
        value: Int
    ) {
        preferences.edit {
            putInt(key, value)
        }
    }

    /**
     * Retrieve Int value.
     */
    fun getInt(
        key: String,
        defaultValue: Int = 0
    ): Int {
        return preferences.getInt(
            key,
            defaultValue
        )
    }

    /**
     * Save Long value.
     */
    fun putLong(
        key: String,
        value: Long
    ) {
        preferences.edit {
            putLong(key, value)
        }
    }

    /**
     * Retrieve Long value.
     */
    fun getLong(
        key: String,
        defaultValue: Long = 0L
    ): Long {
        return preferences.getLong(
            key,
            defaultValue
        )
    }

    /**
     * Save Boolean value.
     */
    fun putBoolean(
        key: String,
        value: Boolean
    ) {
        preferences.edit {
            putBoolean(key, value)
        }
    }

    /**
     * Retrieve Boolean value.
     */
    fun getBoolean(
        key: String,
        defaultValue: Boolean = false
    ): Boolean {
        return preferences.getBoolean(
            key,
            defaultValue
        )
    }

    /**
     * Save Float value.
     */
    fun putFloat(
        key: String,
        value: Float
    ) {
        preferences.edit {
            putFloat(key, value)
        }
    }

    /**
     * Retrieve Float value.
     */
    fun getFloat(
        key: String,
        defaultValue: Float = 0f
    ): Float {
        return preferences.getFloat(
            key,
            defaultValue
        )
    }

    /**
     * Remove specific preference.
     */
    fun remove(
        key: String
    ) {
        preferences.edit {
            remove(key)
        }
    }

    /**
     * Check if key exists.
     */
    fun contains(
        key: String
    ): Boolean {
        return preferences.contains(key)
    }

    /**
     * Clear all preferences.
     */
    fun clearAll() {
        preferences.edit {
            clear()
        }
    }

    /**
     * Theme mode management.
     */
    fun setThemeMode(
        mode: String
    ) {
        putString(
            KEY_THEME_MODE,
            mode
        )

        _themeMode.value = mode
    }

    fun getThemeMode(): String {
        return getString(
            KEY_THEME_MODE,
            THEME_SYSTEM
        )
    }

    /**
     * Security settings.
     */
    fun setBiometricEnabled(
        enabled: Boolean
    ) {
        putBoolean(
            KEY_BIOMETRIC_ENABLED,
            enabled
        )
    }

    fun isBiometricEnabled(): Boolean {
        return getBoolean(
            KEY_BIOMETRIC_ENABLED
        )
    }

    fun setRealtimeProtectionEnabled(
        enabled: Boolean
    ) {
        putBoolean(
            KEY_REALTIME_PROTECTION,
            enabled
        )
    }

    fun isRealtimeProtectionEnabled(): Boolean {
        return getBoolean(
            KEY_REALTIME_PROTECTION,
            true
        )
    }

    fun setNotificationsEnabled(
        enabled: Boolean
    ) {
        putBoolean(
            KEY_NOTIFICATIONS,
            enabled
        )
    }

    fun areNotificationsEnabled(): Boolean {
        return getBoolean(
            KEY_NOTIFICATIONS,
            true
        )
    }

    /**
     * Generate preferences report.
     */
    fun generatePreferencesReport(): String {

        return buildString {

            appendLine("Preferences Report")
            appendLine("------------------------")
            appendLine("Theme Mode           : ${getThemeMode()}")
            appendLine("Biometric Enabled    : ${isBiometricEnabled()}")
            appendLine("Notifications        : ${areNotificationsEnabled()}")
            appendLine("Realtime Protection  : ${isRealtimeProtectionEnabled()}")
            appendLine("Stored Entries       : ${preferences.all.size}")
        }
    }

    companion object {

        private const val PREF_NAME =
            "sentrix_preferences"

        const val KEY_THEME_MODE =
            "theme_mode"

        const val KEY_BIOMETRIC_ENABLED =
            "biometric_enabled"

        const val KEY_REALTIME_PROTECTION =
            "realtime_protection"

        const val KEY_NOTIFICATIONS =
            "notifications_enabled"

        const val THEME_LIGHT =
            "LIGHT"

        const val THEME_DARK =
            "DARK"

        const val THEME_SYSTEM =
            "SYSTEM"
    }
}
