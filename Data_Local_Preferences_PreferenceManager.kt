package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * PreferenceManager
 *
 * Centralized SharedPreferences manager for SentriX.
 *
 * Responsible for storing:
 * - User authentication state
 * - Session information
 * - Security settings
 * - Scan preferences
 * - Notification settings
 * - Device trust configuration
 * - Privacy settings
 * - App configuration values
 *
 * Note:
 * Sensitive information such as passwords,
 * tokens, and encryption keys should be stored
 * using EncryptedSharedPreferences or Android Keystore.
 */
@Singleton
class PreferenceManager @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_preferences"

        // Authentication
        private const val KEY_USER_ID = "user_id"
        private const val KEY_SESSION_ID = "session_id"
        private const val KEY_IS_LOGGED_IN = "is_logged_in"

        // Security
        private const val KEY_SECURITY_SCORE = "security_score"
        private const val KEY_CYBER_DEFENSE_LEVEL = "cyber_defense_level"

        // Scanning
        private const val KEY_LAST_SCAN_TIME = "last_scan_time"
        private const val KEY_AUTO_SCAN_ENABLED = "auto_scan_enabled"

        // Notifications
        private const val KEY_NOTIFICATION_ENABLED = "notification_enabled"

        // Privacy
        private const val KEY_PRIVACY_MONITORING_ENABLED =
            "privacy_monitoring_enabled"

        // Device Trust
        private const val KEY_DEVICE_TRUST_SCORE =
            "device_trust_score"

        // App Settings
        private const val KEY_FIRST_LAUNCH = "first_launch"
        private const val KEY_DARK_MODE = "dark_mode"
    }

    /**
     * SharedPreferences instance.
     */
    private val preferences: SharedPreferences =
        context.getSharedPreferences(
            PREF_NAME,
            Context.MODE_PRIVATE
        )

    // ----------------------------------------------------------------
    // Authentication
    // ----------------------------------------------------------------

    fun saveUserId(userId: String) {
        preferences.edit()
            .putString(KEY_USER_ID, userId)
            .apply()
    }

    fun getUserId(): String? {
        return preferences.getString(KEY_USER_ID, null)
    }

    fun saveSessionId(sessionId: String) {
        preferences.edit()
            .putString(KEY_SESSION_ID, sessionId)
            .apply()
    }

    fun getSessionId(): String? {
        return preferences.getString(KEY_SESSION_ID, null)
    }

    fun setLoggedIn(isLoggedIn: Boolean) {
        preferences.edit()
            .putBoolean(KEY_IS_LOGGED_IN, isLoggedIn)
            .apply()
    }

    fun isLoggedIn(): Boolean {
        return preferences.getBoolean(
            KEY_IS_LOGGED_IN,
            false
        )
    }

    // ----------------------------------------------------------------
    // Security Settings
    // ----------------------------------------------------------------

    fun saveSecurityScore(score: Int) {
        preferences.edit()
            .putInt(KEY_SECURITY_SCORE, score)
            .apply()
    }

    fun getSecurityScore(): Int {
        return preferences.getInt(
            KEY_SECURITY_SCORE,
            0
        )
    }

    fun saveCyberDefenseLevel(level: String) {
        preferences.edit()
            .putString(KEY_CYBER_DEFENSE_LEVEL, level)
            .apply()
    }

    fun getCyberDefenseLevel(): String {
        return preferences.getString(
            KEY_CYBER_DEFENSE_LEVEL,
            "STANDARD"
        ) ?: "STANDARD"
    }

    // ----------------------------------------------------------------
    // Scan Settings
    // ----------------------------------------------------------------

    fun saveLastScanTime(timestamp: Long) {
        preferences.edit()
            .putLong(KEY_LAST_SCAN_TIME, timestamp)
            .apply()
    }

    fun getLastScanTime(): Long {
        return preferences.getLong(
            KEY_LAST_SCAN_TIME,
            0L
        )
    }

    fun setAutoScanEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_AUTO_SCAN_ENABLED, enabled)
            .apply()
    }

    fun isAutoScanEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_AUTO_SCAN_ENABLED,
            true
        )
    }

    // ----------------------------------------------------------------
    // Notification Settings
    // ----------------------------------------------------------------

    fun setNotificationEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_NOTIFICATION_ENABLED, enabled)
            .apply()
    }

    fun isNotificationEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_NOTIFICATION_ENABLED,
            true
        )
    }

    // ----------------------------------------------------------------
    // Privacy Settings
    // ----------------------------------------------------------------

    fun setPrivacyMonitoringEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(
                KEY_PRIVACY_MONITORING_ENABLED,
                enabled
            )
            .apply()
    }

    fun isPrivacyMonitoringEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_PRIVACY_MONITORING_ENABLED,
            true
        )
    }

    // ----------------------------------------------------------------
    // Device Trust
    // ----------------------------------------------------------------

    fun saveDeviceTrustScore(score: Int) {
        preferences.edit()
            .putInt(KEY_DEVICE_TRUST_SCORE, score)
            .apply()
    }

    fun getDeviceTrustScore(): Int {
        return preferences.getInt(
            KEY_DEVICE_TRUST_SCORE,
            100
        )
    }

    // ----------------------------------------------------------------
    // App Settings
    // ----------------------------------------------------------------

    fun setFirstLaunch(isFirstLaunch: Boolean) {
        preferences.edit()
            .putBoolean(KEY_FIRST_LAUNCH, isFirstLaunch)
            .apply()
    }

    fun isFirstLaunch(): Boolean {
        return preferences.getBoolean(
            KEY_FIRST_LAUNCH,
            true
        )
    }

    fun setDarkMode(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DARK_MODE, enabled)
            .apply()
    }

    fun isDarkMode(): Boolean {
        return preferences.getBoolean(
            KEY_DARK_MODE,
            false
        )
    }

    // ----------------------------------------------------------------
    // Utility Methods
    // ----------------------------------------------------------------

    /**
     * Clears all stored preferences.
     * Typically used during logout.
     */
    fun clearAll() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Clears only authentication-related data.
     */
    fun clearSession() {
        preferences.edit()
            .remove(KEY_USER_ID)
            .remove(KEY_SESSION_ID)
            .remove(KEY_IS_LOGGED_IN)
            .apply()
    }
}
