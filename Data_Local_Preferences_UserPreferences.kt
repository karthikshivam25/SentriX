package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * UserPreferences
 *
 * Manages user-related preferences and settings
 * throughout the SentriX application.
 *
 * Responsibilities:
 * - User profile information
 * - Login status
 * - Session tracking
 * - Theme settings
 * - Language preferences
 * - First launch status
 * - Onboarding completion
 * - User customization options
 *
 * Note:
 * Do not store passwords, authentication tokens,
 * OTPs, or encryption keys in SharedPreferences.
 * Use EncryptedSharedPreferences or Android Keystore.
 */
@Singleton
class UserPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_user_preferences"

        // User Information
        private const val KEY_USER_ID =
            "user_id"

        private const val KEY_USERNAME =
            "username"

        private const val KEY_EMAIL =
            "email"

        private const val KEY_PROFILE_IMAGE =
            "profile_image"

        // Authentication
        private const val KEY_IS_LOGGED_IN =
            "is_logged_in"

        private const val KEY_SESSION_ID =
            "session_id"

        // Application Settings
        private const val KEY_DARK_MODE =
            "dark_mode"

        private const val KEY_LANGUAGE =
            "language"

        // Onboarding
        private const val KEY_FIRST_LAUNCH =
            "first_launch"

        private const val KEY_ONBOARDING_COMPLETED =
            "onboarding_completed"

        // Dashboard Preferences
        private const val KEY_SHOW_SECURITY_SCORE =
            "show_security_score"

        private const val KEY_SHOW_RECENT_THREATS =
            "show_recent_threats"

        private const val KEY_SHOW_SCAN_HISTORY =
            "show_scan_history"

        // Last Activity
        private const val KEY_LAST_ACTIVE_TIME =
            "last_active_time"
    }

    /**
     * SharedPreferences instance.
     */
    private val preferences: SharedPreferences =
        context.getSharedPreferences(
            PREF_NAME,
            Context.MODE_PRIVATE
        )

    // =====================================================
    // User Information
    // =====================================================

    fun saveUserId(userId: String) {
        preferences.edit()
            .putString(KEY_USER_ID, userId)
            .apply()
    }

    fun getUserId(): String? {
        return preferences.getString(
            KEY_USER_ID,
            null
        )
    }

    fun saveUsername(username: String) {
        preferences.edit()
            .putString(KEY_USERNAME, username)
            .apply()
    }

    fun getUsername(): String? {
        return preferences.getString(
            KEY_USERNAME,
            null
        )
    }

    fun saveEmail(email: String) {
        preferences.edit()
            .putString(KEY_EMAIL, email)
            .apply()
    }

    fun getEmail(): String? {
        return preferences.getString(
            KEY_EMAIL,
            null
        )
    }

    fun saveProfileImage(imageUrl: String) {
        preferences.edit()
            .putString(KEY_PROFILE_IMAGE, imageUrl)
            .apply()
    }

    fun getProfileImage(): String? {
        return preferences.getString(
            KEY_PROFILE_IMAGE,
            null
        )
    }

    // =====================================================
    // Authentication
    // =====================================================

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

    fun saveSessionId(sessionId: String) {
        preferences.edit()
            .putString(KEY_SESSION_ID, sessionId)
            .apply()
    }

    fun getSessionId(): String? {
        return preferences.getString(
            KEY_SESSION_ID,
            null
        )
    }

    // =====================================================
    // Theme Settings
    // =====================================================

    fun setDarkMode(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DARK_MODE, enabled)
            .apply()
    }

    fun isDarkModeEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_DARK_MODE,
            false
        )
    }

    // =====================================================
    // Language Settings
    // =====================================================

    /**
     * Examples:
     * "en"
     * "ta"
     * "hi"
     * "fr"
     */
    fun setLanguage(languageCode: String) {
        preferences.edit()
            .putString(KEY_LANGUAGE, languageCode)
            .apply()
    }

    fun getLanguage(): String {
        return preferences.getString(
            KEY_LANGUAGE,
            "en"
        ) ?: "en"
    }

    // =====================================================
    // Onboarding
    // =====================================================

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

    fun setOnboardingCompleted(completed: Boolean) {
        preferences.edit()
            .putBoolean(KEY_ONBOARDING_COMPLETED, completed)
            .apply()
    }

    fun isOnboardingCompleted(): Boolean {
        return preferences.getBoolean(
            KEY_ONBOARDING_COMPLETED,
            false
        )
    }

    // =====================================================
    // Dashboard Preferences
    // =====================================================

    fun setShowSecurityScore(show: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SHOW_SECURITY_SCORE, show)
            .apply()
    }

    fun shouldShowSecurityScore(): Boolean {
        return preferences.getBoolean(
            KEY_SHOW_SECURITY_SCORE,
            true
        )
    }

    fun setShowRecentThreats(show: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SHOW_RECENT_THREATS, show)
            .apply()
    }

    fun shouldShowRecentThreats(): Boolean {
        return preferences.getBoolean(
            KEY_SHOW_RECENT_THREATS,
            true
        )
    }

    fun setShowScanHistory(show: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SHOW_SCAN_HISTORY, show)
            .apply()
    }

    fun shouldShowScanHistory(): Boolean {
        return preferences.getBoolean(
            KEY_SHOW_SCAN_HISTORY,
            true
        )
    }

    // =====================================================
    // Last Activity
    // =====================================================

    fun saveLastActiveTime(timestamp: Long) {
        preferences.edit()
            .putLong(KEY_LAST_ACTIVE_TIME, timestamp)
            .apply()
    }

    fun getLastActiveTime(): Long {
        return preferences.getLong(
            KEY_LAST_ACTIVE_TIME,
            0L
        )
    }

    // =====================================================
    // Utility Methods
    // =====================================================

    /**
     * Clears only authentication data.
     */
    fun clearSession() {
        preferences.edit()
            .remove(KEY_USER_ID)
            .remove(KEY_SESSION_ID)
            .remove(KEY_IS_LOGGED_IN)
            .apply()
    }

    /**
     * Clears all stored user preferences.
     */
    fun clear() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Resets preferences to default values.
     */
    fun resetToDefaults() {
        preferences.edit()
            .clear()
            .apply()
    }
}
