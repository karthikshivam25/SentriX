package com.sentrix.core.managers

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * SessionManager
 *
 * Handles:
 * - User login state
 * - Session creation
 * - Session expiration
 * - Authentication status
 * - Last activity tracking
 * - Logout operations
 */
class SessionManager(context: Context) {

    private val preferences: SharedPreferences =
        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    private val _isLoggedIn = MutableStateFlow(isSessionActive())
    val isLoggedIn: StateFlow<Boolean> = _isLoggedIn.asStateFlow()

    /**
     * Create a new session.
     */
    fun createSession(
        userId: String,
        authToken: String
    ) {
        preferences.edit {
            putString(KEY_USER_ID, userId)
            putString(KEY_AUTH_TOKEN, authToken)
            putLong(KEY_LOGIN_TIME, System.currentTimeMillis())
            putLong(KEY_LAST_ACTIVITY, System.currentTimeMillis())
        }

        _isLoggedIn.value = true
    }

    /**
     * Update user activity timestamp.
     */
    fun updateActivity() {
        preferences.edit {
            putLong(KEY_LAST_ACTIVITY, System.currentTimeMillis())
        }
    }

    /**
     * Returns current user id.
     */
    fun getUserId(): String? {
        return preferences.getString(KEY_USER_ID, null)
    }

    /**
     * Returns auth token.
     */
    fun getAuthToken(): String? {
        return preferences.getString(KEY_AUTH_TOKEN, null)
    }

    /**
     * Check whether session is active.
     */
    fun isSessionActive(): Boolean {
        val token = getAuthToken()
        return !token.isNullOrBlank()
    }

    /**
     * Session timeout check.
     */
    fun isSessionExpired(
        timeoutMinutes: Long = DEFAULT_TIMEOUT_MINUTES
    ): Boolean {

        val lastActivity =
            preferences.getLong(KEY_LAST_ACTIVITY, 0L)

        if (lastActivity == 0L) {
            return true
        }

        val elapsed =
            System.currentTimeMillis() - lastActivity

        return elapsed >
                timeoutMinutes * 60 * 1000
    }

    /**
     * Force logout if session expired.
     */
    fun validateSession(
        timeoutMinutes: Long = DEFAULT_TIMEOUT_MINUTES
    ): Boolean {

        if (isSessionExpired(timeoutMinutes)) {
            logout()
            return false
        }

        return true
    }

    /**
     * Logout user.
     */
    fun logout() {
        preferences.edit {
            clear()
        }

        _isLoggedIn.value = false
    }

    /**
     * Returns login timestamp.
     */
    fun getLoginTime(): Long {
        return preferences.getLong(KEY_LOGIN_TIME, 0L)
    }

    /**
     * Returns last activity timestamp.
     */
    fun getLastActivity(): Long {
        return preferences.getLong(KEY_LAST_ACTIVITY, 0L)
    }

    /**
     * Returns session duration.
     */
    fun getSessionDurationMillis(): Long {
        val loginTime = getLoginTime()

        if (loginTime == 0L) return 0L

        return System.currentTimeMillis() - loginTime
    }

    /**
     * Returns session duration in minutes.
     */
    fun getSessionDurationMinutes(): Long {
        return getSessionDurationMillis() / (1000 * 60)
    }

    companion object {

        private const val PREF_NAME = "sentrix_session"

        private const val KEY_USER_ID = "user_id"
        private const val KEY_AUTH_TOKEN = "auth_token"
        private const val KEY_LOGIN_TIME = "login_time"
        private const val KEY_LAST_ACTIVITY = "last_activity"

        const val DEFAULT_TIMEOUT_MINUTES = 30L
    }
}
