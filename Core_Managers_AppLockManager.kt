package com.sentrix.core.managers

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * AppLockManager
 *
 * Responsibilities:
 * - App lock management
 * - Protected application tracking
 * - PIN verification
 * - Lock state monitoring
 * - Biometric preference management
 * - Security reporting
 *
 * NOTE:
 * Android does not allow third-party apps to
 * directly lock other applications without
 * Accessibility Service, Device Owner APIs,
 * or specialized permissions.
 *
 * This manager provides the core logic layer
 * for SentriX App Lock functionality.
 */
class AppLockManager(
    private val context: Context
) {

    private val preferences =
        context.getSharedPreferences(
            PREF_NAME,
            Context.MODE_PRIVATE
        )

    private val _lockEnabled =
        MutableStateFlow(
            preferences.getBoolean(
                KEY_APP_LOCK_ENABLED,
                false
            )
        )

    val lockEnabled: StateFlow<Boolean> =
        _lockEnabled.asStateFlow()

    /**
     * Enable App Lock.
     */
    fun enableAppLock() {

        preferences.edit {
            putBoolean(
                KEY_APP_LOCK_ENABLED,
                true
            )
        }

        _lockEnabled.value = true
    }

    /**
     * Disable App Lock.
     */
    fun disableAppLock() {

        preferences.edit {
            putBoolean(
                KEY_APP_LOCK_ENABLED,
                false
            )
        }

        _lockEnabled.value = false
    }

    /**
     * Check App Lock status.
     */
    fun isAppLockEnabled(): Boolean {
        return _lockEnabled.value
    }

    /**
     * Set PIN.
     */
    fun setPin(
        pin: String
    ): Boolean {

        if (pin.length < 4) {
            return false
        }

        preferences.edit {
            putString(
                KEY_APP_LOCK_PIN,
                pin
            )
        }

        return true
    }

    /**
     * Verify PIN.
     */
    fun verifyPin(
        pin: String
    ): Boolean {

        val savedPin =
            preferences.getString(
                KEY_APP_LOCK_PIN,
                null
            )

        return savedPin == pin
    }

    /**
     * Remove PIN.
     */
    fun removePin() {

        preferences.edit {
            remove(KEY_APP_LOCK_PIN)
        }
    }

    /**
     * Protect application.
     */
    fun lockApplication(
        packageName: String
    ) {

        val apps =
            getLockedApplications()
                .toMutableSet()

        apps.add(packageName)

        saveLockedApps(apps)
    }

    /**
     * Remove protection.
     */
    fun unlockApplication(
        packageName: String
    ) {

        val apps =
            getLockedApplications()
                .toMutableSet()

        apps.remove(packageName)

        saveLockedApps(apps)
    }

    /**
     * Check protected app.
     */
    fun isApplicationLocked(
        packageName: String
    ): Boolean {

        return getLockedApplications()
            .contains(packageName)
    }

    /**
     * Get protected apps.
     */
    fun getLockedApplications(): Set<String> {

        return preferences.getStringSet(
            KEY_LOCKED_APPS,
            emptySet()
        ) ?: emptySet()
    }

    /**
     * Enable biometric unlock.
     */
    fun enableBiometricUnlock() {

        preferences.edit {
            putBoolean(
                KEY_BIOMETRIC_UNLOCK,
                true
            )
        }
    }

    /**
     * Disable biometric unlock.
     */
    fun disableBiometricUnlock() {

        preferences.edit {
            putBoolean(
                KEY_BIOMETRIC_UNLOCK,
                false
            )
        }
    }

    /**
     * Check biometric setting.
     */
    fun isBiometricEnabled(): Boolean {

        return preferences.getBoolean(
            KEY_BIOMETRIC_UNLOCK,
            false
        )
    }

    /**
     * Generate security report.
     */
    fun generateReport(): String {

        return buildString {

            appendLine("App Lock Report")
            appendLine("---------------------------")
            appendLine(
                "Enabled         : ${
                    isAppLockEnabled()
                }"
            )

            appendLine(
                "Locked Apps     : ${
                    getLockedApplications().size
                }"
            )

            appendLine(
                "Biometric Unlock: ${
                    isBiometricEnabled()
                }"
            )

            appendLine(
                "PIN Configured  : ${
                    hasPinConfigured()
                }"
            )
        }
    }

    /**
     * PIN status.
     */
    fun hasPinConfigured(): Boolean {

        return !preferences
            .getString(
                KEY_APP_LOCK_PIN,
                null
            )
            .isNullOrBlank()
    }

    /**
     * Save locked applications.
     */
    private fun saveLockedApps(
        apps: Set<String>
    ) {

        preferences.edit {
            putStringSet(
                KEY_LOCKED_APPS,
                apps
            )
        }
    }

    companion object {

        private const val PREF_NAME =
            "sentrix_app_lock"

        private const val KEY_APP_LOCK_ENABLED =
            "app_lock_enabled"

        private const val KEY_APP_LOCK_PIN =
            "app_lock_pin"

        private const val KEY_LOCKED_APPS =
            "locked_apps"

        private const val KEY_BIOMETRIC_UNLOCK =
            "biometric_unlock"
    }
}
