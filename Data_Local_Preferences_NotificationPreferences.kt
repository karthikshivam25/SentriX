package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * NotificationPreferences
 *
 * Manages all notification-related settings for SentriX.
 *
 * Responsibilities:
 * - Security alert notifications
 * - Threat notifications
 * - Scan completion notifications
 * - Privacy alerts
 * - Device trust alerts
 * - Authentication notifications
 * - Push notification preferences
 * - Notification sound and vibration settings
 */
@Singleton
class NotificationPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_notification_preferences"

        // Master Notification Switch
        private const val KEY_NOTIFICATIONS_ENABLED =
            "notifications_enabled"

        // Threat Alerts
        private const val KEY_THREAT_ALERTS_ENABLED =
            "threat_alerts_enabled"

        // Security Alerts
        private const val KEY_SECURITY_ALERTS_ENABLED =
            "security_alerts_enabled"

        // Scan Notifications
        private const val KEY_SCAN_NOTIFICATIONS_ENABLED =
            "scan_notifications_enabled"

        // Privacy Alerts
        private const val KEY_PRIVACY_ALERTS_ENABLED =
            "privacy_alerts_enabled"

        // Device Trust Alerts
        private const val KEY_DEVICE_TRUST_ALERTS_ENABLED =
            "device_trust_alerts_enabled"

        // Authentication Alerts
        private const val KEY_AUTH_ALERTS_ENABLED =
            "auth_alerts_enabled"

        // Push Notifications
        private const val KEY_PUSH_NOTIFICATIONS_ENABLED =
            "push_notifications_enabled"

        // Notification Sound
        private const val KEY_NOTIFICATION_SOUND_ENABLED =
            "notification_sound_enabled"

        // Notification Vibration
        private const val KEY_NOTIFICATION_VIBRATION_ENABLED =
            "notification_vibration_enabled"

        // Critical Alerts
        private const val KEY_CRITICAL_ALERTS_ONLY =
            "critical_alerts_only"

        // Notification History
        private const val KEY_NOTIFICATION_HISTORY_ENABLED =
            "notification_history_enabled"
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
    // Master Notifications
    // =====================================================

    fun setNotificationsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_NOTIFICATIONS_ENABLED, enabled)
            .apply()
    }

    fun areNotificationsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_NOTIFICATIONS_ENABLED,
            true
        )
    }

    // =====================================================
    // Threat Alerts
    // =====================================================

    fun setThreatAlertsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_THREAT_ALERTS_ENABLED, enabled)
            .apply()
    }

    fun areThreatAlertsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_THREAT_ALERTS_ENABLED,
            true
        )
    }

    // =====================================================
    // Security Alerts
    // =====================================================

    fun setSecurityAlertsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SECURITY_ALERTS_ENABLED, enabled)
            .apply()
    }

    fun areSecurityAlertsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_SECURITY_ALERTS_ENABLED,
            true
        )
    }

    // =====================================================
    // Scan Notifications
    // =====================================================

    fun setScanNotificationsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SCAN_NOTIFICATIONS_ENABLED, enabled)
            .apply()
    }

    fun areScanNotificationsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_SCAN_NOTIFICATIONS_ENABLED,
            true
        )
    }

    // =====================================================
    // Privacy Alerts
    // =====================================================

    fun setPrivacyAlertsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_PRIVACY_ALERTS_ENABLED, enabled)
            .apply()
    }

    fun arePrivacyAlertsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_PRIVACY_ALERTS_ENABLED,
            true
        )
    }

    // =====================================================
    // Device Trust Alerts
    // =====================================================

    fun setDeviceTrustAlertsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DEVICE_TRUST_ALERTS_ENABLED, enabled)
            .apply()
    }

    fun areDeviceTrustAlertsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_DEVICE_TRUST_ALERTS_ENABLED,
            true
        )
    }

    // =====================================================
    // Authentication Alerts
    // =====================================================

    fun setAuthenticationAlertsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_AUTH_ALERTS_ENABLED, enabled)
            .apply()
    }

    fun areAuthenticationAlertsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_AUTH_ALERTS_ENABLED,
            true
        )
    }

    // =====================================================
    // Push Notifications
    // =====================================================

    fun setPushNotificationsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_PUSH_NOTIFICATIONS_ENABLED, enabled)
            .apply()
    }

    fun arePushNotificationsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_PUSH_NOTIFICATIONS_ENABLED,
            true
        )
    }

    // =====================================================
    // Notification Sound
    // =====================================================

    fun setNotificationSoundEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_NOTIFICATION_SOUND_ENABLED, enabled)
            .apply()
    }

    fun isNotificationSoundEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_NOTIFICATION_SOUND_ENABLED,
            true
        )
    }

    // =====================================================
    // Notification Vibration
    // =====================================================

    fun setNotificationVibrationEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_NOTIFICATION_VIBRATION_ENABLED, enabled)
            .apply()
    }

    fun isNotificationVibrationEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_NOTIFICATION_VIBRATION_ENABLED,
            true
        )
    }

    // =====================================================
    // Critical Alerts Only
    // =====================================================

    fun setCriticalAlertsOnly(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_CRITICAL_ALERTS_ONLY, enabled)
            .apply()
    }

    fun isCriticalAlertsOnlyEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_CRITICAL_ALERTS_ONLY,
            false
        )
    }

    // =====================================================
    // Notification History
    // =====================================================

    fun setNotificationHistoryEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_NOTIFICATION_HISTORY_ENABLED, enabled)
            .apply()
    }

    fun isNotificationHistoryEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_NOTIFICATION_HISTORY_ENABLED,
            true
        )
    }

    // =====================================================
    // Utility Methods
    // =====================================================

    /**
     * Clears all notification preferences.
     */
    fun clear() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Resets all notification settings
     * to their default values.
     */
    fun resetToDefaults() {
        preferences.edit()
            .clear()
            .apply()
    }
}
