package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * PrivacyPreferences
 *
 * Manages all privacy-related settings for SentriX.
 *
 * Responsibilities:
 * - Privacy monitoring settings
 * - App permission monitoring
 * - Clipboard protection
 * - Camera & microphone monitoring
 * - Tracker detection settings
 * - Data collection preferences
 * - Privacy alert controls
 * - Privacy scan configuration
 *
 * Note:
 * This class stores user privacy preferences only.
 * Sensitive information should never be stored in
 * plain SharedPreferences.
 */
@Singleton
class PrivacyPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_privacy_preferences"

        // Privacy Monitoring
        private const val KEY_PRIVACY_MONITORING_ENABLED =
            "privacy_monitoring_enabled"

        // Permission Monitoring
        private const val KEY_PERMISSION_MONITORING_ENABLED =
            "permission_monitoring_enabled"

        // Clipboard Protection
        private const val KEY_CLIPBOARD_PROTECTION_ENABLED =
            "clipboard_protection_enabled"

        // Camera Monitoring
        private const val KEY_CAMERA_MONITORING_ENABLED =
            "camera_monitoring_enabled"

        // Microphone Monitoring
        private const val KEY_MICROPHONE_MONITORING_ENABLED =
            "microphone_monitoring_enabled"

        // Tracker Detection
        private const val KEY_TRACKER_DETECTION_ENABLED =
            "tracker_detection_enabled"

        // Privacy Alerts
        private const val KEY_PRIVACY_ALERTS_ENABLED =
            "privacy_alerts_enabled"

        // Automatic Privacy Scans
        private const val KEY_AUTO_PRIVACY_SCAN_ENABLED =
            "auto_privacy_scan_enabled"

        // Scan Frequency
        private const val KEY_PRIVACY_SCAN_FREQUENCY =
            "privacy_scan_frequency"

        // Analytics Sharing
        private const val KEY_ANALYTICS_SHARING_ENABLED =
            "analytics_sharing_enabled"

        // Data Collection
        private const val KEY_DATA_COLLECTION_ENABLED =
            "data_collection_enabled"

        // Privacy Score Threshold
        private const val KEY_PRIVACY_SCORE_THRESHOLD =
            "privacy_score_threshold"
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
    // Privacy Monitoring
    // =====================================================

    fun setPrivacyMonitoringEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_PRIVACY_MONITORING_ENABLED, enabled)
            .apply()
    }

    fun isPrivacyMonitoringEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_PRIVACY_MONITORING_ENABLED,
            true
        )
    }

    // =====================================================
    // Permission Monitoring
    // =====================================================

    fun setPermissionMonitoringEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_PERMISSION_MONITORING_ENABLED, enabled)
            .apply()
    }

    fun isPermissionMonitoringEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_PERMISSION_MONITORING_ENABLED,
            true
        )
    }

    // =====================================================
    // Clipboard Protection
    // =====================================================

    fun setClipboardProtectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_CLIPBOARD_PROTECTION_ENABLED, enabled)
            .apply()
    }

    fun isClipboardProtectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_CLIPBOARD_PROTECTION_ENABLED,
            true
        )
    }

    // =====================================================
    // Camera Monitoring
    // =====================================================

    fun setCameraMonitoringEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_CAMERA_MONITORING_ENABLED, enabled)
            .apply()
    }

    fun isCameraMonitoringEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_CAMERA_MONITORING_ENABLED,
            true
        )
    }

    // =====================================================
    // Microphone Monitoring
    // =====================================================

    fun setMicrophoneMonitoringEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_MICROPHONE_MONITORING_ENABLED, enabled)
            .apply()
    }

    fun isMicrophoneMonitoringEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_MICROPHONE_MONITORING_ENABLED,
            true
        )
    }

    // =====================================================
    // Tracker Detection
    // =====================================================

    fun setTrackerDetectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_TRACKER_DETECTION_ENABLED, enabled)
            .apply()
    }

    fun isTrackerDetectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_TRACKER_DETECTION_ENABLED,
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
    // Automatic Privacy Scanning
    // =====================================================

    fun setAutoPrivacyScanEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_AUTO_PRIVACY_SCAN_ENABLED, enabled)
            .apply()
    }

    fun isAutoPrivacyScanEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_AUTO_PRIVACY_SCAN_ENABLED,
            true
        )
    }

    /**
     * Supported values:
     * DAILY
     * WEEKLY
     * MONTHLY
     */
    fun setPrivacyScanFrequency(frequency: String) {
        preferences.edit()
            .putString(KEY_PRIVACY_SCAN_FREQUENCY, frequency)
            .apply()
    }

    fun getPrivacyScanFrequency(): String {
        return preferences.getString(
            KEY_PRIVACY_SCAN_FREQUENCY,
            "WEEKLY"
        ) ?: "WEEKLY"
    }

    // =====================================================
    // Analytics & Data Collection
    // =====================================================

    fun setAnalyticsSharingEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_ANALYTICS_SHARING_ENABLED, enabled)
            .apply()
    }

    fun isAnalyticsSharingEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_ANALYTICS_SHARING_ENABLED,
            false
        )
    }

    fun setDataCollectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DATA_COLLECTION_ENABLED, enabled)
            .apply()
    }

    fun isDataCollectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_DATA_COLLECTION_ENABLED,
            false
        )
    }

    // =====================================================
    // Privacy Score Threshold
    // =====================================================

    /**
     * Minimum acceptable privacy score.
     * Range: 0 - 100
     */
    fun setPrivacyScoreThreshold(score: Int) {
        preferences.edit()
            .putInt(KEY_PRIVACY_SCORE_THRESHOLD, score)
            .apply()
    }

    fun getPrivacyScoreThreshold(): Int {
        return preferences.getInt(
            KEY_PRIVACY_SCORE_THRESHOLD,
            75
        )
    }

    // =====================================================
    // Utility Methods
    // =====================================================

    /**
     * Clears all stored privacy settings.
     */
    fun clear() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Restores default privacy settings.
     */
    fun resetToDefaults() {
        preferences.edit()
            .clear()
            .apply()
    }
}
