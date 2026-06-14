package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ScanPreferences
 *
 * Manages all scan-related settings and configurations
 * for the SentriX security engine.
 *
 * Responsibilities:
 * - Auto scan settings
 * - Scan scheduling
 * - Scan frequency management
 * - Scan type preferences
 * - Background scanning
 * - Battery optimization settings
 * - Wi-Fi only scanning
 * - Scan result retention
 */
@Singleton
class ScanPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_scan_preferences"

        // Auto Scan Settings
        private const val KEY_AUTO_SCAN_ENABLED =
            "auto_scan_enabled"

        // Scan Frequency
        private const val KEY_SCAN_FREQUENCY =
            "scan_frequency"

        // Preferred Scan Type
        private const val KEY_DEFAULT_SCAN_TYPE =
            "default_scan_type"

        // Last Scan Information
        private const val KEY_LAST_SCAN_TIME =
            "last_scan_time"

        // Background Scan
        private const val KEY_BACKGROUND_SCAN_ENABLED =
            "background_scan_enabled"

        // Battery Optimization
        private const val KEY_BATTERY_OPTIMIZED_SCAN =
            "battery_optimized_scan"

        // WiFi Only Scanning
        private const val KEY_WIFI_ONLY_SCAN =
            "wifi_only_scan"

        // Scheduled Scan Time
        private const val KEY_SCHEDULED_SCAN_HOUR =
            "scheduled_scan_hour"

        private const val KEY_SCHEDULED_SCAN_MINUTE =
            "scheduled_scan_minute"

        // Scan History Retention
        private const val KEY_SCAN_HISTORY_RETENTION_DAYS =
            "scan_history_retention_days"

        // Scan Notifications
        private const val KEY_SCAN_NOTIFICATION_ENABLED =
            "scan_notification_enabled"
    }

    private val preferences: SharedPreferences =
        context.getSharedPreferences(
            PREF_NAME,
            Context.MODE_PRIVATE
        )

    // =====================================================
    // Auto Scan
    // =====================================================

    /**
     * Enable or disable automatic scanning.
     */
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

    // =====================================================
    // Scan Frequency
    // =====================================================

    /**
     * Available values:
     * DAILY
     * WEEKLY
     * MONTHLY
     */
    fun setScanFrequency(frequency: String) {
        preferences.edit()
            .putString(KEY_SCAN_FREQUENCY, frequency)
            .apply()
    }

    fun getScanFrequency(): String {
        return preferences.getString(
            KEY_SCAN_FREQUENCY,
            "DAILY"
        ) ?: "DAILY"
    }

    // =====================================================
    // Default Scan Type
    // =====================================================

    /**
     * Available values:
     * QUICK_SCAN
     * FULL_SCAN
     * APP_SCAN
     * NETWORK_SCAN
     * PRIVACY_SCAN
     */
    fun setDefaultScanType(scanType: String) {
        preferences.edit()
            .putString(KEY_DEFAULT_SCAN_TYPE, scanType)
            .apply()
    }

    fun getDefaultScanType(): String {
        return preferences.getString(
            KEY_DEFAULT_SCAN_TYPE,
            "QUICK_SCAN"
        ) ?: "QUICK_SCAN"
    }

    // =====================================================
    // Last Scan Information
    // =====================================================

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

    // =====================================================
    // Background Scanning
    // =====================================================

    fun setBackgroundScanEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_BACKGROUND_SCAN_ENABLED, enabled)
            .apply()
    }

    fun isBackgroundScanEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_BACKGROUND_SCAN_ENABLED,
            true
        )
    }

    // =====================================================
    // Battery Optimization
    // =====================================================

    /**
     * Enables low-power scanning mode.
     */
    fun setBatteryOptimizedScan(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_BATTERY_OPTIMIZED_SCAN, enabled)
            .apply()
    }

    fun isBatteryOptimizedScanEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_BATTERY_OPTIMIZED_SCAN,
            true
        )
    }

    // =====================================================
    // Wi-Fi Only Scan
    // =====================================================

    /**
     * Allow scans only when connected to Wi-Fi.
     */
    fun setWifiOnlyScan(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_WIFI_ONLY_SCAN, enabled)
            .apply()
    }

    fun isWifiOnlyScanEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_WIFI_ONLY_SCAN,
            false
        )
    }

    // =====================================================
    // Scheduled Scan Time
    // =====================================================

    fun setScheduledScanHour(hour: Int) {
        preferences.edit()
            .putInt(KEY_SCHEDULED_SCAN_HOUR, hour)
            .apply()
    }

    fun getScheduledScanHour(): Int {
        return preferences.getInt(
            KEY_SCHEDULED_SCAN_HOUR,
            2
        ) // 2 AM default
    }

    fun setScheduledScanMinute(minute: Int) {
        preferences.edit()
            .putInt(KEY_SCHEDULED_SCAN_MINUTE, minute)
            .apply()
    }

    fun getScheduledScanMinute(): Int {
        return preferences.getInt(
            KEY_SCHEDULED_SCAN_MINUTE,
            0
        )
    }

    // =====================================================
    // Scan History Retention
    // =====================================================

    /**
     * Number of days scan history is retained.
     */
    fun setScanHistoryRetentionDays(days: Int) {
        preferences.edit()
            .putInt(KEY_SCAN_HISTORY_RETENTION_DAYS, days)
            .apply()
    }

    fun getScanHistoryRetentionDays(): Int {
        return preferences.getInt(
            KEY_SCAN_HISTORY_RETENTION_DAYS,
            90
        )
    }

    // =====================================================
    // Scan Notifications
    // =====================================================

    fun setScanNotificationEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SCAN_NOTIFICATION_ENABLED, enabled)
            .apply()
    }

    fun isScanNotificationEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_SCAN_NOTIFICATION_ENABLED,
            true
        )
    }

    // =====================================================
    // Utility Methods
    // =====================================================

    /**
     * Clears all scan preferences.
     */
    fun clear() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Resets scan preferences to default values.
     */
    fun resetToDefaults() {
        preferences.edit()
            .clear()
            .apply()
    }
}
