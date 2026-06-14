package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SecurityPreferences
 *
 * Handles all security-related application settings
 * and user security preferences for SentriX.
 *
 * Responsibilities:
 * - Real-time protection settings
 * - Auto scan configuration
 * - Threat detection preferences
 * - Security alert controls
 * - Device trust settings
 * - Cyber defense configuration
 * - Security policy management
 */
@Singleton
class SecurityPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_security_preferences"

        // Real-Time Protection
        private const val KEY_REALTIME_PROTECTION =
            "realtime_protection"

        // Auto Scan
        private const val KEY_AUTO_SCAN =
            "auto_scan"

        // Scan Frequency
        private const val KEY_SCAN_FREQUENCY =
            "scan_frequency"

        // Threat Detection
        private const val KEY_THREAT_DETECTION =
            "threat_detection"

        // Security Alerts
        private const val KEY_SECURITY_ALERTS =
            "security_alerts"

        // Device Trust Monitoring
        private const val KEY_DEVICE_TRUST_MONITORING =
            "device_trust_monitoring"

        // Cyber Defense Mode
        private const val KEY_CYBER_DEFENSE_MODE =
            "cyber_defense_mode"

        // Security Score Threshold
        private const val KEY_SECURITY_SCORE_THRESHOLD =
            "security_score_threshold"

        // Network Protection
        private const val KEY_NETWORK_PROTECTION =
            "network_protection"

        // Root Detection
        private const val KEY_ROOT_DETECTION =
            "root_detection"
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
    // Real-Time Protection
    // =====================================================

    /**
     * Enable or disable real-time protection.
     */
    fun setRealtimeProtectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_REALTIME_PROTECTION, enabled)
            .apply()
    }

    fun isRealtimeProtectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_REALTIME_PROTECTION,
            true
        )
    }

    // =====================================================
    // Auto Scan
    // =====================================================

    /**
     * Enable or disable automatic scans.
     */
    fun setAutoScanEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_AUTO_SCAN, enabled)
            .apply()
    }

    fun isAutoScanEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_AUTO_SCAN,
            true
        )
    }

    /**
     * Scan frequency values:
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
    // Threat Detection
    // =====================================================

    /**
     * Enable advanced threat detection.
     */
    fun setThreatDetectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_THREAT_DETECTION, enabled)
            .apply()
    }

    fun isThreatDetectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_THREAT_DETECTION,
            true
        )
    }

    // =====================================================
    // Security Alerts
    // =====================================================

    /**
     * Enable security notifications and alerts.
     */
    fun setSecurityAlertsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SECURITY_ALERTS, enabled)
            .apply()
    }

    fun isSecurityAlertsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_SECURITY_ALERTS,
            true
        )
    }

    // =====================================================
    // Device Trust Monitoring
    // =====================================================

    /**
     * Enable continuous device trust monitoring.
     */
    fun setDeviceTrustMonitoringEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DEVICE_TRUST_MONITORING, enabled)
            .apply()
    }

    fun isDeviceTrustMonitoringEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_DEVICE_TRUST_MONITORING,
            true
        )
    }

    // =====================================================
    // Cyber Defense Configuration
    // =====================================================

    /**
     * Defense modes:
     * BASIC
     * STANDARD
     * ADVANCED
     * MAXIMUM
     * EMERGENCY
     */
    fun setCyberDefenseMode(mode: String) {
        preferences.edit()
            .putString(KEY_CYBER_DEFENSE_MODE, mode)
            .apply()
    }

    fun getCyberDefenseMode(): String {
        return preferences.getString(
            KEY_CYBER_DEFENSE_MODE,
            "STANDARD"
        ) ?: "STANDARD"
    }

    // =====================================================
    // Security Score Threshold
    // =====================================================

    /**
     * Minimum acceptable security score.
     * Default = 70
     */
    fun setSecurityScoreThreshold(score: Int) {
        preferences.edit()
            .putInt(KEY_SECURITY_SCORE_THRESHOLD, score)
            .apply()
    }

    fun getSecurityScoreThreshold(): Int {
        return preferences.getInt(
            KEY_SECURITY_SCORE_THRESHOLD,
            70
        )
    }

    // =====================================================
    // Network Protection
    // =====================================================

    /**
     * Enable network threat monitoring.
     */
    fun setNetworkProtectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_NETWORK_PROTECTION, enabled)
            .apply()
    }

    fun isNetworkProtectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_NETWORK_PROTECTION,
            true
        )
    }

    // =====================================================
    // Root Detection
    // =====================================================

    /**
     * Enable root/jailbreak detection.
     */
    fun setRootDetectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_ROOT_DETECTION, enabled)
            .apply()
    }

    fun isRootDetectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_ROOT_DETECTION,
            true
        )
    }

    // =====================================================
    // Utility Methods
    // =====================================================

    /**
     * Reset all security preferences
     * to their default values.
     */
    fun resetToDefaults() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Remove all stored security settings.
     */
    fun clear() {
        preferences.edit()
            .clear()
            .apply()
    }
}
