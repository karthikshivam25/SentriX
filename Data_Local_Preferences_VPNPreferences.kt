package com.sentrix.data.local.preferences

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * VPNPreferences
 *
 * Manages all VPN-related settings and configurations
 * used by SentriX.
 *
 * Responsibilities:
 * - VPN protection settings
 * - Auto-connect configuration
 * - Trusted network management
 * - VPN protocol preferences
 * - Kill switch settings
 * - DNS protection settings
 * - Connection history preferences
 * - VPN notification settings
 *
 * Note:
 * This class stores only user preferences.
 * Sensitive VPN credentials should be stored
 * securely using EncryptedSharedPreferences
 * or Android Keystore.
 */
@Singleton
class VPNPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {

        private const val PREF_NAME = "sentrix_vpn_preferences"

        // VPN Status
        private const val KEY_VPN_ENABLED =
            "vpn_enabled"

        // Auto Connect
        private const val KEY_AUTO_CONNECT =
            "auto_connect"

        // Connect on Public WiFi
        private const val KEY_AUTO_CONNECT_PUBLIC_WIFI =
            "auto_connect_public_wifi"

        // VPN Protocol
        private const val KEY_VPN_PROTOCOL =
            "vpn_protocol"

        // Kill Switch
        private const val KEY_KILL_SWITCH_ENABLED =
            "kill_switch_enabled"

        // DNS Protection
        private const val KEY_DNS_PROTECTION_ENABLED =
            "dns_protection_enabled"

        // Split Tunneling
        private const val KEY_SPLIT_TUNNELING_ENABLED =
            "split_tunneling_enabled"

        // Trusted Networks
        private const val KEY_TRUSTED_NETWORKS =
            "trusted_networks"

        // VPN Notifications
        private const val KEY_VPN_NOTIFICATIONS_ENABLED =
            "vpn_notifications_enabled"

        // Last Connected Server
        private const val KEY_LAST_SERVER =
            "last_server"

        // Connection Timestamp
        private const val KEY_LAST_CONNECTION_TIME =
            "last_connection_time"
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
    // VPN Status
    // =====================================================

    fun setVpnEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_VPN_ENABLED, enabled)
            .apply()
    }

    fun isVpnEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_VPN_ENABLED,
            false
        )
    }

    // =====================================================
    // Auto Connect
    // =====================================================

    fun setAutoConnect(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_AUTO_CONNECT, enabled)
            .apply()
    }

    fun isAutoConnectEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_AUTO_CONNECT,
            true
        )
    }

    /**
     * Automatically connect VPN when
     * public Wi-Fi is detected.
     */
    fun setAutoConnectPublicWifi(enabled: Boolean) {
        preferences.edit()
            .putBoolean(
                KEY_AUTO_CONNECT_PUBLIC_WIFI,
                enabled
            )
            .apply()
    }

    fun isAutoConnectPublicWifiEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_AUTO_CONNECT_PUBLIC_WIFI,
            true
        )
    }

    // =====================================================
    // VPN Protocol
    // =====================================================

    /**
     * Supported values:
     * - WIREGUARD
     * - OPENVPN
     * - IKEV2
     */
    fun setVpnProtocol(protocol: String) {
        preferences.edit()
            .putString(KEY_VPN_PROTOCOL, protocol)
            .apply()
    }

    fun getVpnProtocol(): String {
        return preferences.getString(
            KEY_VPN_PROTOCOL,
            "WIREGUARD"
        ) ?: "WIREGUARD"
    }

    // =====================================================
    // Kill Switch
    // =====================================================

    fun setKillSwitchEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_KILL_SWITCH_ENABLED, enabled)
            .apply()
    }

    fun isKillSwitchEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_KILL_SWITCH_ENABLED,
            true
        )
    }

    // =====================================================
    // DNS Protection
    // =====================================================

    fun setDnsProtectionEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_DNS_PROTECTION_ENABLED, enabled)
            .apply()
    }

    fun isDnsProtectionEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_DNS_PROTECTION_ENABLED,
            true
        )
    }

    // =====================================================
    // Split Tunneling
    // =====================================================

    fun setSplitTunnelingEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_SPLIT_TUNNELING_ENABLED, enabled)
            .apply()
    }

    fun isSplitTunnelingEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_SPLIT_TUNNELING_ENABLED,
            false
        )
    }

    // =====================================================
    // Trusted Networks
    // =====================================================

    /**
     * Stores trusted Wi-Fi SSIDs
     * separated by commas.
     */
    fun saveTrustedNetworks(networks: String) {
        preferences.edit()
            .putString(KEY_TRUSTED_NETWORKS, networks)
            .apply()
    }

    fun getTrustedNetworks(): String {
        return preferences.getString(
            KEY_TRUSTED_NETWORKS,
            ""
        ) ?: ""
    }

    // =====================================================
    // VPN Notifications
    // =====================================================

    fun setVpnNotificationsEnabled(enabled: Boolean) {
        preferences.edit()
            .putBoolean(KEY_VPN_NOTIFICATIONS_ENABLED, enabled)
            .apply()
    }

    fun areVpnNotificationsEnabled(): Boolean {
        return preferences.getBoolean(
            KEY_VPN_NOTIFICATIONS_ENABLED,
            true
        )
    }

    // =====================================================
    // Last Connected Server
    // =====================================================

    fun saveLastServer(server: String) {
        preferences.edit()
            .putString(KEY_LAST_SERVER, server)
            .apply()
    }

    fun getLastServer(): String {
        return preferences.getString(
            KEY_LAST_SERVER,
            ""
        ) ?: ""
    }

    // =====================================================
    // Connection History
    // =====================================================

    fun saveLastConnectionTime(timestamp: Long) {
        preferences.edit()
            .putLong(KEY_LAST_CONNECTION_TIME, timestamp)
            .apply()
    }

    fun getLastConnectionTime(): Long {
        return preferences.getLong(
            KEY_LAST_CONNECTION_TIME,
            0L
        )
    }

    // =====================================================
    // Utility Methods
    // =====================================================

    /**
     * Clears all VPN preferences.
     */
    fun clear() {
        preferences.edit()
            .clear()
            .apply()
    }

    /**
     * Restores default VPN settings.
     */
    fun resetToDefaults() {
        preferences.edit()
            .clear()
            .apply()
    }
}
