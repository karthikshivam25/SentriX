package com.sentrix.core.constants

object VPNConstants {

    /* ============================================================
     * VPN STATUS
     * ============================================================ */

    const val VPN_CONNECTED = "VPN_CONNECTED"
    const val VPN_DISCONNECTED = "VPN_DISCONNECTED"
    const val VPN_CONNECTING = "VPN_CONNECTING"
    const val VPN_RECONNECTING = "VPN_RECONNECTING"
    const val VPN_FAILED = "VPN_FAILED"

    /* ============================================================
     * VPN TYPES
     * ============================================================ */

    const val VPN_TYPE_OPENVPN = "OPENVPN"
    const val VPN_TYPE_WIREGUARD = "WIREGUARD"
    const val VPN_TYPE_IKEV2 = "IKEV2"
    const val VPN_TYPE_L2TP = "L2TP"

    /* ============================================================
     * VPN PROTOCOLS
     * ============================================================ */

    const val PROTOCOL_TCP = "TCP"
    const val PROTOCOL_UDP = "UDP"

    /* ============================================================
     * VPN SERVER CONFIGURATION
     * ============================================================ */

    const val DEFAULT_VPN_PORT = 1194
    const val WIREGUARD_PORT = 51820
    const val IKEV2_PORT = 500

    const val DEFAULT_DNS_PRIMARY = "1.1.1.1"
    const val DEFAULT_DNS_SECONDARY = "8.8.8.8"

    /* ============================================================
     * VPN SECURITY
     * ============================================================ */

    const val VPN_ENCRYPTION_AES_256 = "AES-256"
    const val VPN_HASH_SHA256 = "SHA-256"

    const val KILL_SWITCH_ENABLED = true
    const val DNS_LEAK_PROTECTION_ENABLED = true
    const val IPV6_LEAK_PROTECTION_ENABLED = true

    /* ============================================================
     * VPN PERFORMANCE
     * ============================================================ */

    const val VPN_CONNECT_TIMEOUT = 30_000L
    const val VPN_RECONNECT_DELAY = 5_000L
    const val VPN_PING_INTERVAL = 15_000L

    /* ============================================================
     * VPN NOTIFICATIONS
     * ============================================================ */

    const val VPN_NOTIFICATION_ID = 3001

    const val VPN_NOTIFICATION_CHANNEL =
        "vpn_service_channel"

    const val VPN_NOTIFICATION_TITLE =
        "SentriX VPN Protection"

    const val VPN_NOTIFICATION_MESSAGE =
        "Secure VPN connection is active"

    /* ============================================================
     * VPN ACTIONS
     * ============================================================ */

    const val ACTION_CONNECT_VPN =
        "ACTION_CONNECT_VPN"

    const val ACTION_DISCONNECT_VPN =
        "ACTION_DISCONNECT_VPN"

    const val ACTION_RECONNECT_VPN =
        "ACTION_RECONNECT_VPN"

    /* ============================================================
     * VPN SERVER REGIONS
     * ============================================================ */

    const val REGION_USA = "USA"
    const val REGION_UK = "UK"
    const val REGION_INDIA = "INDIA"
    const val REGION_GERMANY = "GERMANY"
    const val REGION_SINGAPORE = "SINGAPORE"

    /* ============================================================
     * VPN ERROR CODES
     * ============================================================ */

    const val ERROR_AUTH_FAILED = 1001
    const val ERROR_SERVER_UNREACHABLE = 1002
    const val ERROR_TIMEOUT = 1003
    const val ERROR_NETWORK_LOST = 1004

    /* ============================================================
     * VPN TRAFFIC
     * ============================================================ */

    const val TRAFFIC_UPLOAD = "UPLOAD"
    const val TRAFFIC_DOWNLOAD = "DOWNLOAD"

    const val MAX_BANDWIDTH_LIMIT_MBPS = 1000

    /* ============================================================
     * VPN SESSION
     * ============================================================ */

    const val SESSION_ACTIVE = "SESSION_ACTIVE"
    const val SESSION_EXPIRED = "SESSION_EXPIRED"

    const val MAX_SESSION_DURATION_HOURS = 24L

    /* ============================================================
     * VPN LOGGING
     * ============================================================ */

    const val VPN_LOG_TAG = "SENTRIX_VPN"

    const val ENABLE_CONNECTION_LOGS = true
    const val ENABLE_SECURITY_LOGS = true

}
