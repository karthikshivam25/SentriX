package com.sentrix.core.enums

/**
 * Represents notification categories used in SentriX
 */
enum class NotificationType(
    val displayName: String,
    val description: String
) {

    SECURITY_ALERT(
        displayName = "Security Alert",
        description = "Critical security-related notification"
    ),

    THREAT_DETECTED(
        displayName = "Threat Detected",
        description = "Malware or suspicious activity detected"
    ),

    SCAN_COMPLETED(
        displayName = "Scan Completed",
        description = "Device scan completed successfully"
    ),

    SCAN_FAILED(
        displayName = "Scan Failed",
        description = "Scan process encountered an error"
    ),

    VPN_STATUS(
        displayName = "VPN Status",
        description = "VPN connection status update"
    ),

    PRIVACY_ALERT(
        displayName = "Privacy Alert",
        description = "Privacy-related risk or tracking detection"
    ),

    PERMISSION_ALERT(
        displayName = "Permission Alert",
        description = "Sensitive permission usage detected"
    ),

    SYSTEM_HEALTH(
        displayName = "System Health",
        description = "Device performance and health update"
    ),

    BATTERY_OPTIMIZATION(
        displayName = "Battery Optimization",
        description = "Battery usage and optimization suggestion"
    ),

    NETWORK_ACTIVITY(
        displayName = "Network Activity",
        description = "Suspicious or monitored network activity"
    ),

    FIREWALL_EVENT(
        displayName = "Firewall Event",
        description = "Firewall blocked or monitored activity"
    ),

    AI_ANALYSIS(
        displayName = "AI Analysis",
        description = "AI-generated security insight or report"
    ),

    UPDATE_AVAILABLE(
        displayName = "Update Available",
        description = "Application or database update available"
    ),

    BACKUP_STATUS(
        displayName = "Backup Status",
        description = "Backup or restore operation status"
    ),

    ACCOUNT_ACTIVITY(
        displayName = "Account Activity",
        description = "Authentication or account-related event"
    ),

    REMINDER(
        displayName = "Reminder",
        description = "General reminder notification"
    ),

    PROMOTIONAL(
        displayName = "Promotional",
        description = "Feature announcement or promotional content"
    ),

    UNKNOWN(
        displayName = "Unknown",
        description = "Unknown notification category"
    );

    /**
     * Returns true if notification is security related
     */
    fun isSecurityNotification(): Boolean {
        return this == SECURITY_ALERT ||
               this == THREAT_DETECTED ||
               this == PRIVACY_ALERT ||
               this == FIREWALL_EVENT ||
               this == NETWORK_ACTIVITY
    }

    /**
     * Returns true if notification requires user attention
     */
    fun requiresAttention(): Boolean {
        return this == SECURITY_ALERT ||
               this == THREAT_DETECTED ||
               this == PERMISSION_ALERT ||
               this == SCAN_FAILED
    }

    /**
     * Returns true if notification is informational only
     */
    fun isInformational(): Boolean {
        return this == SCAN_COMPLETED ||
               this == UPDATE_AVAILABLE ||
               this == BACKUP_STATUS ||
               this == REMINDER
    }
}
