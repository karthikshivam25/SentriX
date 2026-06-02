package com.sentrix.core.constants

object NotificationConstants {

    /* ============================================================
     * NOTIFICATION CHANNEL IDS
     * ============================================================ */

    const val CHANNEL_SECURITY_ALERTS =
        "channel_security_alerts"

    const val CHANNEL_SCAN_REPORTS =
        "channel_scan_reports"

    const val CHANNEL_REALTIME_PROTECTION =
        "channel_realtime_protection"

    const val CHANNEL_SYSTEM_STATUS =
        "channel_system_status"

    const val CHANNEL_UPDATES =
        "channel_updates"

    /* ============================================================
     * NOTIFICATION CHANNEL NAMES
     * ============================================================ */

    const val CHANNEL_NAME_SECURITY_ALERTS =
        "Security Alerts"

    const val CHANNEL_NAME_SCAN_REPORTS =
        "Scan Reports"

    const val CHANNEL_NAME_REALTIME_PROTECTION =
        "Realtime Protection"

    const val CHANNEL_NAME_SYSTEM_STATUS =
        "System Status"

    const val CHANNEL_NAME_UPDATES =
        "Application Updates"

    /* ============================================================
     * NOTIFICATION IDS
     * ============================================================ */

    const val ID_SECURITY_ALERT = 1001
    const val ID_SCAN_PROGRESS = 1002
    const val ID_SCAN_COMPLETED = 1003
    const val ID_REALTIME_PROTECTION = 1004
    const val ID_SYSTEM_STATUS = 1005
    const val ID_APP_UPDATE = 1006

    /* ============================================================
     * NOTIFICATION TYPES
     * ============================================================ */

    const val TYPE_SECURITY_ALERT =
        "SECURITY_ALERT"

    const val TYPE_SCAN_REPORT =
        "SCAN_REPORT"

    const val TYPE_REALTIME_EVENT =
        "REALTIME_EVENT"

    const val TYPE_SYSTEM_EVENT =
        "SYSTEM_EVENT"

    const val TYPE_UPDATE =
        "UPDATE"

    /* ============================================================
     * NOTIFICATION PRIORITY
     * ============================================================ */

    const val PRIORITY_LOW = 1
    const val PRIORITY_DEFAULT = 2
    const val PRIORITY_HIGH = 3
    const val PRIORITY_MAX = 4

    /* ============================================================
     * NOTIFICATION TITLES
     * ============================================================ */

    const val TITLE_SECURITY_ALERT =
        "Security Alert"

    const val TITLE_SCAN_COMPLETED =
        "Scan Completed"

    const val TITLE_SCAN_IN_PROGRESS =
        "Scanning Device"

    const val TITLE_REALTIME_PROTECTION =
        "Realtime Protection Active"

    const val TITLE_SYSTEM_STATUS =
        "System Status"

    /* ============================================================
     * NOTIFICATION MESSAGES
     * ============================================================ */

    const val MESSAGE_DEVICE_SECURE =
        "Your device is secure"

    const val MESSAGE_THREAT_DETECTED =
        "Threat detected on your device"

    const val MESSAGE_SCAN_RUNNING =
        "Security scan is currently running"

    const val MESSAGE_SCAN_FINISHED =
        "Security scan completed successfully"

    const val MESSAGE_PROTECTION_ENABLED =
        "Realtime protection enabled"

    const val MESSAGE_PROTECTION_DISABLED =
        "Realtime protection disabled"

    /* ============================================================
     * ACTION BUTTONS
     * ============================================================ */

    const val ACTION_VIEW_REPORT =
        "ACTION_VIEW_REPORT"

    const val ACTION_REMOVE_THREAT =
        "ACTION_REMOVE_THREAT"

    const val ACTION_IGNORE_THREAT =
        "ACTION_IGNORE_THREAT"

    const val ACTION_START_SCAN =
        "ACTION_START_SCAN"

    const val ACTION_STOP_SCAN =
        "ACTION_STOP_SCAN"

    /* ============================================================
     * PENDING INTENT REQUEST CODES
     * ============================================================ */

    const val REQUEST_CODE_SECURITY_ALERT = 2001
    const val REQUEST_CODE_SCAN_REPORT = 2002
    const val REQUEST_CODE_REALTIME = 2003
    const val REQUEST_CODE_UPDATE = 2004

    /* ============================================================
     * GROUPS
     * ============================================================ */

    const val GROUP_SECURITY =
        "group_security"

    const val GROUP_SCANS =
        "group_scans"

    const val GROUP_SYSTEM =
        "group_system"

    /* ============================================================
     * NOTIFICATION STATUS
     * ============================================================ */

    const val STATUS_SENT = "SENT"
    const val STATUS_DELIVERED = "DELIVERED"
    const val STATUS_READ = "READ"
    const val STATUS_DISMISSED = "DISMISSED"

    /* ============================================================
     * FOREGROUND SERVICE NOTIFICATION
     * ============================================================ */

    const val FOREGROUND_SERVICE_TITLE =
        "SentriX Protection Running"

    const val FOREGROUND_SERVICE_MESSAGE =
        "Realtime security protection is active"

}
