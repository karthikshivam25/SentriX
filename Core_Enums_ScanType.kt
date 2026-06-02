package com.sentrix.core.enums

/**
 * Defines the different scan types available in SentriX
 */
enum class ScanType(
    val displayName: String,
    val description: String
) {

    QUICK_SCAN(
        displayName = "Quick Scan",
        description = "Scans critical areas and active threats quickly"
    ),

    FULL_SCAN(
        displayName = "Full Scan",
        description = "Performs a complete deep scan of the entire device"
    ),

    SMART_SCAN(
        displayName = "Smart Scan",
        description = "Uses AI to scan high-risk areas intelligently"
    ),

    REALTIME_SCAN(
        displayName = "Realtime Scan",
        description = "Continuously monitors threats in real time"
    ),

    APK_SCAN(
        displayName = "APK Scan",
        description = "Scans APK files for malware and suspicious behavior"
    ),

    FILE_SCAN(
        displayName = "File Scan",
        description = "Scans selected files and folders"
    ),

    NETWORK_SCAN(
        displayName = "Network Scan",
        description = "Analyzes network traffic and suspicious connections"
    ),

    CLOUD_SCAN(
        displayName = "Cloud Scan",
        description = "Uploads threat signatures securely for cloud analysis"
    ),

    USB_SCAN(
        displayName = "USB Scan",
        description = "Scans connected external USB devices"
    ),

    MEMORY_SCAN(
        displayName = "Memory Scan",
        description = "Analyzes RAM processes and memory threats"
    ),

    SYSTEM_SCAN(
        displayName = "System Scan",
        description = "Checks core system integrity and vulnerabilities"
    ),

    ROOT_SCAN(
        displayName = "Root Detection Scan",
        description = "Detects root exploits and elevated privilege risks"
    ),

    PHISHING_SCAN(
        displayName = "Phishing Scan",
        description = "Detects phishing links, fake apps, and scam content"
    ),

    PRIVACY_SCAN(
        displayName = "Privacy Scan",
        description = "Checks permissions, trackers, and privacy leaks"
    ),

    WIFI_SECURITY_SCAN(
        displayName = "Wi-Fi Security Scan",
        description = "Analyzes Wi-Fi network vulnerabilities and attacks"
    ),

    BATTERY_OPTIMIZATION_SCAN(
        displayName = "Battery Optimization Scan",
        description = "Finds apps affecting battery and device performance"
    ),

    SCHEDULED_SCAN(
        displayName = "Scheduled Scan",
        description = "Runs automated scans at predefined intervals"
    ),

    CUSTOM_SCAN(
        displayName = "Custom Scan",
        description = "User-defined scan configuration"
    );

    /**
     * Returns true if the scan is deep-level analysis
     */
    fun isDeepScan(): Boolean {
        return this == FULL_SCAN ||
               this == SYSTEM_SCAN ||
               this == MEMORY_SCAN ||
               this == ROOT_SCAN
    }

    /**
     * Returns true if the scan supports realtime monitoring
     */
    fun isRealtime(): Boolean {
        return this == REALTIME_SCAN
    }

    /**
     * Returns true if AI-assisted scanning is used
     */
    fun usesAI(): Boolean {
        return this == SMART_SCAN ||
               this == PHISHING_SCAN ||
               this == NETWORK_SCAN
    }
}
