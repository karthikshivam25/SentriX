package com.sentrix.core.enums

/**
 * Represents possible sources of detected threats
 */
enum class ThreatSource(
    val displayName: String,
    val description: String
) {

    APPLICATION(
        displayName = "Application",
        description = "Threat originated from an installed application"
    ),

    APK_FILE(
        displayName = "APK File",
        description = "Threat detected inside an APK package"
    ),

    DOWNLOADED_FILE(
        displayName = "Downloaded File",
        description = "Threat found in a downloaded file"
    ),

    EMAIL_ATTACHMENT(
        displayName = "Email Attachment",
        description = "Threat delivered through an email attachment"
    ),

    WEB_DOWNLOAD(
        displayName = "Web Download",
        description = "Threat originated from an internet download"
    ),

    WEBSITE(
        displayName = "Website",
        description = "Threat associated with a malicious or unsafe website"
    ),

    NETWORK(
        displayName = "Network",
        description = "Threat detected through network activity"
    ),

    WIFI(
        displayName = "Wi-Fi",
        description = "Threat associated with insecure Wi-Fi connections"
    ),

    BLUETOOTH(
        displayName = "Bluetooth",
        description = "Threat detected through Bluetooth communication"
    ),

    USB_DEVICE(
        displayName = "USB Device",
        description = "Threat originated from an external USB device"
    ),

    CLOUD_STORAGE(
        displayName = "Cloud Storage",
        description = "Threat detected from synced cloud storage content"
    ),

    SYSTEM_PROCESS(
        displayName = "System Process",
        description = "Threat found within system-level processes"
    ),

    THIRD_PARTY_LIBRARY(
        displayName = "Third-Party Library",
        description = "Threat introduced through external SDKs or libraries"
    ),

    ADVERTISEMENT(
        displayName = "Advertisement",
        description = "Threat delivered through malicious advertisements"
    ),

    PHISHING_LINK(
        displayName = "Phishing Link",
        description = "Threat detected from phishing URLs or fake pages"
    ),

    QR_CODE(
        displayName = "QR Code",
        description = "Threat originated from a malicious QR code"
    ),

    UNKNOWN(
        displayName = "Unknown",
        description = "Threat source could not be identified"
    );

    /**
     * Returns true if the source is internet-based
     */
    fun isOnlineSource(): Boolean {
        return this == WEBSITE ||
               this == WEB_DOWNLOAD ||
               this == NETWORK ||
               this == CLOUD_STORAGE ||
               this == PHISHING_LINK
    }

    /**
     * Returns true if the source is external-device based
     */
    fun isExternalSource(): Boolean {
        return this == USB_DEVICE ||
               this == BLUETOOTH ||
               this == WIFI
    }

    /**
     * Returns true if user interaction likely triggered the threat
     */
    fun requiresUserInteraction(): Boolean {
        return this == EMAIL_ATTACHMENT ||
               this == DOWNLOADED_FILE ||
               this == QR_CODE ||
               this == APK_FILE
    }
}
