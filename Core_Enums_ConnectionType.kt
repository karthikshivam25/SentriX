package com.sentrix.core.enums

/**
 * Represents available network connection types
 */
enum class ConnectionType(
    val displayName: String,
    val description: String
) {

    WIFI(
        displayName = "Wi-Fi",
        description = "Wireless local area network connection"
    ),

    MOBILE_DATA(
        displayName = "Mobile Data",
        description = "Cellular mobile network connection"
    ),

    ETHERNET(
        displayName = "Ethernet",
        description = "Wired network connection"
    ),

    VPN(
        displayName = "VPN",
        description = "Virtual private network secure connection"
    ),

    BLUETOOTH(
        displayName = "Bluetooth",
        description = "Short-range wireless device connection"
    ),

    HOTSPOT(
        displayName = "Hotspot",
        description = "Portable shared internet connection"
    ),

    SATELLITE(
        displayName = "Satellite",
        description = "Satellite-based internet connection"
    ),

    USB_TETHERING(
        displayName = "USB Tethering",
        description = "Internet shared through USB connection"
    ),

    NFC(
        displayName = "NFC",
        description = "Near-field communication connection"
    ),

    OFFLINE(
        displayName = "Offline",
        description = "No active internet connection"
    ),

    UNKNOWN(
        displayName = "Unknown",
        description = "Connection type could not be identified"
    );

    /**
     * Returns true if internet connectivity is available
     */
    fun isConnected(): Boolean {
        return this != OFFLINE && this != UNKNOWN
    }

    /**
     * Returns true if connection is wireless
     */
    fun isWireless(): Boolean {
        return this == WIFI ||
               this == MOBILE_DATA ||
               this == BLUETOOTH ||
               this == HOTSPOT ||
               this == SATELLITE ||
               this == NFC
    }

    /**
     * Returns true if connection is secure/private
     */
    fun isSecureConnection(): Boolean {
        return this == VPN ||
               this == ETHERNET
    }

    /**
     * Returns true if mobile-based connectivity is used
     */
    fun isMobileNetwork(): Boolean {
        return this == MOBILE_DATA ||
               this == HOTSPOT ||
               this == USB_TETHERING
    }
}
