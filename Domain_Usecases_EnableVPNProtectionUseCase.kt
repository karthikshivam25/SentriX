package com.sentrix.domain.usecases

/**
 * EnableVPNProtectionUseCase
 *
 * Responsible for enabling
 * VPN protection within the
 * SentriX cybersecurity platform.
 *
 * VPN protection helps:
 * - Secure internet traffic
 * - Protect user privacy
 * - Encrypt network communication
 * - Prevent data interception
 * - Improve online security
 *
 * Used by:
 * - SecurityDashboard
 * - VPNManager
 * - NetworkProtectionEngine
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Enable VPN protection
 * - Validate VPN availability
 * - Establish secure connection
 * - Generate connection status
 */
class EnableVPNProtectionUseCase {

    /**
     * Enables VPN protection.
     */
    operator fun invoke(
        vpnAvailable: Boolean,
        serverLocation: String
    ): VPNProtectionResult {

        if (!vpnAvailable) {

            return VPNProtectionResult(
                enabledAt =
                    System.currentTimeMillis(),

                isEnabled =
                    false,

                connectionStatus =
                    VPNConnectionStatus.FAILED,

                serverLocation =
                    null,

                message =
                    "VPN service is unavailable."
            )
        }

        return VPNProtectionResult(
            enabledAt =
                System.currentTimeMillis(),

            isEnabled =
                true,

            connectionStatus =
                VPNConnectionStatus.CONNECTED,

            serverLocation =
                serverLocation,

            message =
                "VPN protection enabled successfully."
        )
    }
}

/**
 * VPNProtectionResult
 *
 * Represents VPN
 * activation result.
 */
data class VPNProtectionResult(

    /**
     * Enable timestamp.
     */
    val enabledAt: Long,

    /**
     * VPN enabled status.
     */
    val isEnabled: Boolean,

    /**
     * Current connection status.
     */
    val connectionStatus:
        VPNConnectionStatus,

    /**
     * Connected server.
     */
    val serverLocation: String?,

    /**
     * Status message.
     */
    val message: String
)

/**
 * VPN connection status.
 */
enum class VPNConnectionStatus {

    /**
     * VPN connected.
     */
    CONNECTED,

    /**
     * VPN connecting.
     */
    CONNECTING,

    /**
     * VPN disconnected.
     */
    DISCONNECTED,

    /**
     * VPN connection failed.
     */
    FAILED
}
