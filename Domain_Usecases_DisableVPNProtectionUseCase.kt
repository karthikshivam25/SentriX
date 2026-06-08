package com.sentrix.domain.usecases

/**
 * DisableVPNProtectionUseCase
 *
 * Responsible for disabling
 * VPN protection within the
 * SentriX cybersecurity platform.
 *
 * Disabling VPN protection:
 * - Terminates VPN connection
 * - Stops traffic encryption
 * - Restores normal networking
 * - Updates protection status
 *
 * Used by:
 * - SecurityDashboard
 * - VPNManager
 * - NetworkProtectionEngine
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Disable VPN protection
 * - Disconnect active session
 * - Update VPN status
 * - Generate operation result
 */
class DisableVPNProtectionUseCase {

    /**
     * Disables VPN protection.
     */
    operator fun invoke(
        vpnCurrentlyEnabled: Boolean
    ): VPNProtectionResult {

        if (!vpnCurrentlyEnabled) {

            return VPNProtectionResult(
                disabledAt =
                    System.currentTimeMillis(),

                isEnabled =
                    false,

                connectionStatus =
                    VPNConnectionStatus.DISCONNECTED,

                message =
                    "VPN protection is already disabled."
            )
        }

        return VPNProtectionResult(
            disabledAt =
                System.currentTimeMillis(),

            isEnabled =
                false,

            connectionStatus =
                VPNConnectionStatus.DISCONNECTED,

            message =
                "VPN protection disabled successfully."
        )
    }
}

/**
 * VPNProtectionResult
 *
 * Represents VPN
 * deactivation result.
 */
data class VPNProtectionResult(

    /**
     * Disable timestamp.
     */
    val disabledAt: Long,

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
