package com.sentrix.core.managers

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * VPNManager
 *
 * Responsibilities:
 * - Detect VPN status
 * - Monitor VPN changes
 * - Provide VPN security information
 * - Generate VPN security reports
 * - Integrate with SentriX threat analysis
 */
class VPNManager(
    private val context: Context
) {

    private val connectivityManager =
        context.getSystemService(
            Context.CONNECTIVITY_SERVICE
        ) as ConnectivityManager

    private val _vpnState =
        MutableStateFlow(getCurrentVPNState())

    val vpnState: StateFlow<VPNState> =
        _vpnState.asStateFlow()

    /**
     * Refresh VPN state manually.
     */
    fun refreshState() {
        _vpnState.value = getCurrentVPNState()
    }

    /**
     * Check if VPN is active.
     */
    fun isVPNActive(): Boolean {
        return getCurrentVPNState().isConnected
    }

    /**
     * Get current VPN state.
     */
    fun getCurrentVPNState(): VPNState {

        val network = connectivityManager.activeNetwork

        if (network == null) {
            return VPNState(
                isConnected = false,
                provider = "Unknown",
                securityScore = 0
            )
        }

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)

        val vpnConnected =
            capabilities?.hasTransport(
                NetworkCapabilities.TRANSPORT_VPN
            ) == true

        return VPNState(
            isConnected = vpnConnected,
            provider = detectVPNProvider(),
            securityScore = calculateVPNScore(vpnConnected)
        )
    }

    /**
     * Calculate VPN security score.
     */
    private fun calculateVPNScore(
        connected: Boolean
    ): Int {

        return if (connected) {
            100
        } else {
            40
        }
    }

    /**
     * Attempt VPN provider detection.
     *
     * NOTE:
     * Android does not officially expose VPN
     * provider names without VPN app integration.
     */
    private fun detectVPNProvider(): String {

        return try {
            val interfaces =
                java.net.NetworkInterface.getNetworkInterfaces()

            interfaces.toList().forEach { networkInterface ->

                val name =
                    networkInterface.name.lowercase()

                if (
                    name.contains("tun") ||
                    name.contains("ppp") ||
                    name.contains("vpn")
                ) {
                    return networkInterface.displayName
                        ?: "VPN Interface"
                }
            }

            "Unknown"

        } catch (_: Exception) {
            "Unknown"
        }
    }

    /**
     * Generate VPN report.
     */
    fun generateVPNReport(): String {

        val state = getCurrentVPNState()

        return buildString {

            appendLine("VPN Security Report")
            appendLine("---------------------")
            appendLine("VPN Active      : ${state.isConnected}")
            appendLine("Provider        : ${state.provider}")
            appendLine("Security Score  : ${state.securityScore}")
            appendLine("Recommendation  : ${getRecommendation()}")
        }
    }

    /**
     * Security recommendation.
     */
    fun getRecommendation(): String {

        return if (isVPNActive()) {
            "VPN protection is active."
        } else {
            "Enable a trusted VPN when using public networks."
        }
    }

    /**
     * Determine VPN risk level.
     */
    fun getRiskLevel(): VPNRiskLevel {

        return if (isVPNActive()) {
            VPNRiskLevel.LOW
        } else {
            VPNRiskLevel.MODERATE
        }
    }

    /**
     * VPN state model.
     */
    data class VPNState(
        val isConnected: Boolean,
        val provider: String,
        val securityScore: Int
    )

    /**
     * VPN risk levels.
     */
    enum class VPNRiskLevel {
        LOW,
        MODERATE,
        HIGH,
        CRITICAL
    }
}
