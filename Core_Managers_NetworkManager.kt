package com.sentrix.core.managers

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * NetworkManager
 *
 * Responsibilities:
 * - Monitor network connectivity
 * - Detect connection type
 * - Internet availability checks
 * - Network capability inspection
 * - Real-time network state updates
 */
class NetworkManager(
    private val context: Context
) {

    private val connectivityManager =
        context.getSystemService(
            Context.CONNECTIVITY_SERVICE
        ) as ConnectivityManager

    private val _networkState =
        MutableStateFlow(getCurrentNetworkState())

    val networkState: StateFlow<NetworkState> =
        _networkState.asStateFlow()

    private var networkCallback:
            ConnectivityManager.NetworkCallback? = null

    /**
     * Start monitoring network changes.
     */
    fun startMonitoring() {

        if (networkCallback != null) return

        networkCallback =
            object : ConnectivityManager.NetworkCallback() {

                override fun onAvailable(network: Network) {
                    _networkState.value =
                        getCurrentNetworkState()
                }

                override fun onLost(network: Network) {
                    _networkState.value =
                        getCurrentNetworkState()
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities
                ) {
                    _networkState.value =
                        getCurrentNetworkState()
                }
            }

        val request = NetworkRequest.Builder()
            .addCapability(
                NetworkCapabilities.NET_CAPABILITY_INTERNET
            )
            .build()

        connectivityManager.registerNetworkCallback(
            request,
            networkCallback!!
        )
    }

    /**
     * Stop monitoring.
     */
    fun stopMonitoring() {

        networkCallback?.let {
            runCatching {
                connectivityManager.unregisterNetworkCallback(it)
            }
        }

        networkCallback = null
    }

    /**
     * Get current state.
     */
    fun getCurrentNetworkState(): NetworkState {

        val network = connectivityManager.activeNetwork
            ?: return NetworkState(
                isConnected = false,
                connectionType = ConnectionType.NONE,
                isValidated = false
            )

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return NetworkState(
                    isConnected = false,
                    connectionType = ConnectionType.NONE,
                    isValidated = false
                )

        val connectionType = when {
            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_WIFI
            ) -> ConnectionType.WIFI

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_CELLULAR
            ) -> ConnectionType.MOBILE

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_ETHERNET
            ) -> ConnectionType.ETHERNET

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_BLUETOOTH
            ) -> ConnectionType.BLUETOOTH

            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_VPN
            ) -> ConnectionType.VPN

            else -> ConnectionType.UNKNOWN
        }

        return NetworkState(
            isConnected = true,
            connectionType = connectionType,
            isValidated = capabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_VALIDATED
            )
        )
    }

    /**
     * Internet available.
     */
    fun isInternetAvailable(): Boolean {
        return getCurrentNetworkState().isValidated
    }

    /**
     * Connected to Wi-Fi.
     */
    fun isWifiConnected(): Boolean {
        return getCurrentNetworkState()
            .connectionType == ConnectionType.WIFI
    }

    /**
     * Connected to Mobile Data.
     */
    fun isMobileConnected(): Boolean {
        return getCurrentNetworkState()
            .connectionType == ConnectionType.MOBILE
    }

    /**
     * VPN active.
     */
    fun isVpnActive(): Boolean {
        return getCurrentNetworkState()
            .connectionType == ConnectionType.VPN
    }

    /**
     * Network security score.
     */
    fun calculateNetworkSecurityScore(): Int {

        val state = getCurrentNetworkState()

        if (!state.isConnected) {
            return 0
        }

        var score = 100

        when (state.connectionType) {

            ConnectionType.WIFI -> {
                score -= 5
            }

            ConnectionType.MOBILE -> {
                score -= 10
            }

            ConnectionType.ETHERNET -> {
                score -= 2
            }

            ConnectionType.VPN -> {
                score += 5
            }

            ConnectionType.BLUETOOTH -> {
                score -= 20
            }

            else -> {
                score -= 30
            }
        }

        if (!state.isValidated) {
            score -= 40
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Human-readable summary.
     */
    fun getNetworkSummary(): String {

        val state = getCurrentNetworkState()

        return buildString {
            appendLine("Network Summary")
            appendLine("----------------------")
            appendLine("Connected : ${state.isConnected}")
            appendLine("Type      : ${state.connectionType}")
            appendLine("Internet  : ${state.isValidated}")
            appendLine("Score     : ${calculateNetworkSecurityScore()}")
        }
    }

    /**
     * Network state model.
     */
    data class NetworkState(
        val isConnected: Boolean,
        val connectionType: ConnectionType,
        val isValidated: Boolean
    )

    /**
     * Connection types.
     */
    enum class ConnectionType {
        WIFI,
        MOBILE,
        ETHERNET,
        VPN,
        BLUETOOTH,
        UNKNOWN,
        NONE
    }
}
