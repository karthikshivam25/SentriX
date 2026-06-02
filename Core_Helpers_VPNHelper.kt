package com.sentrix.core.helpers

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build

object VPNHelper {

    /**
     * Check if VPN is currently active
     */
    fun isVpnActive(context: Context): Boolean {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

            val activeNetwork: Network =
                connectivityManager.activeNetwork ?: return false

            val capabilities =
                connectivityManager.getNetworkCapabilities(activeNetwork)
                    ?: return false

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

        } else {

            connectivityManager.allNetworks.any { network ->
                val capabilities =
                    connectivityManager.getNetworkCapabilities(network)

                capabilities?.hasTransport(
                    NetworkCapabilities.TRANSPORT_VPN
                ) == true
            }
        }
    }

    /**
     * Get VPN network capabilities
     */
    fun getVpnCapabilities(context: Context): NetworkCapabilities? {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return null

        return connectivityManager.getNetworkCapabilities(network)
    }

    /**
     * Check if connection is secure through VPN
     */
    fun isSecureVpnConnection(context: Context): Boolean {
        val capabilities = getVpnCapabilities(context)

        return capabilities?.hasTransport(
            NetworkCapabilities.TRANSPORT_VPN
        ) == true
    }

    /**
     * Get active network type
     */
    fun getActiveNetworkType(context: Context): String {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return "No Network"

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return "Unknown"

        return when {

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> {
                "Wi-Fi"
            }

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                "Mobile Data"
            }

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> {
                "Ethernet"
            }

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> {
                "VPN"
            }

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> {
                "Bluetooth"
            }

            else -> {
                "Unknown"
            }
        }
    }

    /**
     * Check if internet is validated
     */
    fun hasValidatedInternet(context: Context): Boolean {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return false

        return capabilities.hasCapability(
            NetworkCapabilities.NET_CAPABILITY_VALIDATED
        )
    }

    /**
     * Check if network is metered
     */
    fun isMeteredConnection(context: Context): Boolean {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        return connectivityManager.isActiveNetworkMetered
    }

    /**
     * Check if using roaming network
     */
    fun isRoaming(context: Context): Boolean {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return false

        return !capabilities.hasCapability(
            NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING
        )
    }

    /**
     * Get network downlink speed in Mbps
     */
    fun getDownloadSpeed(context: Context): Int {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return 0

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return 0

        return capabilities.linkDownstreamBandwidthKbps / 1024
    }

    /**
     * Get network uplink speed in Mbps
     */
    fun getUploadSpeed(context: Context): Int {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return 0

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return 0

        return capabilities.linkUpstreamBandwidthKbps / 1024
    }
}
