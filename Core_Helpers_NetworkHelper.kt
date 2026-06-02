package com.sentrix.core.helpers

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.net.wifi.WifiManager
import android.os.Build
import androidx.annotation.RequiresApi
import com.sentrix.core.enums.ConnectionType
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Collections

/**
 * Helper class for network monitoring and utilities
 */
object NetworkHelper {

    /**
     * Returns current active network type
     */
    fun getConnectionType(context: Context): ConnectionType {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val activeNetwork = connectivityManager.activeNetwork
            ?: return ConnectionType.OFFLINE

        val capabilities =
            connectivityManager.getNetworkCapabilities(activeNetwork)
                ?: return ConnectionType.UNKNOWN

        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ->
                ConnectionType.WIFI

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                ConnectionType.MOBILE_DATA

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ->
                ConnectionType.ETHERNET

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ->
                ConnectionType.VPN

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) ->
                ConnectionType.BLUETOOTH

            else -> ConnectionType.UNKNOWN
        }
    }

    /**
     * Returns true if internet connection is available
     */
    fun isInternetAvailable(context: Context): Boolean {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return false

        return capabilities.hasCapability(
            NetworkCapabilities.NET_CAPABILITY_INTERNET
        )
    }

    /**
     * Returns current Wi-Fi SSID
     */
    @Suppress("DEPRECATION")
    fun getWifiSSID(context: Context): String {

        val wifiManager =
            context.applicationContext.getSystemService(
                Context.WIFI_SERVICE
            ) as WifiManager

        return wifiManager.connectionInfo?.ssid ?: "Unknown"
    }

    /**
     * Returns device local IP address
     */
    fun getLocalIpAddress(): String {

        return try {

            val interfaces = Collections.list(
                NetworkInterface.getNetworkInterfaces()
            )

            for (networkInterface in interfaces) {

                val addresses = Collections.list(
                    networkInterface.inetAddresses
                )

                for (address in addresses) {

                    if (!address.isLoopbackAddress &&
                        address is InetAddress
                    ) {
                        return address.hostAddress ?: "Unavailable"
                    }
                }
            }

            "Unavailable"

        } catch (exception: Exception) {
            "Unavailable"
        }
    }

    /**
     * Returns total transmitted bytes
     */
    fun getTotalUploadBytes(): Long {
        return TrafficStats.getTotalTxBytes()
    }

    /**
     * Returns total received bytes
     */
    fun getTotalDownloadBytes(): Long {
        return TrafficStats.getTotalRxBytes()
    }

    /**
     * Formats bytes into readable format
     */
    fun formatBytes(bytes: Long): String {

        if (bytes <= 0) return "0 B"

        val units = arrayOf(
            "B",
            "KB",
            "MB",
            "GB",
            "TB"
        )

        val digitGroups =
            (Math.log10(bytes.toDouble()) / Math.log10(1024.0)).toInt()

        return String.format(
            "%.2f %s",
            bytes / Math.pow(1024.0, digitGroups.toDouble()),
            units[digitGroups]
        )
    }

    /**
     * Monitor network state changes
     */
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun registerNetworkCallback(
        context: Context,
        onAvailable: (Network) -> Unit,
        onLost: (Network) -> Unit
    ): ConnectivityManager.NetworkCallback {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val networkRequest = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        val callback =
            object : ConnectivityManager.NetworkCallback() {

                override fun onAvailable(network: Network) {
                    super.onAvailable(network)
                    onAvailable(network)
                }

                override fun onLost(network: Network) {
                    super.onLost(network)
                    onLost(network)
                }
            }

        connectivityManager.registerNetworkCallback(
            networkRequest,
            callback
        )

        return callback
    }

    /**
     * Unregister network callback
     */
    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    fun unregisterNetworkCallback(
        context: Context,
        callback: ConnectivityManager.NetworkCallback
    ) {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        connectivityManager.unregisterNetworkCallback(callback)
    }
}
