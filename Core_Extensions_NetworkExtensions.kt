package com.sentrix.core.extensions

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Collections

/**
 * Network Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Connectivity Helpers
 * ------------------------------------------------------------------------- */

fun Context.isNetworkAvailable(): Boolean {

    val connectivityManager =
        getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager

    val network = connectivityManager.activeNetwork
        ?: return false

    val capabilities =
        connectivityManager.getNetworkCapabilities(network)
            ?: return false

    return capabilities.hasCapability(
        NetworkCapabilities.NET_CAPABILITY_INTERNET
    )
}

fun Context.isInternetAvailable(): Boolean {

    val connectivityManager =
        getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager

    val network = connectivityManager.activeNetwork
        ?: return false

    val capabilities =
        connectivityManager.getNetworkCapabilities(network)
            ?: return false

    return capabilities.hasCapability(
        NetworkCapabilities.NET_CAPABILITY_VALIDATED
    )
}

/* -------------------------------------------------------------------------
 * Connection Type Helpers
 * ------------------------------------------------------------------------- */

fun Context.getConnectionType(): String {

    val connectivityManager =
        getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager

    val network = connectivityManager.activeNetwork
        ?: return "Disconnected"

    val capabilities =
        connectivityManager.getNetworkCapabilities(network)
            ?: return "Unknown"

    return when {
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ->
            "WiFi"

        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
            "Mobile Data"

        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ->
            "Ethernet"

        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ->
            "VPN"

        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) ->
            "Bluetooth"

        else -> "Unknown"
    }
}

fun Context.isWifiConnected(): Boolean {
    return getConnectionType() == "WiFi"
}

fun Context.isMobileDataConnected(): Boolean {
    return getConnectionType() == "Mobile Data"
}

fun Context.isVpnConnected(): Boolean {

    val connectivityManager =
        getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager

    val network = connectivityManager.activeNetwork
        ?: return false

    val capabilities =
        connectivityManager.getNetworkCapabilities(network)
            ?: return false

    return capabilities.hasTransport(
        NetworkCapabilities.TRANSPORT_VPN
    )
}

/* -------------------------------------------------------------------------
 * Network Capability Helpers
 * ------------------------------------------------------------------------- */

fun Context.hasValidatedInternet(): Boolean {

    val connectivityManager =
        getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager

    val network = connectivityManager.activeNetwork
        ?: return false

    val capabilities =
        connectivityManager.getNetworkCapabilities(network)
            ?: return false

    return capabilities.hasCapability(
        NetworkCapabilities.NET_CAPABILITY_VALIDATED
    )
}

fun Context.hasCaptivePortal(): Boolean {

    val connectivityManager =
        getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager

    val network = connectivityManager.activeNetwork
        ?: return false

    val capabilities =
        connectivityManager.getNetworkCapabilities(network)
            ?: return false

    return capabilities.hasCapability(
        NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL
    )
}

/* -------------------------------------------------------------------------
 * Local IP Helpers
 * ------------------------------------------------------------------------- */

fun getLocalIpAddress(): String? {
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
                    address.hostAddress != null &&
                    address.hostAddress?.contains(":") == false
                ) {
                    return address.hostAddress
                }
            }
        }

        null

    } catch (_: Exception) {
        null
    }
}

fun getDeviceHostName(): String? {
    return try {
        InetAddress.getLocalHost().hostName
    } catch (_: Exception) {
        null
    }
}

/* -------------------------------------------------------------------------
 * Security Helpers
 * ------------------------------------------------------------------------- */

fun Context.isUsingVpn(): Boolean {
    return isVpnConnected()
}

fun Context.isSecureNetwork(): Boolean {

    return isInternetAvailable() &&
            !hasCaptivePortal()
}

fun Context.networkSecurityScore(): Int {

    var score = 0

    if (isInternetAvailable()) score += 40
    if (isVpnConnected()) score += 30
    if (!hasCaptivePortal()) score += 30

    return score
}

fun Context.networkRiskLevel(): String {

    return when (networkSecurityScore()) {
        in 90..100 -> "Low Risk"
        in 70..89 -> "Moderate Risk"
        in 40..69 -> "High Risk"
        else -> "Critical Risk"
    }
}

/* -------------------------------------------------------------------------
 * Network Monitoring
 * ------------------------------------------------------------------------- */

fun ConnectivityManager.registerNetworkCallbackSafe(
    onAvailable: (Network) -> Unit = {},
    onLost: (Network) -> Unit = {}
): ConnectivityManager.NetworkCallback {

    val callback =
        object : ConnectivityManager.NetworkCallback() {

            override fun onAvailable(network: Network) {
                onAvailable.invoke(network)
            }

            override fun onLost(network: Network) {
                onLost.invoke(network)
            }
        }

    val request = NetworkRequest.Builder()
        .addCapability(
            NetworkCapabilities.NET_CAPABILITY_INTERNET
        )
        .build()

    registerNetworkCallback(
        request,
        callback
    )

    return callback
}

fun ConnectivityManager.unregisterNetworkCallbackSafe(
    callback: ConnectivityManager.NetworkCallback?
) {
    try {
        callback?.let {
            unregisterNetworkCallback(it)
        }
    } catch (_: Exception) {
    }
}

/* -------------------------------------------------------------------------
 * Bandwidth Classification
 * ------------------------------------------------------------------------- */

fun Long.toNetworkSpeedLabel(): String {

    return when {
        this >= 100_000_000L -> "Very Fast"
        this >= 50_000_000L -> "Fast"
        this >= 10_000_000L -> "Moderate"
        this >= 1_000_000L -> "Slow"
        else -> "Very Slow"
    }
}

/* -------------------------------------------------------------------------
 * SentriX Threat Detection Helpers
 * ------------------------------------------------------------------------- */

fun Context.isPotentiallyUnsafeNetwork(): Boolean {

    return !isSecureNetwork() ||
            hasCaptivePortal()
}

fun Context.shouldWarnUserAboutNetwork(): Boolean {

    return networkSecurityScore() < 70
}

fun Context.networkThreatSummary(): String {

    return when {
        shouldWarnUserAboutNetwork() ->
            "Potential network security risk detected."

        isVpnConnected() ->
            "VPN protection active."

        else ->
            "Network connection appears secure."
    }
}
