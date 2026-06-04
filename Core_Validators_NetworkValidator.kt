package com.sentrix.core.validators

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.sentrix.core.enums.ConnectionType
import com.sentrix.core.exceptions.InvalidNetworkException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * NetworkValidator
 *
 * Responsibilities:
 * - Network connectivity validation
 * - Internet availability checks
 * - Connection type detection
 * - Network security analysis
 * - Connection quality assessment
 */
object NetworkValidator {

    /**
     * Validate network availability.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidNetworkException::class
    )
    fun validate(
        context: Context?
    ): Boolean {

        if (context == null) {
            throw RequiredFieldException(
                "Context"
            )
        }

        if (!isConnected(context)) {
            throw InvalidNetworkException(
                "No active network connection."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        context: Context?
    ): Boolean {

        return try {

            validate(context)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check network connectivity.
     */
    fun isConnected(
        context: Context
    ): Boolean {

        val connectivityManager =
            context.getSystemService(
                Context.CONNECTIVITY_SERVICE
            ) as ConnectivityManager

        val network =
            connectivityManager.activeNetwork
                ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(
                network
            ) ?: return false

        return capabilities.hasCapability(
            NetworkCapabilities.NET_CAPABILITY_INTERNET
        )
    }

    /**
     * Get connection type.
     */
    fun getConnectionType(
        context: Context
    ): ConnectionType {

        val connectivityManager =
            context.getSystemService(
                Context.CONNECTIVITY_SERVICE
            ) as ConnectivityManager

        val network =
            connectivityManager.activeNetwork
                ?: return ConnectionType.NONE

        val capabilities =
            connectivityManager.getNetworkCapabilities(
                network
            ) ?: return ConnectionType.NONE

        return when {

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
                NetworkCapabilities.TRANSPORT_VPN
            ) -> ConnectionType.VPN

            else -> ConnectionType.UNKNOWN
        }
    }

    /**
     * Check VPN connection.
     */
    fun isVpnConnected(
        context: Context
    ): Boolean {

        return getConnectionType(
            context
        ) == ConnectionType.VPN
    }

    /**
     * Check Wi-Fi connection.
     */
    fun isWifiConnected(
        context: Context
    ): Boolean {

        return getConnectionType(
            context
        ) == ConnectionType.WIFI
    }

    /**
     * Check mobile data connection.
     */
    fun isMobileConnected(
        context: Context
    ): Boolean {

        return getConnectionType(
            context
        ) == ConnectionType.MOBILE
    }

    /**
     * Get network risk level.
     */
    fun getRiskLevel(
        context: Context
    ): String {

        return when (
            getConnectionType(context)
        ) {

            ConnectionType.WIFI ->
                "Medium"

            ConnectionType.MOBILE ->
                "Low"

            ConnectionType.VPN ->
                "Very Low"

            ConnectionType.ETHERNET ->
                "Low"

            else ->
                "High"
        }
    }

    /**
     * Generate network summary.
     */
    fun getSummary(
        context: Context
    ): String {

        return buildString {

            appendLine(
                "Connected: ${isConnected(context)}"
            )

            appendLine(
                "Connection Type: ${
                    getConnectionType(
                        context
                    )
                }"
            )

            appendLine(
                "VPN Active: ${
                    isVpnConnected(
                        context
                    )
                }"
            )

            appendLine(
                "Risk Level: ${
                    getRiskLevel(
                        context
                    )
                }"
            )
        }
    }
}
