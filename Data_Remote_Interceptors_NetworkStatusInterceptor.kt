package com.sentrix.data.remote.interceptors

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import okhttp3.Interceptor
import okhttp3.Response
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Network Status Interceptor
 *
 * Package:
 * com.sentrix.data.remote.interceptors
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Verifies the current network state before an HTTP request is
 * executed.
 *
 * This interceptor helps SentriX avoid unnecessary network
 * operations when the device has no usable network connection.
 *
 * Responsibilities:
 * ------------------------------------------------------------
 * - Detect whether a network is available.
 * - Verify internet capability.
 * - Detect validated internet connectivity.
 * - Detect Wi-Fi connectivity.
 * - Detect cellular connectivity.
 * - Detect VPN connectivity.
 * - Detect metered connections.
 * - Add safe network metadata headers.
 * - Provide meaningful network-related exceptions.
 *
 * Security considerations:
 * ------------------------------------------------------------
 * This interceptor DOES NOT:
 *
 * - Read passwords.
 * - Read authentication tokens.
 * - Read request bodies.
 * - Read response bodies.
 * - Perform network scanning.
 * - Bypass Android network security.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * This class belongs to the Data/Remote layer because it is
 * coupled to:
 *
 * - OkHttp
 * - Android ConnectivityManager
 * - NetworkCapabilities
 *
 * Higher layers should not depend directly on these Android
 * networking APIs.
 */
@Singleton
class NetworkStatusInterceptor @Inject constructor(
    private val context: Context
) : Interceptor {

    companion object {

        /**
         * Header containing the current network type.
         *
         * Example values:
         * WIFI
         * CELLULAR
         * VPN
         * ETHERNET
         * UNKNOWN
         */
        private const val HEADER_NETWORK_TYPE = "X-SentriX-Network-Type"

        /**
         * Header indicating whether Android considers the
         * connection metered.
         */
        private const val HEADER_NETWORK_METERED = "X-SentriX-Network-Metered"

        /**
         * Header indicating whether the network has been
         * validated for internet access.
         */
        private const val HEADER_NETWORK_VALIDATED =
            "X-SentriX-Network-Validated"
    }

    /**
     * Android connectivity service.
     *
     * ConnectivityManager is retrieved once rather than
     * repeatedly calling getSystemService().
     */
    private val connectivityManager: ConnectivityManager by lazy {
        context.getSystemService(
            Context.CONNECTIVITY_SERVICE
        ) as ConnectivityManager
    }

    /**
     * Intercepts the outgoing request.
     *
     * Flow:
     *
     * 1. Inspect current network state.
     * 2. Reject request if there is no usable network.
     * 3. Add safe network metadata.
     * 4. Continue the OkHttp interceptor chain.
     */
    @Throws(IOException::class)
    override fun intercept(chain: Interceptor.Chain): Response {

        /**
         * Determine current network state.
         */
        val networkState = getNetworkState()

        /**
         * If the device does not currently have a usable
         * network, fail early.
         *
         * This avoids unnecessary socket connection attempts.
         */
        if (!networkState.isConnected) {
            throw NoNetworkConnectionException(
                message = "SentriX could not execute the request because " +
                    "no usable network connection is available."
            )
        }

        /**
         * Build a new request containing only non-sensitive
         * network metadata.
         */
        val request = chain.request()
            .newBuilder()
            .header(
                HEADER_NETWORK_TYPE,
                networkState.networkType.name
            )
            .header(
                HEADER_NETWORK_METERED,
                networkState.isMetered.toString()
            )
            .header(
                HEADER_NETWORK_VALIDATED,
                networkState.isValidated.toString()
            )
            .build()

        /**
         * Continue the interceptor chain.
         */
        return chain.proceed(request)
    }

    /**
     * Obtains the current network state.
     *
     * Android's NetworkCapabilities API is used instead of
     * deprecated NetworkInfo APIs.
     */
    private fun getNetworkState(): NetworkState {

        /**
         * Get the currently active network.
         */
        val activeNetwork: Network =
            connectivityManager.activeNetwork
                ?: return NetworkState.disconnected()

        /**
         * Obtain capabilities for the active network.
         */
        val capabilities =
            connectivityManager.getNetworkCapabilities(activeNetwork)
                ?: return NetworkState.disconnected()

        /**
         * Determine whether the network can actually provide
         * internet connectivity.
         *
         * INTERNET means the network is configured to provide
         * internet access.
         */
        val hasInternetCapability =
            capabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_INTERNET
            )

        /**
         * VALIDATED means Android has successfully determined
         * that the network can reach the internet.
         *
         * This is stronger than simply having the INTERNET
         * capability.
         *
         * On older Android versions the validation capability
         * may not be available, so the INTERNET capability is
         * used as the fallback.
         */
        val isValidated =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                capabilities.hasCapability(
                    NetworkCapabilities.NET_CAPABILITY_VALIDATED
                )
            } else {
                hasInternetCapability
            }

        /**
         * Determine network transport.
         *
         * A network may expose multiple transports. The priority
         * here is:
         *
         * VPN
         * Wi-Fi
         * Cellular
         * Ethernet
         * Bluetooth
         * Unknown
         */
        val networkType = determineNetworkType(capabilities)

        /**
         * Determine whether Android considers this network
         * metered.
         *
         * Metered networks may have data/billing restrictions.
         */
        val isMetered =
            !capabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_NOT_METERED
            )

        /**
         * A usable connection requires internet capability.
         *
         * We intentionally do not require VALIDATED here.
         *
         * Why?
         * --------------------------------------------------------
         * Some enterprise networks, captive portals, private
         * networks or security-filtered environments may not
         * expose Android's VALIDATED state immediately.
         *
         * OkHttp should still be allowed to attempt the request
         * and determine whether the backend is reachable.
         */
        val isConnected = hasInternetCapability

        return NetworkState(
            isConnected = isConnected,
            isValidated = isValidated,
            isMetered = isMetered,
            networkType = networkType
        )
    }

    /**
     * Determines the most relevant transport type.
     */
    private fun determineNetworkType(
        capabilities: NetworkCapabilities
    ): NetworkType {

        return when {

            /**
             * VPN is checked first because the underlying
             * transport may be Wi-Fi or cellular while traffic
             * is routed through a VPN.
             */
            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_VPN
            ) -> {
                NetworkType.VPN
            }

            /**
             * Wi-Fi connection.
             */
            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_WIFI
            ) -> {
                NetworkType.WIFI
            }

            /**
             * Mobile/cellular connection.
             */
            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_CELLULAR
            ) -> {
                NetworkType.CELLULAR
            }

            /**
             * Ethernet connection.
             */
            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_ETHERNET
            ) -> {
                NetworkType.ETHERNET
            }

            /**
             * Bluetooth network connection.
             */
            capabilities.hasTransport(
                NetworkCapabilities.TRANSPORT_BLUETOOTH
            ) -> {
                NetworkType.BLUETOOTH
            }

            /**
             * Unknown transport.
             */
            else -> {
                NetworkType.UNKNOWN
            }
        }
    }
}


/**
 * Represents the current network state.
 *
 * Immutable by design so that an individual network request
 * receives a consistent snapshot of the network state.
 */
data class NetworkState(

    /**
     * Whether a usable internet-capable network exists.
     */
    val isConnected: Boolean,

    /**
     * Whether Android has validated internet connectivity.
     */
    val isValidated: Boolean,

    /**
     * Whether the current network is metered.
     */
    val isMetered: Boolean,

    /**
     * Current network transport type.
     */
    val networkType: NetworkType
) {

    companion object {

        /**
         * Creates a disconnected state.
         */
        fun disconnected(): NetworkState {
            return NetworkState(
                isConnected = false,
                isValidated = false,
                isMetered = true,
                networkType = NetworkType.NONE
            )
        }
    }
}


/**
 * Supported network transport types recognized by SentriX.
 */
enum class NetworkType {

    /**
     * No network available.
     */
    NONE,

    /**
     * Wi-Fi network.
     */
    WIFI,

    /**
     * Cellular/mobile network.
     */
    CELLULAR,

    /**
     * VPN transport.
     */
    VPN,

    /**
     * Ethernet connection.
     */
    ETHERNET,

    /**
     * Bluetooth network transport.
     */
    BLUETOOTH,

    /**
     * Unknown or unsupported transport.
     */
    UNKNOWN
}


/**
 * Exception thrown when SentriX cannot find a usable
 * network connection.
 *
 * This is intentionally a dedicated exception so that the
 * repository/use-case layer can distinguish:
 *
 * No network
 *
 * from:
 *
 * Server failure
 * HTTP failure
 * Authentication failure
 * Timeout
 * DNS failure
 */
class NoNetworkConnectionException(
    message: String
) : IOException(message)
