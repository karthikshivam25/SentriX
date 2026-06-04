package com.sentrix.core.interceptors

import com.sentrix.core.helpers.VPNHelper
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for validating VPN status
 * before sensitive network requests are executed.
 */
@Singleton
class VPNInterceptor @Inject constructor(
    private val vpnHelper: VPNHelper
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        // Allow request if VPN enforcement is disabled
        if (!vpnHelper.isVpnRequired()) {
            return chain.proceed(request)
        }

        // Validate VPN connection
        if (!vpnHelper.isVpnConnected()) {
            throw SecurityException(
                "Secure VPN connection required to access this resource."
            )
        }

        val securedRequest = request.newBuilder()
            .addHeader("X-VPN-Protected", "true")
            .addHeader("X-VPN-Status", "Connected")
            .build()

        return chain.proceed(securedRequest)
    }
}
