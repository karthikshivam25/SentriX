package com.sentrix.core.interceptors

import android.os.Build
import okhttp3.Interceptor
import okhttp3.Response
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for attaching common headers
 * to every outgoing network request.
 */
@Singleton
class HeaderInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()

        val updatedRequest = originalRequest.newBuilder()
            .addHeader("Accept", "application/json")
            .addHeader("Content-Type", "application/json")
            .addHeader("Accept-Language", Locale.getDefault().language)
            .addHeader("Platform", PLATFORM)
            .addHeader("OS-Version", Build.VERSION.RELEASE ?: "Unknown")
            .addHeader("Device-SDK", Build.VERSION.SDK_INT.toString())
            .addHeader("Manufacturer", Build.MANUFACTURER ?: "Unknown")
            .addHeader("Model", Build.MODEL ?: "Unknown")
            .addHeader("User-Agent", buildUserAgent())
            .build()

        return chain.proceed(updatedRequest)
    }

    /**
     * Builds a custom user agent string.
     */
    private fun buildUserAgent(): String {
        return buildString {
            append(APP_NAME)
            append("/")
            append(APP_VERSION)
            append(" (Android ")
            append(Build.VERSION.RELEASE)
            append("; SDK ")
            append(Build.VERSION.SDK_INT)
            append("; ")
            append(Build.MANUFACTURER)
            append(" ")
            append(Build.MODEL)
            append(")")
        }
    }

    companion object {
        private const val PLATFORM = "Android"
        private const val APP_NAME = "SentriX"
        private const val APP_VERSION = "1.0.0"
    }
}
