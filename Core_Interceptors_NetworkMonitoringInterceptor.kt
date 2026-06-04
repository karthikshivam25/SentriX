package com.sentrix.core.interceptors

import android.util.Log
import okhttp3.Interceptor
import okhttp3.Response
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for monitoring network performance,
 * request latency, response size, and connection quality.
 */
@Singleton
class NetworkMonitoringInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        val startTime = System.nanoTime()

        try {

            val response = chain.proceed(request)

            val endTime = System.nanoTime()

            val durationMillis = TimeUnit.NANOSECONDS
                .toMillis(endTime - startTime)

            val responseSizeBytes =
                response.body?.contentLength() ?: -1L

            logNetworkMetrics(
                url = request.url.toString(),
                method = request.method,
                responseCode = response.code,
                durationMillis = durationMillis,
                responseSizeBytes = responseSizeBytes
            )

            return response

        } catch (exception: Exception) {

            val endTime = System.nanoTime()

            val durationMillis = TimeUnit.NANOSECONDS
                .toMillis(endTime - startTime)

            Log.e(
                TAG,
                "Network request failed after ${durationMillis}ms " +
                        "for ${request.url}",
                exception
            )

            throw exception
        }
    }

    /**
     * Logs network performance metrics.
     */
    private fun logNetworkMetrics(
        url: String,
        method: String,
        responseCode: Int,
        durationMillis: Long,
        responseSizeBytes: Long
    ) {

        Log.d(
            TAG,
            """
            ==============================
            Network Metrics
            ==============================
            URL           : $url
            Method        : $method
            Response Code : $responseCode
            Duration      : ${durationMillis}ms
            Response Size : ${formatBytes(responseSizeBytes)}
            ==============================
            """.trimIndent()
        )

        if (durationMillis > SLOW_REQUEST_THRESHOLD_MS) {
            Log.w(
                TAG,
                "Slow network request detected: " +
                        "${durationMillis}ms -> $url"
            )
        }
    }

    /**
     * Converts bytes into human-readable format.
     */
    private fun formatBytes(
        bytes: Long
    ): String {

        if (bytes <= 0) return "Unknown"

        val kb = bytes / 1024.0
        val mb = kb / 1024.0

        return when {
            mb >= 1 -> String.format("%.2f MB", mb)
            kb >= 1 -> String.format("%.2f KB", kb)
            else -> "$bytes B"
        }
    }

    companion object {

        private const val TAG = "SentriX-NetworkMonitor"

        /**
         * Requests exceeding this threshold
         * will be marked as slow.
         */
        private const val SLOW_REQUEST_THRESHOLD_MS = 3_000L
    }
}
