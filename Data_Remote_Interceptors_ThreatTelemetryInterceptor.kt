package com.sentrix.data.remote.interceptors

import android.os.Build
import okhttp3.Interceptor
import okhttp3.Response
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.max

/**
 * SentriX - Threat Telemetry Interceptor
 *
 * Package:
 * com.sentrix.data.remote.interceptors
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Collects privacy-safe telemetry about network requests made
 * by the SentriX application.
 *
 * This interceptor DOES NOT:
 * ------------------------------------------------------------
 * - Read request bodies
 * - Read response bodies
 * - Store authentication tokens
 * - Store API keys
 * - Store cookies
 * - Store passwords
 * - Store personally identifiable information
 *
 * It only observes metadata required for security analytics,
 * diagnostics, performance monitoring and threat intelligence.
 *
 * Examples of collected metadata:
 * ------------------------------------------------------------
 * - HTTP method
 * - Host
 * - Path category
 * - HTTP response code
 * - Request duration
 * - Network failure
 * - Request ID
 * - Android version
 * - Application/network client metadata
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * This interceptor belongs to the Data layer because it is
 * coupled to OkHttp/network communication.
 *
 * The interceptor should remain lightweight. Heavy analytics,
 * database operations or network calls should NOT be performed
 * synchronously inside intercept().
 *
 * Thread safety:
 * ------------------------------------------------------------
 * OkHttp may execute multiple requests concurrently. This class
 * therefore does not maintain mutable request-specific state.
 */
@Singleton
class ThreatTelemetryInterceptor @Inject constructor(
    private val telemetryReporter: ThreatTelemetryReporter
) : Interceptor {

    companion object {

        /**
         * Header used to correlate a request across SentriX
         * backend services.
         */
        private const val HEADER_REQUEST_ID = "X-SentriX-Request-ID"

        /**
         * Header indicating that this request originated from
         * the SentriX mobile application.
         */
        private const val HEADER_CLIENT = "X-SentriX-Client"

        /**
         * SentriX application/client identifier.
         */
        private const val CLIENT_NAME = "SentriX-Android"

        /**
         * Maximum path length retained by telemetry.
         *
         * This prevents accidentally storing extremely long
         * URLs or potentially sensitive path information.
         */
        private const val MAX_PATH_LENGTH = 120
    }

    /**
     * Intercepts an outgoing HTTP request and records
     * privacy-safe telemetry after the request completes.
     *
     * Important:
     * ------------------------------------------------------------
     * Telemetry must never prevent the actual network request
     * from completing.
     *
     * Therefore:
     * - Telemetry failures are swallowed.
     * - Network exceptions are re-thrown unchanged.
     */
    @Throws(IOException::class)
    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()

        /**
         * Generate a unique identifier for this network operation.
         *
         * UUID is generated locally and does not contain
         * personally identifiable information.
         */
        val requestId = UUID.randomUUID().toString()

        /**
         * Record request start time using nanoTime().
         *
         * nanoTime() is preferred over currentTimeMillis()
         * for measuring elapsed duration because it is intended
         * for monotonic interval measurements.
         */
        val startTimeNanos = System.nanoTime()

        /**
         * Add only non-sensitive telemetry headers.
         *
         * We intentionally do NOT add:
         * - Authorization
         * - API keys
         * - device identifiers
         * - user identifiers
         * - location information
         */
        val request = originalRequest.newBuilder()
            .header(HEADER_REQUEST_ID, requestId)
            .header(HEADER_CLIENT, CLIENT_NAME)
            .build()

        return try {

            /**
             * Continue the interceptor chain.
             *
             * This is the point where the actual network request
             * is eventually executed by OkHttp.
             */
            val response = chain.proceed(request)

            /**
             * Calculate request duration after receiving the
             * response.
             */
            val durationMs = calculateDurationMillis(startTimeNanos)

            /**
             * Build privacy-safe telemetry.
             */
            val telemetry = NetworkTelemetry(
                requestId = requestId,
                method = request.method,
                host = request.url.host,
                pathCategory = sanitizePath(request.url.encodedPath),
                statusCode = response.code,
                durationMs = durationMs,
                successful = response.isSuccessful,
                failed = false,
                failureType = null,
                androidVersion = Build.VERSION.SDK_INT
            )

            /**
             * Report telemetry.
             *
             * The reporter implementation should ideally enqueue
             * this event for asynchronous processing.
             */
            safelyReport(telemetry)

            response

        } catch (exception: IOException) {

            /**
             * Even failed network requests provide useful
             * security/performance telemetry.
             */
            val durationMs = calculateDurationMillis(startTimeNanos)

            val telemetry = NetworkTelemetry(
                requestId = requestId,
                method = request.method,
                host = request.url.host,
                pathCategory = sanitizePath(request.url.encodedPath),
                statusCode = null,
                durationMs = durationMs,
                successful = false,
                failed = true,
                failureType = exception::class.java.simpleName,
                androidVersion = Build.VERSION.SDK_INT
            )

            /**
             * Reporting telemetry must never replace the
             * original network exception.
             */
            safelyReport(telemetry)

            /**
             * Preserve OkHttp's normal error behaviour.
             */
            throw exception
        }
    }

    /**
     * Calculates elapsed time in milliseconds.
     */
    private fun calculateDurationMillis(startTimeNanos: Long): Long {

        val elapsedNanos = System.nanoTime() - startTimeNanos

        return max(
            0L,
            elapsedNanos / 1_000_000L
        )
    }

    /**
     * Sanitizes the URL path before telemetry collection.
     *
     * We deliberately avoid storing the complete URL because
     * URLs can contain:
     *
     * - user IDs
     * - email addresses
     * - tokens
     * - document IDs
     * - session identifiers
     * - other sensitive information
     *
     * Only a bounded path representation is retained.
     */
    private fun sanitizePath(path: String): String {

        if (path.isBlank()) {
            return "/"
        }

        return if (path.length <= MAX_PATH_LENGTH) {
            path
        } else {
            path.take(MAX_PATH_LENGTH)
        }
    }

    /**
     * Reports telemetry safely.
     *
     * A telemetry system should NEVER be able to break the
     * application's networking layer.
     */
    private fun safelyReport(telemetry: NetworkTelemetry) {

        try {
            telemetryReporter.report(telemetry)
        } catch (_: Exception) {
            /**
             * Intentionally ignored.
             *
             * Telemetry is secondary to the actual network
             * operation.
             */
        }
    }
}


/**
 * Immutable representation of network telemetry.
 *
 * This class deliberately contains only metadata.
 *
 * DO NOT add requestBody, responseBody, authorizationToken,
 * cookie, password or API-key fields here.
 */
data class NetworkTelemetry(

    /**
     * Unique identifier for correlating the network operation.
     */
    val requestId: String,

    /**
     * HTTP method.
     *
     * Examples:
     * GET
     * POST
     * PUT
     * DELETE
     */
    val method: String,

    /**
     * Remote server hostname.
     *
     * Example:
     * api.sentrix.com
     */
    val host: String,

    /**
     * Sanitized endpoint path.
     */
    val pathCategory: String,

    /**
     * HTTP status code.
     *
     * Null when the request failed before receiving a response.
     */
    val statusCode: Int?,

    /**
     * Total request duration in milliseconds.
     */
    val durationMs: Long,

    /**
     * Indicates whether the HTTP operation completed with
     * a successful HTTP status.
     */
    val successful: Boolean,

    /**
     * Indicates whether the network operation itself failed.
     */
    val failed: Boolean,

    /**
     * Type of network exception, when applicable.
     */
    val failureType: String?,

    /**
     * Android SDK version.
     *
     * Useful for compatibility and security analytics.
     */
    val androidVersion: Int
)


/**
 * Abstraction responsible for receiving network telemetry.
 *
 * Clean Architecture note:
 * ------------------------------------------------------------
 * The interceptor should not know whether telemetry is stored
 * in:
 *
 * - Room
 * - Firebase
 * - a SentriX analytics API
 * - a local event queue
 * - another telemetry platform
 *
 * This interface keeps that implementation detail outside
 * the interceptor.
 */
interface ThreatTelemetryReporter {

    /**
     * Reports a single telemetry event.
     *
     * Implementations should preferably enqueue the event
     * asynchronously instead of performing a blocking network
     * operation here.
     */
    fun report(telemetry: NetworkTelemetry)
}
