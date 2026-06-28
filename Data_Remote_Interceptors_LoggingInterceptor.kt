package com.sentrix.data.remote.interceptors

import com.sentrix.core.constants.NetworkConstants
import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer
import timber.log.Timber
import java.io.IOException
import java.nio.charset.Charset
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * -----------------------------------------------------------------------------
 * LoggingInterceptor
 * -----------------------------------------------------------------------------
 *
 * Enterprise-grade network logging interceptor for SentriX.
 *
 * This interceptor is responsible for logging:
 *
 * • Request URL
 * • HTTP Method
 * • Headers
 * • Request Body
 * • Response Code
 * • Response Headers
 * • Response Body
 * • API Execution Time
 * • Network Failures
 *
 * Logging is extremely useful during:
 *
 * - Development
 * - QA testing
 * - API debugging
 * - Security auditing
 * - Performance monitoring
 *
 * Security Considerations:
 *
 * Sensitive information must NEVER be exposed in logs.
 *
 * Examples:
 * - Authorization Token
 * - API Keys
 * - Passwords
 * - OTPs
 * - Refresh Tokens
 * - Device Secrets
 *
 * Therefore, this interceptor automatically masks sensitive headers.
 *
 * This interceptor should only be enabled in debug builds.
 *
 * Example:
 *
 * ```
 * if (BuildConfig.DEBUG) {
 *      addInterceptor(loggingInterceptor)
 * }
 * ```
 *
 * @author SentriX
 */
@Singleton
class LoggingInterceptor @Inject constructor() : Interceptor {

    /**
     * Intercepts network requests and logs
     * request/response information.
     *
     * @param chain Current interceptor chain.
     *
     * @return Network response.
     */
    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        val startTime = System.nanoTime()

        logRequest(request)

        return try {

            val response = chain.proceed(request)

            val durationMillis = TimeUnit.NANOSECONDS.toMillis(
                System.nanoTime() - startTime
            )

            logResponse(response, durationMillis)

            response

        } catch (exception: Exception) {

            val durationMillis = TimeUnit.NANOSECONDS.toMillis(
                System.nanoTime() - startTime
            )

            Timber.e(
                exception,
                """
                ================= NETWORK FAILURE =================
                URL      : ${request.url}
                METHOD   : ${request.method}
                DURATION : ${durationMillis}ms
                ERROR    : ${exception.message}
                ===================================================
                """.trimIndent()
            )

            throw exception
        }
    }

    /**
     * Logs request information.
     *
     * @param request Outgoing request.
     */
    private fun logRequest(request: okhttp3.Request) {

        val requestBody = request.body

        val bodyContent = try {
            requestBody?.let { bodyToString(it) } ?: "Empty Body"
        } catch (exception: Exception) {
            "Unable to read request body"
        }

        val headers = buildString {

            request.headers.names().forEach { headerName ->

                val value = request.header(headerName).orEmpty()

                append(
                    "$headerName : ${maskSensitiveValue(headerName, value)}\n"
                )
            }
        }

        Timber.d(
            """
            ================= HTTP REQUEST =================
            URL      : ${request.url}
            METHOD   : ${request.method}

            HEADERS:
            $headers

            BODY:
            $bodyContent
            =================================================
            """.trimIndent()
        )
    }

    /**
     * Logs response information.
     *
     * @param response Network response.
     * @param durationMillis API execution duration.
     */
    @Throws(IOException::class)
    private fun logResponse(
        response: Response,
        durationMillis: Long
    ) {

        val source = response.peekBody(MAX_LOG_BODY_SIZE)

        val responseBody = try {
            source.string()
        } catch (exception: Exception) {
            "Unable to read response body"
        }

        val headers = buildString {

            response.headers.names().forEach { headerName ->

                append(
                    "$headerName : ${response.header(headerName)}\n"
                )
            }
        }

        Timber.d(
            """
            ================= HTTP RESPONSE =================
            URL       : ${response.request.url}
            CODE      : ${response.code}
            MESSAGE   : ${response.message}
            SUCCESS   : ${response.isSuccessful}
            DURATION  : ${durationMillis}ms

            HEADERS:
            $headers

            BODY:
            $responseBody
            ==================================================
            """.trimIndent()
        )
    }

    /**
     * Converts request body into readable String.
     *
     * @param requestBody Request body.
     *
     * @return Body as String.
     */
    private fun bodyToString(
        requestBody: okhttp3.RequestBody
    ): String {

        return try {

            val buffer = Buffer()

            requestBody.writeTo(buffer)

            val charset = requestBody.contentType()
                ?.charset(Charset.forName(NetworkConstants.UTF_8))
                ?: Charset.forName(NetworkConstants.UTF_8)

            buffer.readString(charset)

        } catch (exception: Exception) {

            "Binary/Streaming Content"
        }
    }

    /**
     * Masks sensitive header values before logging.
     *
     * Example:
     *
     * Authorization: Bearer ***********
     *
     * @param headerName Header key.
     * @param value Header value.
     *
     * @return Masked value.
     */
    private fun maskSensitiveValue(
        headerName: String,
        value: String
    ): String {

        return when (headerName.lowercase()) {

            "authorization",
            "x-api-key",
            "api-key",
            "x-threat-api-key",
            "x-ai-engine-key",
            "cookie",
            "set-cookie",
            "password",
            "refresh-token" -> MASKED_VALUE

            else -> value
        }
    }

    companion object {

        /**
         * Maximum response body size allowed for logging.
         *
         * Large responses may affect performance.
         */
        private const val MAX_LOG_BODY_SIZE = 1024 * 1024L // 1 MB

        /**
         * Masked placeholder.
         */
        private const val MASKED_VALUE = "********"
    }
}
