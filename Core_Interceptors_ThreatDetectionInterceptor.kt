package com.sentrix.core.interceptors

import android.util.Log
import com.sentrix.core.helpers.ThreatAnalysisHelper
import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for detecting suspicious
 * requests and responses that may indicate security threats.
 *
 * Examples:
 * - Malicious URLs
 * - Command injection attempts
 * - SQL injection payloads
 * - XSS payloads
 * - Threat intelligence matches
 */
@Singleton
class ThreatDetectionInterceptor @Inject constructor(
    private val threatAnalysisHelper: ThreatAnalysisHelper
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        analyzeRequest(request)

        val response = chain.proceed(request)

        analyzeResponse(response)

        return response
    }

    /**
     * Analyze outgoing request.
     */
    private fun analyzeRequest(
        request: okhttp3.Request
    ) {

        val findings = mutableListOf<String>()

        val url = request.url.toString()

        if (threatAnalysisHelper.isSuspiciousUrl(url)) {
            findings.add("Suspicious URL detected")
        }

        request.body?.let { body ->

            try {

                val buffer = Buffer()
                body.writeTo(buffer)

                val payload = buffer.readUtf8()

                if (payload.isNotBlank()) {

                    if (threatAnalysisHelper.containsSqlInjection(payload)) {
                        findings.add("SQL Injection signature detected")
                    }

                    if (threatAnalysisHelper.containsXss(payload)) {
                        findings.add("XSS signature detected")
                    }

                    if (threatAnalysisHelper.containsCommandInjection(payload)) {
                        findings.add("Command Injection signature detected")
                    }
                }

            } catch (_: Exception) {
            }
        }

        if (findings.isNotEmpty()) {

            Log.w(
                TAG,
                """
                Threat Indicators Found
                URL: $url
                Findings: ${findings.joinToString()}
                """.trimIndent()
            )

            throw ThreatDetectedException(
                findings.joinToString(separator = ", ")
            )
        }
    }

    /**
     * Analyze incoming response.
     */
    private fun analyzeResponse(
        response: Response
    ) {

        val serverHeader =
            response.header("Server").orEmpty()

        val poweredByHeader =
            response.header("X-Powered-By").orEmpty()

        if (
            threatAnalysisHelper.isSuspiciousServer(serverHeader) ||
            threatAnalysisHelper.isSuspiciousServer(poweredByHeader)
        ) {

            Log.w(
                TAG,
                "Potentially suspicious server fingerprint detected."
            )
        }
    }

    companion object {
        private const val TAG = "SentriX-ThreatDetection"
    }
}

/**
 * Thrown when a threat is detected.
 */
class ThreatDetectedException(
    message: String
) : SecurityException(message)
