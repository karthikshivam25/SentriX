package com.sentrix.core.interceptors

import android.util.Log
import okhttp3.Interceptor
import okhttp3.Response
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for logging network requests and responses.
 */
@Singleton
class LoggingInterceptor @Inject constructor() : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val request = chain.request()

        val startTime = System.nanoTime()

        Log.d(TAG, "┌────────────────────────────────────")
        Log.d(TAG, "Request URL     : ${request.url}")
        Log.d(TAG, "Request Method  : ${request.method}")
        Log.d(TAG, "Request Headers : ${request.headers}")
        Log.d(TAG, "└────────────────────────────────────")

        return try {

            val response = chain.proceed(request)

            val endTime = System.nanoTime()
            val duration =
                TimeUnit.NANOSECONDS.toMillis(endTime - startTime)

            Log.d(TAG, "┌────────────────────────────────────")
            Log.d(TAG, "Response Code   : ${response.code}")
            Log.d(TAG, "Response Message: ${response.message}")
            Log.d(TAG, "Duration        : ${duration}ms")
            Log.d(TAG, "Response URL    : ${response.request.url}")
            Log.d(TAG, "└────────────────────────────────────")

            response

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Network request failed: ${exception.localizedMessage}",
                exception
            )

            throw exception
        }
    }

    companion object {
        private const val TAG = "SentriX-Network"
    }
}
