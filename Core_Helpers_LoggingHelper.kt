package com.sentrix.core.helpers

import android.util.Log

object LoggingHelper {

    private const val DEFAULT_TAG = "SentriX"

    /**
     * Enable or disable logs
     */
    var isLoggingEnabled: Boolean = true

    /**
     * Debug log
     */
    fun debug(
        message: String,
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.d(tag, message)
        }
    }

    /**
     * Info log
     */
    fun info(
        message: String,
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.i(tag, message)
        }
    }

    /**
     * Warning log
     */
    fun warning(
        message: String,
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.w(tag, message)
        }
    }

    /**
     * Error log
     */
    fun error(
        message: String,
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.e(tag, message)
        }
    }

    /**
     * Error log with throwable
     */
    fun error(
        throwable: Throwable,
        message: String = throwable.message ?: "Unknown Error",
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.e(tag, message, throwable)
        }
    }

    /**
     * Verbose log
     */
    fun verbose(
        message: String,
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.v(tag, message)
        }
    }

    /**
     * Security event log
     */
    fun security(
        message: String
    ) {

        if (isLoggingEnabled) {
            Log.w("SentriX-Security", message)
        }
    }

    /**
     * Network event log
     */
    fun network(
        message: String
    ) {

        if (isLoggingEnabled) {
            Log.d("SentriX-Network", message)
        }
    }

    /**
     * Malware detection log
     */
    fun malware(
        message: String
    ) {

        if (isLoggingEnabled) {
            Log.e("SentriX-Malware", message)
        }
    }

    /**
     * AI analysis log
     */
    fun ai(
        message: String
    ) {

        if (isLoggingEnabled) {
            Log.i("SentriX-AI", message)
        }
    }

    /**
     * Scan operation log
     */
    fun scanner(
        message: String
    ) {

        if (isLoggingEnabled) {
            Log.d("SentriX-Scanner", message)
        }
    }

    /**
     * Log formatted divider
     */
    fun divider(
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.d(tag, "==============================")
        }
    }

    /**
     * Log JSON data
     */
    fun json(
        json: String,
        tag: String = DEFAULT_TAG
    ) {

        if (isLoggingEnabled) {
            Log.d(tag, json)
        }
    }

    /**
     * Disable logging for production
     */
    fun disableLogging() {
        isLoggingEnabled = false
    }

    /**
     * Enable logging
     */
    fun enableLogging() {
        isLoggingEnabled = true
    }
}
