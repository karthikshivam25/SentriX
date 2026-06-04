package com.sentrix.core.managers

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

/**
 * LogManager
 *
 * Responsibilities:
 * - Application logging
 * - Security event logging
 * - Error tracking
 * - File log storage
 * - Log export
 * - Log cleanup
 */
class LogManager(
    private val context: Context
) {

    private val logEntries =
        CopyOnWriteArrayList<LogEntry>()

    private val logDirectory: File by lazy {
        File(context.filesDir, LOG_FOLDER).apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }

    /**
     * Debug log.
     */
    fun d(
        tag: String,
        message: String
    ) {
        addLog(
            level = LogLevel.DEBUG,
            tag = tag,
            message = message
        )

        Log.d(tag, message)
    }

    /**
     * Info log.
     */
    fun i(
        tag: String,
        message: String
    ) {
        addLog(
            level = LogLevel.INFO,
            tag = tag,
            message = message
        )

        Log.i(tag, message)
    }

    /**
     * Warning log.
     */
    fun w(
        tag: String,
        message: String
    ) {
        addLog(
            level = LogLevel.WARNING,
            tag = tag,
            message = message
        )

        Log.w(tag, message)
    }

    /**
     * Error log.
     */
    fun e(
        tag: String,
        message: String,
        throwable: Throwable? = null
    ) {
        addLog(
            level = LogLevel.ERROR,
            tag = tag,
            message = message
        )

        Log.e(tag, message, throwable)
    }

    /**
     * Security log.
     */
    fun security(
        event: String,
        details: String
    ) {
        addLog(
            level = LogLevel.SECURITY,
            tag = "SECURITY",
            message = "$event : $details"
        )
    }

    /**
     * Add log entry.
     */
    private fun addLog(
        level: LogLevel,
        tag: String,
        message: String
    ) {

        val entry = LogEntry(
            timestamp = System.currentTimeMillis(),
            level = level,
            tag = tag,
            message = message
        )

        logEntries.add(entry)

        if (logEntries.size > MAX_MEMORY_LOGS) {
            logEntries.removeAt(0)
        }
    }

    /**
     * Get all logs.
     */
    fun getLogs(): List<LogEntry> {
        return logEntries.toList()
    }

    /**
     * Get logs by level.
     */
    fun getLogs(
        level: LogLevel
    ): List<LogEntry> {

        return logEntries.filter {
            it.level == level
        }
    }

    /**
     * Save logs to file.
     */
    suspend fun saveLogsToFile(
        fileName: String = defaultLogFileName()
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val file =
                File(logDirectory, fileName)

            val content = buildString {

                logEntries.forEach { entry ->

                    appendLine(
                        "[${formatTimestamp(entry.timestamp)}] " +
                                "[${entry.level}] " +
                                "[${entry.tag}] " +
                                entry.message
                    )
                }
            }

            file.writeText(content)

            true

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Read log file.
     */
    suspend fun readLogFile(
        fileName: String
    ): String? = withContext(Dispatchers.IO) {

        try {

            val file =
                File(logDirectory, fileName)

            if (!file.exists()) {
                return@withContext null
            }

            file.readText()

        } catch (_: Exception) {
            null
        }
    }

    /**
     * Delete log file.
     */
    suspend fun deleteLogFile(
        fileName: String
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val file =
                File(logDirectory, fileName)

            file.exists() && file.delete()

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Clear memory logs.
     */
    fun clearLogs() {
        logEntries.clear()
    }

    /**
     * Delete all log files.
     */
    suspend fun clearLogFiles(): Boolean =
        withContext(Dispatchers.IO) {

            try {

                logDirectory
                    .listFiles()
                    ?.forEach {
                        it.delete()
                    }

                true

            } catch (_: Exception) {
                false
            }
        }

    /**
     * Generate log report.
     */
    fun generateLogReport(): String {

        val debugCount =
            getLogs(LogLevel.DEBUG).size

        val infoCount =
            getLogs(LogLevel.INFO).size

        val warningCount =
            getLogs(LogLevel.WARNING).size

        val errorCount =
            getLogs(LogLevel.ERROR).size

        val securityCount =
            getLogs(LogLevel.SECURITY).size

        return buildString {

            appendLine("Log Report")
            appendLine("-----------------------")
            appendLine("Total Logs : ${logEntries.size}")
            appendLine("Debug      : $debugCount")
            appendLine("Info       : $infoCount")
            appendLine("Warnings   : $warningCount")
            appendLine("Errors     : $errorCount")
            appendLine("Security   : $securityCount")
        }
    }

    /**
     * Format timestamp.
     */
    private fun formatTimestamp(
        timestamp: Long
    ): String {

        return SimpleDateFormat(
            "yyyy-MM-dd HH:mm:ss",
            Locale.getDefault()
        ).format(Date(timestamp))
    }

    /**
     * Default file name.
     */
    private fun defaultLogFileName(): String {

        val date =
            SimpleDateFormat(
                "yyyyMMdd_HHmmss",
                Locale.getDefault()
            ).format(Date())

        return "sentrix_log_$date.txt"
    }

    /**
     * Log entry model.
     */
    data class LogEntry(
        val timestamp: Long,
        val level: LogLevel,
        val tag: String,
        val message: String
    )

    /**
     * Log levels.
     */
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        SECURITY
    }

    companion object {

        private const val LOG_FOLDER =
            "sentrix_logs"

        private const val MAX_MEMORY_LOGS =
            1000
    }
}
