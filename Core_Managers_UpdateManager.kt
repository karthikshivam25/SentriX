package com.sentrix.core.managers

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * UpdateManager
 *
 * Responsibilities:
 * - App update checking
 * - Version comparison
 * - Update availability detection
 * - Update metadata retrieval
 * - Play Store redirection
 * - Update reporting
 */
class UpdateManager(
    private val context: Context,
    private val preferencesManager: PreferencesManager? = null,
    private val notificationManager: NotificationManager? = null
) {

    /**
     * Check for updates.
     *
     * Replace UPDATE_ENDPOINT with your backend endpoint.
     */
    suspend fun checkForUpdates(): UpdateResult =
        withContext(Dispatchers.IO) {

            try {

                val connection =
                    URL(UPDATE_ENDPOINT)
                        .openConnection() as HttpURLConnection

                connection.requestMethod = "GET"
                connection.connectTimeout = 10_000
                connection.readTimeout = 10_000

                val response =
                    connection.inputStream
                        .bufferedReader()
                        .use { it.readText() }

                val json = JSONObject(response)

                val latestVersion =
                    json.optString("latestVersion")

                val downloadUrl =
                    json.optString("downloadUrl")

                val releaseNotes =
                    json.optString("releaseNotes")

                val mandatory =
                    json.optBoolean("mandatory")

                val currentVersion =
                    getCurrentVersionName()

                val updateAvailable =
                    isNewerVersion(
                        currentVersion,
                        latestVersion
                    )

                UpdateResult(
                    currentVersion = currentVersion,
                    latestVersion = latestVersion,
                    updateAvailable = updateAvailable,
                    mandatory = mandatory,
                    downloadUrl = downloadUrl,
                    releaseNotes = releaseNotes
                )

            } catch (e: Exception) {

                UpdateResult(
                    currentVersion = getCurrentVersionName(),
                    latestVersion = "",
                    updateAvailable = false,
                    mandatory = false,
                    downloadUrl = "",
                    releaseNotes = e.message
                        ?: "Unable to check updates."
                )
            }
        }

    /**
     * Open Play Store.
     */
    fun openPlayStore() {

        val packageName = context.packageName

        try {

            val marketIntent = Intent(
                Intent.ACTION_VIEW,
                Uri.parse(
                    "market://details?id=$packageName"
                )
            )

            marketIntent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK
            )

            context.startActivity(marketIntent)

        } catch (_: Exception) {

            val webIntent = Intent(
                Intent.ACTION_VIEW,
                Uri.parse(
                    "https://play.google.com/store/apps/details?id=$packageName"
                )
            )

            webIntent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK
            )

            context.startActivity(webIntent)
        }
    }

    /**
     * Save last update check timestamp.
     */
    fun saveLastUpdateCheck() {

        preferencesManager?.putLong(
            KEY_LAST_UPDATE_CHECK,
            System.currentTimeMillis()
        )
    }

    /**
     * Retrieve last update check timestamp.
     */
    fun getLastUpdateCheck(): Long {

        return preferencesManager?.getLong(
            KEY_LAST_UPDATE_CHECK,
            0L
        ) ?: 0L
    }

    /**
     * Get installed version name.
     */
    fun getCurrentVersionName(): String {

        return try {

            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    0
                )

            packageInfo.versionName ?: "1.0.0"

        } catch (_: Exception) {
            "1.0.0"
        }
    }

    /**
     * Get installed version code.
     */
    fun getCurrentVersionCode(): Long {

        return try {

            val packageInfo =
                context.packageManager.getPackageInfo(
                    context.packageName,
                    0
                )

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            }

        } catch (_: Exception) {
            1L
        }
    }

    /**
     * Compare semantic versions.
     */
    fun isNewerVersion(
        currentVersion: String,
        latestVersion: String
    ): Boolean {

        return try {

            val current =
                currentVersion.split(".")
                    .map { it.toInt() }

            val latest =
                latestVersion.split(".")
                    .map { it.toInt() }

            val max =
                maxOf(
                    current.size,
                    latest.size
                )

            for (i in 0 until max) {

                val currentPart =
                    current.getOrElse(i) { 0 }

                val latestPart =
                    latest.getOrElse(i) { 0 }

                when {
                    latestPart > currentPart -> return true
                    latestPart < currentPart -> return false
                }
            }

            false

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Generate update report.
     */
    fun generateReport(
        result: UpdateResult
    ): String {

        return buildString {

            appendLine("Update Report")
            appendLine("-----------------------")
            appendLine(
                "Current Version : ${result.currentVersion}"
            )
            appendLine(
                "Latest Version  : ${result.latestVersion}"
            )
            appendLine(
                "Update Available: ${result.updateAvailable}"
            )
            appendLine(
                "Mandatory Update: ${result.mandatory}"
            )

            if (result.releaseNotes.isNotBlank()) {

                appendLine()
                appendLine("Release Notes:")
                appendLine(result.releaseNotes)
            }
        }
    }

    /**
     * Update result model.
     */
    data class UpdateResult(
        val currentVersion: String,
        val latestVersion: String,
        val updateAvailable: Boolean,
        val mandatory: Boolean,
        val downloadUrl: String,
        val releaseNotes: String
    )

    companion object {

        /**
         * Replace with SentriX backend endpoint.
         */
        const val UPDATE_ENDPOINT =
            "https://api.sentrix.security/version"

        const val KEY_LAST_UPDATE_CHECK =
            "last_update_check"
    }
}
