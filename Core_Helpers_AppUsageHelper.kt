package com.sentrix.core.helpers

import android.app.usage.UsageEvents
import android.app.usage.UsageStats
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build
import java.util.concurrent.TimeUnit

object AppUsageHelper {

    /**
     * Get app usage statistics
     */
    fun getUsageStats(
        context: Context,
        days: Int = 1
    ): List<UsageStats> {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return emptyList()
        }

        return try {

            val usageStatsManager =
                context.getSystemService(Context.USAGE_STATS_SERVICE)
                        as UsageStatsManager

            val endTime = System.currentTimeMillis()

            val startTime = endTime - TimeUnit.DAYS.toMillis(days.toLong())

            usageStatsManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                startTime,
                endTime
            ).sortedByDescending {
                it.totalTimeInForeground
            }

        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Get most used applications
     */
    fun getMostUsedApps(
        context: Context,
        limit: Int = 10
    ): List<UsageStats> {

        return getUsageStats(context)
            .take(limit)
    }

    /**
     * Get total screen time in milliseconds
     */
    fun getTotalScreenTime(
        context: Context,
        days: Int = 1
    ): Long {

        return getUsageStats(context, days)
            .sumOf {
                it.totalTimeInForeground
            }
    }

    /**
     * Convert milliseconds to readable time
     */
    fun formatUsageTime(
        timeInMillis: Long
    ): String {

        val hours = TimeUnit.MILLISECONDS.toHours(timeInMillis)

        val minutes = TimeUnit.MILLISECONDS.toMinutes(timeInMillis) % 60

        return "${hours}h ${minutes}m"
    }

    /**
     * Check if usage access permission granted
     */
    fun hasUsageAccessPermission(
        context: Context
    ): Boolean {

        return try {

            val usageStatsManager =
                context.getSystemService(Context.USAGE_STATS_SERVICE)
                        as UsageStatsManager

            val endTime = System.currentTimeMillis()

            val startTime =
                endTime - TimeUnit.MINUTES.toMillis(10)

            val stats = usageStatsManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                startTime,
                endTime
            )

            stats.isNotEmpty()

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get current foreground app package name
     */
    fun getCurrentForegroundApp(
        context: Context
    ): String? {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return null
        }

        return try {

            val usageStatsManager =
                context.getSystemService(Context.USAGE_STATS_SERVICE)
                        as UsageStatsManager

            val endTime = System.currentTimeMillis()

            val beginTime =
                endTime - TimeUnit.MINUTES.toMillis(1)

            val usageEvents = usageStatsManager.queryEvents(
                beginTime,
                endTime
            )

            val event = UsageEvents.Event()

            var lastApp: String? = null

            while (usageEvents.hasNextEvent()) {

                usageEvents.getNextEvent(event)

                if (
                    event.eventType ==
                    UsageEvents.Event.MOVE_TO_FOREGROUND
                ) {
                    lastApp = event.packageName
                }
            }

            lastApp

        } catch (e: Exception) {
            null
        }
    }

    /**
     * Get app launch count approximation
     */
    fun getAppLaunchCount(
        context: Context,
        packageName: String,
        days: Int = 1
    ): Int {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return 0
        }

        return try {

            val usageStatsManager =
                context.getSystemService(Context.USAGE_STATS_SERVICE)
                        as UsageStatsManager

            val endTime = System.currentTimeMillis()

            val startTime =
                endTime - TimeUnit.DAYS.toMillis(days.toLong())

            val usageEvents = usageStatsManager.queryEvents(
                startTime,
                endTime
            )

            val event = UsageEvents.Event()

            var launchCount = 0

            while (usageEvents.hasNextEvent()) {

                usageEvents.getNextEvent(event)

                if (
                    event.packageName == packageName &&
                    event.eventType ==
                    UsageEvents.Event.MOVE_TO_FOREGROUND
                ) {
                    launchCount++
                }
            }

            launchCount

        } catch (e: Exception) {
            0
        }
    }

    /**
     * Get application usage summary
     */
    fun getUsageSummary(
        context: Context
    ): UsageSummary {

        val stats = getUsageStats(context)

        val totalAppsUsed = stats.size

        val totalScreenTime =
            stats.sumOf {
                it.totalTimeInForeground
            }

        val mostUsedApp =
            stats.firstOrNull()?.packageName ?: "Unknown"

        return UsageSummary(
            totalAppsUsed = totalAppsUsed,
            totalScreenTime = totalScreenTime,
            formattedScreenTime =
                formatUsageTime(totalScreenTime),
            mostUsedApp = mostUsedApp
        )
    }

    /**
     * Usage summary model
     */
    data class UsageSummary(
        val totalAppsUsed: Int,
        val totalScreenTime: Long,
        val formattedScreenTime: String,
        val mostUsedApp: String
    )
}
