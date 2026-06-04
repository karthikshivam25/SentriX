package com.sentrix.core.managers

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

/**
 * AnalyticsManager
 *
 * Responsibilities:
 * - Event tracking
 * - User action logging
 * - Security analytics
 * - Scan analytics
 * - Threat analytics
 * - Usage statistics
 * - Report generation
 */
class AnalyticsManager(
    private val context: Context
) {

    private val events =
        CopyOnWriteArrayList<AnalyticsEvent>()

    /**
     * Track an event.
     */
    fun trackEvent(
        eventName: String,
        category: String,
        properties: Map<String, String> = emptyMap()
    ) {

        events.add(
            AnalyticsEvent(
                eventName = eventName,
                category = category,
                timestamp = System.currentTimeMillis(),
                properties = properties
            )
        )
    }

    /**
     * Track screen view.
     */
    fun trackScreenView(
        screenName: String
    ) {
        trackEvent(
            eventName = "screen_view",
            category = "navigation",
            properties = mapOf(
                "screen" to screenName
            )
        )
    }

    /**
     * Track scan execution.
     */
    fun trackScan(
        scanType: String,
        result: String
    ) {
        trackEvent(
            eventName = "scan_completed",
            category = "security",
            properties = mapOf(
                "scan_type" to scanType,
                "result" to result
            )
        )
    }

    /**
     * Track threat detection.
     */
    fun trackThreat(
        threatType: String,
        severity: String
    ) {
        trackEvent(
            eventName = "threat_detected",
            category = "threats",
            properties = mapOf(
                "type" to threatType,
                "severity" to severity
            )
        )
    }

    /**
     * Track permission events.
     */
    fun trackPermissionEvent(
        permission: String,
        granted: Boolean
    ) {
        trackEvent(
            eventName = "permission_event",
            category = "privacy",
            properties = mapOf(
                "permission" to permission,
                "granted" to granted.toString()
            )
        )
    }

    /**
     * Get all events.
     */
    fun getEvents(): List<AnalyticsEvent> {
        return events.toList()
    }

    /**
     * Get events by category.
     */
    fun getEventsByCategory(
        category: String
    ): List<AnalyticsEvent> {

        return events.filter {
            it.category.equals(
                category,
                ignoreCase = true
            )
        }
    }

    /**
     * Count events.
     */
    fun getEventCount(): Int {
        return events.size
    }

    /**
     * Get unique event names.
     */
    fun getUniqueEventNames(): Set<String> {
        return events.map {
            it.eventName
        }.toSet()
    }

    /**
     * Clear analytics data.
     */
    fun clearEvents() {
        events.clear()
    }

    /**
     * Export analytics as JSON.
     */
    fun exportAsJson(): String {

        val jsonArray = JSONArray()

        events.forEach { event ->

            val jsonObject = JSONObject().apply {

                put(
                    "eventName",
                    event.eventName
                )

                put(
                    "category",
                    event.category
                )

                put(
                    "timestamp",
                    event.timestamp
                )

                put(
                    "properties",
                    JSONObject(event.properties)
                )
            }

            jsonArray.put(jsonObject)
        }

        return jsonArray.toString(4)
    }

    /**
     * Generate analytics report.
     */
    fun generateReport(): String {

        val categories =
            events.groupBy {
                it.category
            }

        return buildString {

            appendLine("Analytics Report")
            appendLine("---------------------------")
            appendLine("Total Events : ${events.size}")
            appendLine(
                "Unique Events: ${
                    getUniqueEventNames().size
                }"
            )
            appendLine()

            categories.forEach { (category, items) ->
                appendLine(
                    "$category : ${items.size}"
                )
            }
        }
    }

    /**
     * Get most frequent event.
     */
    fun getMostFrequentEvent(): String? {

        return events
            .groupBy { it.eventName }
            .maxByOrNull {
                it.value.size
            }
            ?.key
    }

    /**
     * Get today's event count.
     */
    fun getTodayEventCount(): Int {

        val today =
            SimpleDateFormat(
                "yyyyMMdd",
                Locale.getDefault()
            ).format(Date())

        return events.count {

            val eventDate =
                SimpleDateFormat(
                    "yyyyMMdd",
                    Locale.getDefault()
                ).format(Date(it.timestamp))

            eventDate == today
        }
    }

    /**
     * Analytics event model.
     */
    data class AnalyticsEvent(
        val eventName: String,
        val category: String,
        val timestamp: Long,
        val properties: Map<String, String>
    )
}
