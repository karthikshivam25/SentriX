package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import java.util.concurrent.ConcurrentHashMap

/**
 * Analytics Middleware
 * Responsible for tracking application events,
 * user interactions, performance metrics,
 * and analytics reporting.
 */
class AnalyticsMiddleware {

    private val eventCounters = ConcurrentHashMap<String, Int>()

    /**
     * Executes a request while collecting analytics.
     */
    suspend fun <T> execute(
        eventName: String,
        analyticsLogger: (String) -> Unit,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        trackEvent(eventName, analyticsLogger)

        try {
            val startTime = System.currentTimeMillis()

            val result = block.invoke()

            val duration = System.currentTimeMillis() - startTime

            analyticsLogger.invoke(
                "Analytics | Event=$eventName | Duration=${duration}ms | Status=SUCCESS"
            )

            emit(NetworkResult.Success(result))

        } catch (exception: Exception) {

            analyticsLogger.invoke(
                "Analytics | Event=$eventName | Status=FAILED | Message=${exception.message}"
            )

            emit(
                NetworkResult.Error(
                    message = exception.message
                        ?: "Analytics middleware error"
                )
            )
        }
    }.catch { throwable ->

        analyticsLogger.invoke(
            "Analytics | Event=$eventName | UnexpectedError=${throwable.message}"
        )

        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected analytics middleware error"
            )
        )
    }

    /**
     * Tracks an analytics event.
     */
    fun trackEvent(
        eventName: String,
        analyticsLogger: (String) -> Unit
    ) {
        val count = (eventCounters[eventName] ?: 0) + 1
        eventCounters[eventName] = count

        analyticsLogger.invoke(
            "Event Tracked: $eventName | Count=$count"
        )
    }

    /**
     * Tracks a screen visit.
     */
    fun trackScreenView(
        screenName: String,
        analyticsLogger: (String) -> Unit
    ) {
        analyticsLogger.invoke(
            "Screen View: $screenName"
        )
    }

    /**
     * Tracks user action.
     */
    fun trackUserAction(
        action: String,
        analyticsLogger: (String) -> Unit
    ) {
        analyticsLogger.invoke(
            "User Action: $action"
        )
    }

    /**
     * Tracks custom metrics.
     */
    fun trackMetric(
        metricName: String,
        value: Number,
        analyticsLogger: (String) -> Unit
    ) {
        analyticsLogger.invoke(
            "Metric: $metricName | Value=$value"
        )
    }

    /**
     * Returns event occurrence count.
     */
    fun getEventCount(
        eventName: String
    ): Int {
        return eventCounters[eventName] ?: 0
    }

    /**
     * Clears analytics cache.
     */
    fun clearAnalytics() {
        eventCounters.clear()
    }

    /**
     * Executes operation with performance tracking.
     */
    suspend fun <T> executeWithPerformanceTracking(
        operationName: String,
        analyticsLogger: (String) -> Unit,
        block: suspend () -> T
    ): NetworkResult<T> {

        val startTime = System.currentTimeMillis()

        return try {

            val result = block.invoke()

            val duration = System.currentTimeMillis() - startTime

            analyticsLogger.invoke(
                "Performance | Operation=$operationName | Duration=${duration}ms"
            )

            NetworkResult.Success(result)

        } catch (exception: Exception) {

            analyticsLogger.invoke(
                "Performance | Operation=$operationName | Failed=${exception.message}"
            )

            NetworkResult.Error(
                message = exception.message
                    ?: "Performance tracking failed"
            )
        }
    }

    /**
     * Generates analytics summary.
     */
    fun generateSummary(): Map<String, Int> {
        return eventCounters.toMap()
    }
}
