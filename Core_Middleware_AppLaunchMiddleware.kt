package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import java.util.concurrent.atomic.AtomicInteger

/**
 * App Launch Middleware
 * Handles application startup validation,
 * launch analytics, security checks,
 * and initialization monitoring.
 */
class AppLaunchMiddleware {

    private val launchCounter = AtomicInteger(0)

    /**
     * Executes startup sequence validations.
     */
    suspend fun <T> execute(
        canLaunch: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!canLaunch) {
            emit(
                NetworkResult.Error(
                    message = "Application launch blocked"
                )
            )
            return@flow
        }

        try {
            incrementLaunchCount()

            val result = block.invoke()

            emit(NetworkResult.Success(result))
        } catch (exception: Exception) {
            emit(
                NetworkResult.Error(
                    message = exception.message
                        ?: "App launch middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected app launch error"
            )
        )
    }

    /**
     * Increments application launch count.
     */
    fun incrementLaunchCount(): Int {
        return launchCounter.incrementAndGet()
    }

    /**
     * Returns total launch count.
     */
    fun getLaunchCount(): Int {
        return launchCounter.get()
    }

    /**
     * Checks whether this is the first launch.
     */
    fun isFirstLaunch(): Boolean {
        return launchCounter.get() <= 1
    }

    /**
     * Calculates launch health score.
     */
    fun calculateLaunchHealthScore(
        initializationSuccess: Boolean,
        startupDurationMs: Long
    ): Int {

        var score = 100

        if (!initializationSuccess) {
            score -= 50
        }

        when {
            startupDurationMs > 10000 -> score -= 30
            startupDurationMs > 5000 -> score -= 20
            startupDurationMs > 3000 -> score -= 10
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Returns startup status level.
     */
    fun getLaunchStatus(
        healthScore: Int
    ): String {
        return when {
            healthScore >= 90 -> "EXCELLENT"
            healthScore >= 75 -> "GOOD"
            healthScore >= 50 -> "WARNING"
            healthScore >= 25 -> "DEGRADED"
            else -> "FAILED"
        }
    }

    /**
     * Executes operation only if launch conditions are met.
     */
    suspend fun <T> executeStartupValidation(
        initializationSuccess: Boolean,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {

            if (!initializationSuccess) {
                NetworkResult.Error(
                    message = "Application initialization failed"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }

        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Startup validation failed"
            )
        }
    }

    /**
     * Logs launch-related events.
     */
    fun logLaunchEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("App Launch Event: $event")
    }

    /**
     * Resets launch statistics.
     */
    fun resetLaunchStatistics() {
        launchCounter.set(0)
    }
}
