package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * Network Monitoring Middleware
 * Monitors network health, connectivity, latency,
 * and bandwidth conditions before executing requests.
 */
class NetworkMonitoringMiddleware {

    /**
     * Executes a request after validating network status.
     */
    suspend fun <T> execute(
        isNetworkAvailable: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isNetworkAvailable) {
            emit(
                NetworkResult.Error(
                    message = "No network connection available"
                )
            )
            return@flow
        }

        try {
            val result = block.invoke()
            emit(NetworkResult.Success(result))
        } catch (exception: Exception) {
            emit(
                NetworkResult.Error(
                    message = exception.message
                        ?: "Network monitoring middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected network monitoring error"
            )
        )
    }

    /**
     * Determines whether the network is healthy.
     */
    fun isNetworkHealthy(
        latencyMs: Long,
        packetLossPercentage: Double
    ): Boolean {
        return latencyMs < 300 &&
                packetLossPercentage < 5.0
    }

    /**
     * Calculates a network quality score.
     */
    fun calculateNetworkScore(
        latencyMs: Long,
        packetLossPercentage: Double
    ): Int {
        var score = 100

        when {
            latencyMs > 1000 -> score -= 50
            latencyMs > 500 -> score -= 30
            latencyMs > 250 -> score -= 15
        }

        when {
            packetLossPercentage > 20 -> score -= 40
            packetLossPercentage > 10 -> score -= 25
            packetLossPercentage > 5 -> score -= 10
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Returns a quality label based on network score.
     */
    fun getNetworkQuality(
        score: Int
    ): String {
        return when {
            score >= 90 -> "EXCELLENT"
            score >= 75 -> "GOOD"
            score >= 50 -> "FAIR"
            score >= 25 -> "POOR"
            else -> "CRITICAL"
        }
    }

    /**
     * Checks whether network speed is acceptable.
     */
    fun isBandwidthSufficient(
        downloadMbps: Double,
        minimumRequiredMbps: Double = 5.0
    ): Boolean {
        return downloadMbps >= minimumRequiredMbps
    }

    /**
     * Executes a protected operation only if
     * network quality meets requirements.
     */
    suspend fun <T> executeWithQualityCheck(
        latencyMs: Long,
        packetLossPercentage: Double,
        minimumScore: Int = 50,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {
            val score = calculateNetworkScore(
                latencyMs,
                packetLossPercentage
            )

            if (score < minimumScore) {
                NetworkResult.Error(
                    message = "Network quality below acceptable threshold"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }
        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Network quality validation failed"
            )
        }
    }

    /**
     * Logs network-related events.
     */
    fun logNetworkEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("Network Event: $event")
    }
}
