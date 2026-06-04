package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import java.util.concurrent.ConcurrentHashMap

/**
 * Realtime Protection Middleware
 * Continuously monitors security events and blocks
 * suspicious activities before execution.
 */
class RealtimeProtectionMiddleware {

    private val threatRegistry = ConcurrentHashMap<String, Long>()

    /**
     * Executes a request after realtime protection checks.
     */
    suspend fun <T> execute(
        isProtectionEnabled: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isProtectionEnabled) {
            emit(
                NetworkResult.Error(
                    message = "Realtime protection is disabled"
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
                        ?: "Realtime protection middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected realtime protection error"
            )
        )
    }

    /**
     * Registers a detected threat.
     */
    fun registerThreat(
        threatId: String
    ) {
        threatRegistry[threatId] = System.currentTimeMillis()
    }

    /**
     * Checks whether a threat is already known.
     */
    fun isKnownThreat(
        threatId: String
    ): Boolean {
        return threatRegistry.containsKey(threatId)
    }

    /**
     * Removes a threat from registry.
     */
    fun clearThreat(
        threatId: String
    ) {
        threatRegistry.remove(threatId)
    }

    /**
     * Returns total active threats.
     */
    fun getActiveThreatCount(): Int {
        return threatRegistry.size
    }

    /**
     * Calculates realtime protection risk score.
     */
    fun calculateRiskScore(
        activeThreats: Int,
        suspiciousEvents: Int
    ): Int {

        val score =
            (activeThreats * 15) +
            (suspiciousEvents * 10)

        return score.coerceIn(0, 100)
    }

    /**
     * Returns protection status level.
     */
    fun getProtectionStatus(
        riskScore: Int
    ): String {
        return when {
            riskScore >= 80 -> "CRITICAL"
            riskScore >= 60 -> "HIGH"
            riskScore >= 40 -> "MEDIUM"
            riskScore >= 20 -> "LOW"
            else -> "PROTECTED"
        }
    }

    /**
     * Determines whether an action should be blocked.
     */
    fun shouldBlockAction(
        riskScore: Int,
        threshold: Int = 70
    ): Boolean {
        return riskScore >= threshold
    }

    /**
     * Executes operation only when protection checks pass.
     */
    suspend fun <T> executeProtected(
        activeThreats: Int,
        suspiciousEvents: Int,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {

            val riskScore = calculateRiskScore(
                activeThreats,
                suspiciousEvents
            )

            if (shouldBlockAction(riskScore)) {
                NetworkResult.Error(
                    message = "Operation blocked by realtime protection"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }

        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Realtime protected execution failed"
            )
        }
    }

    /**
     * Logs realtime protection events.
     */
    fun logProtectionEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("Realtime Protection Event: $event")
    }

    /**
     * Clears all registered threats.
     */
    fun clearAllThreats() {
        threatRegistry.clear()
    }
}
