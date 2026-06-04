package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import java.util.concurrent.ConcurrentHashMap

/**
 * AI Protection Middleware
 * Provides AI-driven threat analysis,
 * anomaly detection, and intelligent
 * security decision enforcement.
 */
class AIProtectionMiddleware {

    private val threatScores = ConcurrentHashMap<String, Int>()

    /**
     * Executes a request after AI security validation.
     */
    suspend fun <T> execute(
        isAiProtectionEnabled: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isAiProtectionEnabled) {
            emit(
                NetworkResult.Error(
                    message = "AI protection is disabled"
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
                        ?: "AI protection middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected AI protection error"
            )
        )
    }

    /**
     * Registers AI-generated threat score.
     */
    fun registerThreatScore(
        threatId: String,
        score: Int
    ) {
        threatScores[threatId] = score.coerceIn(0, 100)
    }

    /**
     * Returns stored threat score.
     */
    fun getThreatScore(
        threatId: String
    ): Int {
        return threatScores[threatId] ?: 0
    }

    /**
     * Detects anomalous behavior.
     */
    fun isAnomalousBehavior(
        baselineScore: Int,
        currentScore: Int,
        threshold: Int = 30
    ): Boolean {
        return kotlin.math.abs(
            currentScore - baselineScore
        ) >= threshold
    }

    /**
     * Calculates overall AI risk score.
     */
    fun calculateRiskScore(
        threatScores: List<Int>
    ): Int {

        if (threatScores.isEmpty()) {
            return 0
        }

        return threatScores.average()
            .toInt()
            .coerceIn(0, 100)
    }

    /**
     * Returns AI protection status.
     */
    fun getProtectionStatus(
        riskScore: Int
    ): String {
        return when {
            riskScore >= 90 -> "CRITICAL"
            riskScore >= 75 -> "HIGH"
            riskScore >= 50 -> "MEDIUM"
            riskScore >= 25 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Determines whether a threat should be blocked.
     */
    fun shouldBlockThreat(
        riskScore: Int,
        threshold: Int = 70
    ): Boolean {
        return riskScore >= threshold
    }

    /**
     * Executes operation only if AI assessment passes.
     */
    suspend fun <T> executeProtected(
        riskScore: Int,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {

            if (shouldBlockThreat(riskScore)) {
                NetworkResult.Error(
                    message = "Operation blocked by AI protection"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }

        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "AI protected execution failed"
            )
        }
    }

    /**
     * Logs AI security events.
     */
    fun logAiEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("AI Protection Event: $event")
    }

    /**
     * Clears all AI threat assessments.
     */
    fun clearThreatScores() {
        threatScores.clear()
    }
}
