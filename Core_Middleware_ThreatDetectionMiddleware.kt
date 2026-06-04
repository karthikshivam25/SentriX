package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * Threat Detection Middleware
 * Performs threat analysis and security validation
 * before allowing requests to proceed.
 */
class ThreatDetectionMiddleware {

    /**
     * Executes a request after threat validation.
     */
    suspend fun <T> execute(
        threatDetected: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (threatDetected) {
            emit(
                NetworkResult.Error(
                    message = "Security threat detected. Request blocked."
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
                    message = exception.message ?: "Threat detection middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message ?: "Unexpected threat detection error"
            )
        )
    }

    /**
     * Detects known malicious patterns.
     */
    fun detectThreat(
        indicators: List<String>,
        knownThreats: List<String>
    ): Boolean {
        return indicators.any { indicator ->
            knownThreats.any { threat ->
                indicator.contains(threat, ignoreCase = true)
            }
        }
    }

    /**
     * Calculates a threat score based on detected indicators.
     */
    fun calculateThreatScore(
        detectedThreats: List<String>
    ): Int {
        return when {
            detectedThreats.isEmpty() -> 0
            detectedThreats.size <= 2 -> 25
            detectedThreats.size <= 5 -> 60
            else -> 100
        }
    }

    /**
     * Determines if the score exceeds risk threshold.
     */
    fun isThreatCritical(
        threatScore: Int,
        threshold: Int = 70
    ): Boolean {
        return threatScore >= threshold
    }

    /**
     * Generates a threat severity level.
     */
    fun getThreatLevel(
        threatScore: Int
    ): String {
        return when {
            threatScore >= 90 -> "CRITICAL"
            threatScore >= 70 -> "HIGH"
            threatScore >= 40 -> "MEDIUM"
            threatScore > 0 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Executes only if environment is considered safe.
     */
    suspend fun <T> executeSecure(
        detectedThreats: List<String>,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {
            val score = calculateThreatScore(detectedThreats)

            if (isThreatCritical(score)) {
                NetworkResult.Error(
                    message = "Critical security threat detected"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }
        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Secure execution failed"
            )
        }
    }

    /**
     * Logs detected threats.
     */
    fun logThreats(
        detectedThreats: List<String>,
        logger: (String) -> Unit
    ) {
        detectedThreats.forEach { threat ->
            logger.invoke("Threat Detected: $threat")
        }
    }
}
