package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * Session Middleware
 * Handles session validation, expiration checks,
 * and session lifecycle management.
 */
class SessionMiddleware {

    /**
     * Executes a request after validating session state.
     */
    suspend fun <T> execute(
        isSessionActive: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isSessionActive) {
            emit(
                NetworkResult.Error(
                    message = "Session is inactive or expired"
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
                        ?: "Session middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected session error"
            )
        )
    }

    /**
     * Checks whether a session is valid.
     */
    fun isSessionValid(
        sessionToken: String?,
        expiryTimestamp: Long,
        currentTimestamp: Long = System.currentTimeMillis()
    ): Boolean {
        return !sessionToken.isNullOrBlank() &&
                expiryTimestamp > currentTimestamp
    }

    /**
     * Determines remaining session duration in milliseconds.
     */
    fun getRemainingSessionTime(
        expiryTimestamp: Long,
        currentTimestamp: Long = System.currentTimeMillis()
    ): Long {
        return (expiryTimestamp - currentTimestamp)
            .coerceAtLeast(0L)
    }

    /**
     * Checks if session is nearing expiration.
     */
    fun isSessionExpiringSoon(
        expiryTimestamp: Long,
        thresholdMillis: Long = 5 * 60 * 1000L,
        currentTimestamp: Long = System.currentTimeMillis()
    ): Boolean {
        return getRemainingSessionTime(
            expiryTimestamp,
            currentTimestamp
        ) <= thresholdMillis
    }

    /**
     * Generates session health score.
     */
    fun calculateSessionHealthScore(
        remainingTimeMillis: Long
    ): Int {
        return when {
            remainingTimeMillis > 60 * 60 * 1000L -> 100
            remainingTimeMillis > 30 * 60 * 1000L -> 80
            remainingTimeMillis > 10 * 60 * 1000L -> 60
            remainingTimeMillis > 5 * 60 * 1000L -> 40
            remainingTimeMillis > 0 -> 20
            else -> 0
        }
    }

    /**
     * Returns session status level.
     */
    fun getSessionStatus(
        healthScore: Int
    ): String {
        return when {
            healthScore >= 80 -> "HEALTHY"
            healthScore >= 60 -> "STABLE"
            healthScore >= 40 -> "WARNING"
            healthScore > 0 -> "CRITICAL"
            else -> "EXPIRED"
        }
    }

    /**
     * Executes operation only if session remains valid.
     */
    suspend fun <T> executeWithSessionValidation(
        sessionToken: String?,
        expiryTimestamp: Long,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {
            if (!isSessionValid(
                    sessionToken,
                    expiryTimestamp
                )
            ) {
                NetworkResult.Error(
                    message = "Session validation failed"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }
        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Session protected execution failed"
            )
        }
    }

    /**
     * Invokes logout callback for expired sessions.
     */
    fun invalidateSession(
        onSessionExpired: (() -> Unit)? = null
    ) {
        onSessionExpired?.invoke()
    }
}
