package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * Permission Monitoring Middleware
 * Validates and monitors application permissions
 * before allowing sensitive operations.
 */
class PermissionMonitoringMiddleware {

    /**
     * Executes a request after permission validation.
     */
    suspend fun <T> execute(
        hasRequiredPermissions: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!hasRequiredPermissions) {
            emit(
                NetworkResult.Error(
                    message = "Required permissions not granted"
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
                        ?: "Permission monitoring middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected permission monitoring error"
            )
        )
    }

    /**
     * Checks whether all required permissions exist.
     */
    fun hasPermissions(
        grantedPermissions: List<String>,
        requiredPermissions: List<String>
    ): Boolean {
        return requiredPermissions.all {
            grantedPermissions.contains(it)
        }
    }

    /**
     * Finds missing permissions.
     */
    fun getMissingPermissions(
        grantedPermissions: List<String>,
        requiredPermissions: List<String>
    ): List<String> {
        return requiredPermissions.filterNot {
            grantedPermissions.contains(it)
        }
    }

    /**
     * Calculates permission compliance score.
     */
    fun calculatePermissionScore(
        grantedPermissions: List<String>,
        requiredPermissions: List<String>
    ): Int {
        if (requiredPermissions.isEmpty()) return 100

        val grantedCount = requiredPermissions.count {
            grantedPermissions.contains(it)
        }

        return ((grantedCount.toDouble() / requiredPermissions.size) * 100)
            .toInt()
            .coerceIn(0, 100)
    }

    /**
     * Returns permission compliance level.
     */
    fun getComplianceLevel(
        score: Int
    ): String {
        return when {
            score >= 95 -> "FULLY_COMPLIANT"
            score >= 75 -> "COMPLIANT"
            score >= 50 -> "PARTIALLY_COMPLIANT"
            score >= 25 -> "LOW_COMPLIANCE"
            else -> "NON_COMPLIANT"
        }
    }

    /**
     * Executes operation only when permission requirements are met.
     */
    suspend fun <T> executeWithPermissionCheck(
        grantedPermissions: List<String>,
        requiredPermissions: List<String>,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {
            if (!hasPermissions(
                    grantedPermissions,
                    requiredPermissions
                )
            ) {
                NetworkResult.Error(
                    message = "Permission validation failed"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }
        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Permission protected execution failed"
            )
        }
    }

    /**
     * Logs permission-related events.
     */
    fun logPermissionEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("Permission Event: $event")
    }
}
