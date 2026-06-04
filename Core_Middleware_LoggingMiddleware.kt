package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * Logging Middleware
 * Responsible for request/response logging,
 * audit tracking, and application event monitoring.
 */
class LoggingMiddleware {

    /**
     * Executes a request while logging lifecycle events.
     */
    suspend fun <T> execute(
        operationName: String,
        logger: (String) -> Unit,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        logger.invoke("Started operation: $operationName")

        try {
            val result = block.invoke()

            logger.invoke("Completed operation: $operationName")

            emit(NetworkResult.Success(result))
        } catch (exception: Exception) {

            logger.invoke(
                "Failed operation: $operationName | " +
                        "${exception.message}"
            )

            emit(
                NetworkResult.Error(
                    message = exception.message
                        ?: "Logging middleware error"
                )
            )
        }
    }.catch { throwable ->

        logger.invoke(
            "Unexpected error in operation: $operationName | " +
                    "${throwable.message}"
        )

        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected logging middleware error"
            )
        )
    }

    /**
     * Logs informational messages.
     */
    fun logInfo(
        message: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("[INFO] $message")
    }

    /**
     * Logs warning messages.
     */
    fun logWarning(
        message: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("[WARNING] $message")
    }

    /**
     * Logs error messages.
     */
    fun logError(
        message: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("[ERROR] $message")
    }

    /**
     * Logs debug messages.
     */
    fun logDebug(
        message: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("[DEBUG] $message")
    }

    /**
     * Creates an audit trail entry.
     */
    fun createAuditLog(
        userId: String,
        action: String,
        logger: (String) -> Unit
    ) {
        logger.invoke(
            "AUDIT | User: $userId | Action: $action | " +
                    "Timestamp: ${System.currentTimeMillis()}"
        )
    }

    /**
     * Measures execution time of a block.
     */
    suspend fun <T> measureExecutionTime(
        operationName: String,
        logger: (String) -> Unit,
        block: suspend () -> T
    ): T {

        val startTime = System.currentTimeMillis()

        return try {
            val result = block.invoke()

            val duration =
                System.currentTimeMillis() - startTime

            logger.invoke(
                "$operationName executed in ${duration}ms"
            )

            result
        } catch (exception: Exception) {

            val duration =
                System.currentTimeMillis() - startTime

            logger.invoke(
                "$operationName failed after ${duration}ms"
            )

            throw exception
        }
    }

    /**
     * Executes operation with automatic logging.
     */
    suspend fun <T> executeWithLogging(
        operationName: String,
        logger: (String) -> Unit,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {

            logger.invoke("Executing: $operationName")

            val result = block.invoke()

            logger.invoke("Success: $operationName")

            NetworkResult.Success(result)

        } catch (exception: Exception) {

            logger.invoke(
                "Error: $operationName | " +
                        "${exception.message}"
            )

            NetworkResult.Error(
                message = exception.message
                    ?: "Logged operation failed"
            )
        }
    }
}
