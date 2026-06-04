package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * Authentication Middleware
 * Handles authentication validation before processing requests.
 */
class AuthenticationMiddleware {

    /**
     * Validates authentication state before executing request.
     */
    suspend fun <T> execute(
        isAuthenticated: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isAuthenticated) {
            emit(
                NetworkResult.Error(
                    message = "User authentication required"
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
                    message = exception.message ?: "Authentication middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message ?: "Unexpected authentication error"
            )
        )
    }

    /**
     * Checks whether user session is valid.
     */
    fun isSessionValid(
        token: String?,
        expiryTime: Long,
        currentTime: Long = System.currentTimeMillis()
    ): Boolean {
        return !token.isNullOrBlank() &&
                expiryTime > currentTime
    }

    /**
     * Verifies access permissions.
     */
    fun hasPermission(
        userPermissions: List<String>,
        requiredPermission: String
    ): Boolean {
        return userPermissions.contains(requiredPermission)
    }

    /**
     * Validates JWT or access token format.
     */
    fun validateToken(token: String?): Boolean {
        if (token.isNullOrBlank()) return false

        val parts = token.split(".")
        return parts.size == 3
    }

    /**
     * Clears authentication state.
     */
    fun logout(
        onLogout: (() -> Unit)? = null
    ) {
        onLogout?.invoke()
    }

    /**
     * Executes request only when authenticated.
     */
    suspend fun <T> executeAuthenticated(
        token: String?,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {
            if (!validateToken(token)) {
                NetworkResult.Error("Invalid authentication token")
            } else {
                NetworkResult.Success(block.invoke())
            }
        } catch (exception: Exception) {
            NetworkResult.Error(
                exception.message ?: "Authentication failed"
            )
        }
    }
}
