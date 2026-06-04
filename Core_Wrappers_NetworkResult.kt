package com.sentrix.core.wrappers

/**
 * Represents the result of a network operation.
 */
sealed class NetworkResult<out T> {

    /**
     * Successful network response.
     */
    data class Success<T>(
        val data: T,
        val message: String? = null,
        val code: Int = 200
    ) : NetworkResult<T>()

    /**
     * API returned an error response.
     */
    data class Error(
        val message: String,
        val code: Int? = null,
        val throwable: Throwable? = null
    ) : NetworkResult<Nothing>()

    /**
     * Network request is currently in progress.
     */
    data object Loading : NetworkResult<Nothing>()

    /**
     * No internet connection available.
     */
    data object NoInternet : NetworkResult<Nothing>()

    /**
     * Request timed out.
     */
    data object Timeout : NetworkResult<Nothing>()

    /**
     * Request was cancelled.
     */
    data object Cancelled : NetworkResult<Nothing>()

    /**
     * Unknown or unexpected error.
     */
    data class Unknown(
        val throwable: Throwable? = null
    ) : NetworkResult<Nothing>()

    /**
     * Utility helpers.
     */
    fun isSuccess(): Boolean = this is Success
    fun isError(): Boolean = this is Error
    fun isLoading(): Boolean = this is Loading
}
