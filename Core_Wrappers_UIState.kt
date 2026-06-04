package com.sentrix.core.wrappers

/**
 * Represents UI state for screens using MVVM/MVI architecture.
 */
sealed class UIState<out T> {

    /**
     * Initial state before any action is performed.
     */
    data object Idle : UIState<Nothing>()

    /**
     * Loading state while processing data.
     */
    data object Loading : UIState<Nothing>()

    /**
     * Success state containing data.
     */
    data class Success<T>(
        val data: T,
        val message: String? = null
    ) : UIState<T>()

    /**
     * Error state containing failure information.
     */
    data class Error(
        val message: String,
        val code: Int? = null,
        val throwable: Throwable? = null
    ) : UIState<Nothing>()

    /**
     * Empty state when no data is available.
     */
    data class Empty(
        val message: String = "No data available"
    ) : UIState<Nothing>()

    /**
     * Returns true if state is Success.
     */
    fun isSuccess(): Boolean = this is Success

    /**
     * Returns true if state is Error.
     */
    fun isError(): Boolean = this is Error

    /**
     * Returns true if state is Loading.
     */
    fun isLoading(): Boolean = this is Loading

    /**
     * Returns true if state is Empty.
     */
    fun isEmpty(): Boolean = this is Empty

    /**
     * Returns true if state is Idle.
     */
    fun isIdle(): Boolean = this is Idle
}
