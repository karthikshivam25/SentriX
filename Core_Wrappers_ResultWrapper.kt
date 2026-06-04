package com.sentrix.core.wrappers

/**
 * ResultWrapper
 *
 * Responsibilities:
 * - Encapsulate operation results
 * - Handle success/failure states
 * - Standardize business logic responses
 * - Improve error handling
 * - Support domain layer operations
 */
sealed class ResultWrapper<out T> {

    /**
     * Successful result.
     */
    data class Success<T>(
        val data: T
    ) : ResultWrapper<T>()

    /**
     * Failed result.
     */
    data class Failure(
        val message: String,
        val throwable: Throwable? = null
    ) : ResultWrapper<Nothing>()

    /**
     * Pending state.
     */
    object Pending :
        ResultWrapper<Nothing>()

    /**
     * Check success state.
     */
    fun isSuccess(): Boolean {

        return this is Success
    }

    /**
     * Check failure state.
     */
    fun isFailure(): Boolean {

        return this is Failure
    }

    /**
     * Check pending state.
     */
    fun isPending(): Boolean {

        return this is Pending
    }

    /**
     * Get data safely.
     */
    fun getDataOrNull(): T? {

        return when (this) {

            is Success -> data

            else -> null
        }
    }

    /**
     * Get failure message safely.
     */
    fun getFailureMessage(): String? {

        return when (this) {

            is Failure -> message

            else -> null
        }
    }

    /**
     * Execute callback on success.
     */
    inline fun onSuccess(
        action: (T) -> Unit
    ): ResultWrapper<T> {

        if (this is Success) {
            action(data)
        }

        return this
    }

    /**
     * Execute callback on failure.
     */
    inline fun onFailure(
        action: (String) -> Unit
    ): ResultWrapper<T> {

        if (this is Failure) {
            action(message)
        }

        return this
    }

    companion object {

        /**
         * Create success result.
         */
        fun <T> success(
            data: T
        ): ResultWrapper<T> {

            return Success(data)
        }

        /**
         * Create failure result.
         */
        fun failure(
            message: String,
            throwable: Throwable? = null
        ): ResultWrapper<Nothing> {

            return Failure(
                message = message,
                throwable = throwable
            )
        }

        /**
         * Create pending result.
         */
        fun pending():
                ResultWrapper<Nothing> {

            return Pending
        }
    }
}
