package com.sentrix.core.wrappers

/**
 * Resource
 *
 * Responsibilities:
 * - Represent UI/Data states
 * - Handle Success/Error/Loading
 * - Standardize repository responses
 * - Improve state management
 * - Simplify ViewModel communication
 */
sealed class Resource<out T> {

    /**
     * Success state.
     */
    data class Success<T>(
        val data: T
    ) : Resource<T>()

    /**
     * Error state.
     */
    data class Error(
        val message: String,
        val throwable: Throwable? = null
    ) : Resource<Nothing>()

    /**
     * Loading state.
     */
    object Loading :
        Resource<Nothing>()

    /**
     * Empty state.
     */
    object Empty :
        Resource<Nothing>()

    /**
     * Check success state.
     */
    fun isSuccess(): Boolean {

        return this is Success
    }

    /**
     * Check error state.
     */
    fun isError(): Boolean {

        return this is Error
    }

    /**
     * Check loading state.
     */
    fun isLoading(): Boolean {

        return this is Loading
    }

    /**
     * Check empty state.
     */
    fun isEmpty(): Boolean {

        return this is Empty
    }

    /**
     * Extract data safely.
     */
    fun getDataOrNull(): T? {

        return when (this) {

            is Success -> data

            else -> null
        }
    }

    /**
     * Extract error message safely.
     */
    fun getErrorMessage(): String? {

        return when (this) {

            is Error -> message

            else -> null
        }
    }

    companion object {

        /**
         * Create success resource.
         */
        fun <T> success(
            data: T
        ): Resource<T> {

            return Success(data)
        }

        /**
         * Create error resource.
         */
        fun error(
            message: String,
            throwable: Throwable? = null
        ): Resource<Nothing> {

            return Error(
                message = message,
                throwable = throwable
            )
        }

        /**
         * Create loading resource.
         */
        fun loading():
                Resource<Nothing> {

            return Loading
        }

        /**
         * Create empty resource.
         */
        fun empty():
                Resource<Nothing> {

            return Empty
        }
    }
}
