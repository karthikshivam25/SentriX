package com.sentrix.core.wrappers

/**
 * Represents a standardized failure response across the application.
 */
data class FailureWrapper(
    val message: String,
    val code: Int? = null,
    val reason: String? = null,
    val throwable: Throwable? = null,
    val timestamp: Long = System.currentTimeMillis()
) {

    /**
     * Returns true if an error code exists.
     */
    fun hasCode(): Boolean = code != null

    /**
     * Returns true if an exception is attached.
     */
    fun hasThrowable(): Boolean = throwable != null

    /**
     * Converts the failure information into a readable string.
     */
    fun toReadableMessage(): String {
        return buildString {
            append(message)

            reason?.takeIf { it.isNotBlank() }?.let {
                append(" | Reason: ")
                append(it)
            }

            code?.let {
                append(" | Code: ")
                append(it)
            }
        }
    }

    companion object {

        fun networkFailure(
            message: String = "Network request failed",
            code: Int? = null,
            throwable: Throwable? = null
        ): FailureWrapper {
            return FailureWrapper(
                message = message,
                code = code,
                throwable = throwable
            )
        }

        fun validationFailure(
            message: String,
            reason: String? = null
        ): FailureWrapper {
            return FailureWrapper(
                message = message,
                reason = reason
            )
        }

        fun unknownFailure(
            throwable: Throwable? = null
        ): FailureWrapper {
            return FailureWrapper(
                message = "An unknown error occurred",
                throwable = throwable
            )
        }
    }
}
