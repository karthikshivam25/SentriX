package com.sentrix.core.wrappers

/**
 * Standardized error wrapper used across the application.
 */
data class ErrorWrapper(
    val code: Int? = null,
    val message: String,
    val description: String? = null,
    val throwable: Throwable? = null,
    val timestamp: Long = System.currentTimeMillis()
) {

    fun hasCode(): Boolean = code != null

    fun hasThrowable(): Boolean = throwable != null

    fun toReadableMessage(): String {
        return buildString {
            append(message)

            if (!description.isNullOrBlank()) {
                append(" - ")
                append(description)
            }

            if (code != null) {
                append(" (Code: ")
                append(code)
                append(")")
            }
        }
    }

    companion object {

        fun networkError(
            message: String = "Network connection failed",
            code: Int? = null,
            throwable: Throwable? = null
        ): ErrorWrapper {
            return ErrorWrapper(
                code = code,
                message = message,
                throwable = throwable
            )
        }

        fun validationError(
            message: String
        ): ErrorWrapper {
            return ErrorWrapper(
                message = message
            )
        }

        fun unknownError(
            throwable: Throwable? = null
        ): ErrorWrapper {
            return ErrorWrapper(
                message = "An unexpected error occurred",
                throwable = throwable
            )
        }
    }
}
