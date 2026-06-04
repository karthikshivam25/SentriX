package com.sentrix.core.wrappers

/**
 * Standard success wrapper used across the application.
 */
data class SuccessWrapper<T>(
    val data: T? = null,
    val message: String = "Operation completed successfully",
    val code: Int = 200,
    val timestamp: Long = System.currentTimeMillis()
) {

    fun hasData(): Boolean = data != null

    fun isSuccessful(): Boolean = code in 200..299

    companion object {

        fun <T> success(
            data: T,
            message: String = "Success",
            code: Int = 200
        ): SuccessWrapper<T> {
            return SuccessWrapper(
                data = data,
                message = message,
                code = code
            )
        }

        fun simple(
            message: String = "Operation completed successfully"
        ): SuccessWrapper<Unit> {
            return SuccessWrapper(
                data = Unit,
                message = message,
                code = 200
            )
        }
    }
}
