package com.sentrix.core.wrappers

import com.google.gson.annotations.SerializedName

/**
 * APIResponse
 *
 * Responsibilities:
 * - Standardize API responses
 * - Handle success/error payloads
 * - Support pagination metadata
 * - Simplify network layer integration
 * - Improve API consistency
 */
data class APIResponse<T>(

    @SerializedName("success")
    val success: Boolean,

    @SerializedName("message")
    val message: String? = null,

    @SerializedName("data")
    val data: T? = null,

    @SerializedName("error_code")
    val errorCode: String? = null,

    @SerializedName("timestamp")
    val timestamp: Long =
        System.currentTimeMillis(),

    @SerializedName("pagination")
    val pagination: Pagination? = null
) {

    /**
     * Check success state.
     */
    fun isSuccessful(): Boolean {

        return success
    }

    /**
     * Check error state.
     */
    fun isError(): Boolean {

        return !success
    }

    /**
     * Get data safely.
     */
    fun getDataOrNull(): T? {

        return data
    }

    /**
     * Get message safely.
     */
    fun getMessageOrDefault(): String {

        return message
            ?: if (success) {
                "Operation successful"
            } else {
                "Operation failed"
            }
    }

    /**
     * Pagination metadata.
     */
    data class Pagination(

        @SerializedName("page")
        val page: Int,

        @SerializedName("page_size")
        val pageSize: Int,

        @SerializedName("total_pages")
        val totalPages: Int,

        @SerializedName("total_items")
        val totalItems: Long
    ) {

        /**
         * Check if next page exists.
         */
        fun hasNextPage(): Boolean {

            return page < totalPages
        }

        /**
         * Check if previous page exists.
         */
        fun hasPreviousPage(): Boolean {

            return page > 1
        }
    }

    companion object {

        /**
         * Create success response.
         */
        fun <T> success(
            data: T,
            message: String? = null
        ): APIResponse<T> {

            return APIResponse(
                success = true,
                message = message,
                data = data
            )
        }

        /**
         * Create error response.
         */
        fun <T> error(
            message: String,
            errorCode: String? = null
        ): APIResponse<T> {

            return APIResponse(
                success = false,
                message = message,
                errorCode = errorCode
            )
        }
    }
}
