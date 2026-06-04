package com.sentrix.core.wrappers

import com.sentrix.core.enums.PermissionRisk

/**
 * Represents the result of a permission security analysis.
 */
data class PermissionResultWrapper(
    val permissionName: String,
    val isGranted: Boolean,
    val riskLevel: PermissionRisk,
    val description: String = "",
    val reason: String = "",
    val recommendation: String = "",
    val category: String = "",
    val analyzedAt: Long = System.currentTimeMillis(),
    val metadata: Map<String, Any> = emptyMap()
) {

    /**
     * Returns true if the permission is considered dangerous.
     */
    fun isHighRisk(): Boolean {
        return riskLevel == PermissionRisk.HIGH ||
                riskLevel == PermissionRisk.CRITICAL
    }

    /**
     * Returns true if permission has been granted.
     */
    fun isAllowed(): Boolean = isGranted

    /**
     * Returns true if additional information exists.
     */
    fun hasMetadata(): Boolean = metadata.isNotEmpty()

    /**
     * Returns a user-friendly risk label.
     */
    fun getRiskLabel(): String {
        return when (riskLevel) {
            PermissionRisk.LOW -> "Low"
            PermissionRisk.MEDIUM -> "Medium"
            PermissionRisk.HIGH -> "High"
            PermissionRisk.CRITICAL -> "Critical"
            PermissionRisk.UNKNOWN -> "Unknown"
        }
    }

    /**
     * Returns whether a recommendation is available.
     */
    fun hasRecommendation(): Boolean =
        recommendation.isNotBlank()

    companion object {

        fun empty(): PermissionResultWrapper {
            return PermissionResultWrapper(
                permissionName = "",
                isGranted = false,
                riskLevel = PermissionRisk.UNKNOWN
            )
        }
    }
}
