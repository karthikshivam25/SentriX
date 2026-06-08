package com.sentrix.domain.repositories

import com.sentrix.domain.models.AppPermission
import com.sentrix.domain.models.PermissionCategory
import com.sentrix.domain.models.PermissionRisk

/**
 * PermissionRepository
 *
 * Repository responsible for
 * managing application permissions
 * within the SentriX cybersecurity
 * platform.
 *
 * Used by:
 * - MonitorPermissionsUseCase
 * - PermissionAnalysisEngine
 * - SecurityDashboard
 * - PrivacyProtectionManager
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Retrieve permissions
 * - Store permission records
 * - Update permission status
 * - Analyze permission risks
 * - Support privacy protection
 */
interface PermissionRepository {

    /**
     * Retrieves all permissions.
     *
     * @return Permission list.
     */
    suspend fun getPermissions():
        List<AppPermission>

    /**
     * Retrieves permission
     * by identifier.
     *
     * @param permissionId Permission ID.
     *
     * @return Permission record.
     */
    suspend fun getPermissionById(
        permissionId: String
    ): AppPermission?

    /**
     * Saves permission record.
     *
     * @param permission Permission.
     */
    suspend fun savePermission(
        permission: AppPermission
    )

    /**
     * Updates permission record.
     *
     * @param permission Permission.
     */
    suspend fun updatePermission(
        permission: AppPermission
    )

    /**
     * Deletes permission record.
     *
     * @param permissionId Permission ID.
     */
    suspend fun deletePermission(
        permissionId: String
    )

    /**
     * Retrieves permissions
     * by risk level.
     *
     * @param risk Risk level.
     *
     * @return Permission list.
     */
    suspend fun getPermissionsByRisk(
        risk: PermissionRisk
    ): List<AppPermission>

    /**
     * Retrieves permissions
     * by category.
     *
     * @param category Permission category.
     *
     * @return Permission list.
     */
    suspend fun getPermissionsByCategory(
        category: PermissionCategory
    ): List<AppPermission>

    /**
     * Retrieves dangerous
     * permissions.
     *
     * @return Dangerous permissions.
     */
    suspend fun getDangerousPermissions():
        List<AppPermission>

    /**
     * Retrieves total
     * permission count.
     *
     * @return Permission count.
     */
    suspend fun getPermissionCount():
        Int
}

/**
 * AppPermission
 *
 * Represents an application
 * permission record.
 */
data class AppPermission(

    /**
     * Permission identifier.
     */
    val permissionId: String,

    /**
     * Application identifier.
     */
    val appId: String,

    /**
     * Application name.
     */
    val appName: String,

    /**
     * Permission name.
     */
    val permissionName: String,

    /**
     * Permission category.
     */
    val category:
        PermissionCategory,

    /**
     * Permission risk level.
     */
    val risk:
        PermissionRisk,

    /**
     * Granted status.
     */
    val isGranted: Boolean,

    /**
     * Permission timestamp.
     */
    val grantedAt: Long
)

/**
 * Permission categories.
 */
enum class PermissionCategory {

    /**
     * Camera permission.
     */
    CAMERA,

    /**
     * Microphone permission.
     */
    MICROPHONE,

    /**
     * Location permission.
     */
    LOCATION,

    /**
     * Contacts permission.
     */
    CONTACTS,

    /**
     * Storage permission.
     */
    STORAGE,

    /**
     * SMS permission.
     */
    SMS,

    /**
     * Phone permission.
     */
    PHONE,

    /**
     * Notification permission.
     */
    NOTIFICATIONS
}

/**
 * Permission risk levels.
 */
enum class PermissionRisk {

    /**
     * Low risk permission.
     */
    LOW,

    /**
     * Medium risk permission.
     */
    MEDIUM,

    /**
     * High risk permission.
     */
    HIGH,

    /**
     * Critical risk permission.
     */
    CRITICAL
}
