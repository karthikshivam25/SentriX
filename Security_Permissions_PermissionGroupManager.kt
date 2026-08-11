package com.sentrix.security.permissions

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PermissionGroupManager
 *
 * Centralized manager for organizing Android permissions into
 * logical security and privacy groups.
 *
 * Responsibilities:
 * - Group permissions by security category.
 * - Determine which permission groups are declared.
 * - Determine which permission groups are granted.
 * - Identify high-risk permission groups.
 * - Calculate permission-group exposure.
 * - Provide group-level summaries for SentriX analysis.
 *
 * This class does NOT request or revoke permissions.
 *
 * Architecture:
 *
 * PermissionManager
 *        ↓
 * PermissionChecker
 *        ↓
 * PermissionGroupManager
 *        ↓
 * PermissionAnalyzer
 *        ↓
 * PermissionRiskAnalyzer
 */
class PermissionGroupManager(
    private val context: Context,
    private val permissionChecker: PermissionChecker =
        PermissionChecker(context)
) {

    private val applicationContext =
        context.applicationContext

    /**
     * Returns all permission groups supported by SentriX.
     */
    fun getAllGroups(): List<PermissionGroup> =
        PermissionGroupCatalog.allGroups

    /**
     * Returns a specific permission group.
     */
    fun getGroup(
        groupId: String
    ): PermissionGroup? {

        return PermissionGroupCatalog.allGroups
            .firstOrNull {
                it.id.equals(
                    groupId,
                    ignoreCase = true
                )
            }
    }

    /**
     * Returns the group associated with a permission.
     */
    fun getGroupForPermission(
        permission: String
    ): PermissionGroup? {

        return PermissionGroupCatalog.allGroups
            .firstOrNull {
                permission in it.permissions
            }
    }

    /**
     * Returns all groups associated with a permission.
     *
     * Usually one permission belongs to one primary SentriX
     * group, but this method returns a list to support future
     * overlapping classifications.
     */
    fun getGroupsForPermission(
        permission: String
    ): List<PermissionGroup> {

        return PermissionGroupCatalog.allGroups
            .filter {
                permission in it.permissions
            }
    }

    /**
     * Groups a list of permissions.
     */
    fun groupPermissions(
        permissions: List<String>
    ): Map<PermissionGroup, List<String>> {

        val result =
            linkedMapOf<PermissionGroup, MutableList<String>>()

        permissions.forEach { permission ->

            val group =
                getGroupForPermission(permission)

            if (group != null) {

                result
                    .getOrPut(group) {
                        mutableListOf()
                    }
                    .add(permission)
            }
        }

        return result
    }

    /**
     * Groups permissions while preserving permissions that
     * do not have a SentriX classification.
     */
    fun groupPermissionsWithUnknown(
        permissions: List<String>
    ): PermissionGroupingResult {

        val grouped =
            linkedMapOf<PermissionGroup, MutableList<String>>()

        val unknown =
            mutableListOf<String>()

        permissions.forEach { permission ->

            val group =
                getGroupForPermission(permission)

            if (group != null) {

                grouped
                    .getOrPut(group) {
                        mutableListOf()
                    }
                    .add(permission)

            } else {

                unknown += permission
            }
        }

        return PermissionGroupingResult(
            groups = grouped.mapValues {
                it.value.toList()
            },
            unknownPermissions = unknown
        )
    }

    /**
     * Returns groups that contain at least one permission
     * from the supplied list.
     */
    fun findActiveGroups(
        permissions: List<String>
    ): List<PermissionGroup> {

        val permissionSet =
            permissions.toSet()

        return PermissionGroupCatalog.allGroups
            .filter { group ->

                group.permissions.any {
                    it in permissionSet
                }
            }
    }

    /**
     * Returns groups that contain at least one granted
     * permission.
     */
    fun findGrantedGroups(
        packageName: String,
        permissions: List<String>
    ): List<PermissionGroup> {

        val grantedPermissions =
            permissions.filter {
                permissionChecker.isPermissionGranted(
                    packageName,
                    it
                )
            }

        return findActiveGroups(
            grantedPermissions
        )
    }

    /**
     * Performs a complete group-level analysis.
     */
    suspend fun analyzeGroups(
        packageName: String
    ): PermissionGroupAnalysis =
        withContext(Dispatchers.IO) {

            if (
                !permissionChecker.isPackageAvailable(
                    packageName
                )
            ) {

                return@withContext PermissionGroupAnalysis(
                    packageName = packageName,
                    status =
                        PermissionGroupAnalysisStatus
                            .PACKAGE_NOT_FOUND,
                    groups = emptyList(),
                    activeGroupCount = 0,
                    grantedGroupCount = 0,
                    highRiskGroupCount = 0,
                    criticalGroupCount = 0,
                    exposureScore = 0
                )
            }

            val permissions =
                getRequestedPermissions(
                    packageName
                )

            val groupResults =
                PermissionGroupCatalog.allGroups.mapNotNull { group ->

                    analyzeGroup(
                        packageName = packageName,
                        group = group,
                        declaredPermissions = permissions
                    )
                }

            val active =
                groupResults.filter {
                    it.declaredPermissions.isNotEmpty()
                }

            val granted =
                groupResults.filter {
                    it.grantedPermissions.isNotEmpty()
                }

            val highRisk =
                active.filter {
                    it.riskLevel ==
                            PermissionGroupRiskLevel.HIGH ||
                            it.riskLevel ==
                            PermissionGroupRiskLevel.CRITICAL
                }

            val critical =
                active.filter {
                    it.riskLevel ==
                            PermissionGroupRiskLevel.CRITICAL
                }

            val exposureScore =
                calculateExposureScore(
                    groupResults
                )

            PermissionGroupAnalysis(
                packageName = packageName,
                status =
                    PermissionGroupAnalysisStatus.COMPLETED,
                groups = groupResults,
                activeGroupCount = active.size,
                grantedGroupCount = granted.size,
                highRiskGroupCount = highRisk.size,
                criticalGroupCount = critical.size,
                exposureScore = exposureScore
            )
        }

    /**
     * Analyzes one permission group.
     */
    private fun analyzeGroup(
        packageName: String,
        group: PermissionGroup,
        declaredPermissions: List<String>
    ): PermissionGroupResult {

        val declared =
            declaredPermissions.filter {
                it in group.permissions
            }

        if (declared.isEmpty()) {
            return PermissionGroupResult(
                group = group,
                declaredPermissions = emptyList(),
                grantedPermissions = emptyList(),
                deniedPermissions = emptyList(),
                grantRatio = 0f,
                riskLevel = PermissionGroupRiskLevel.LOW
            )
        }

        val granted =
            declared.filter {
                permissionChecker.isPermissionGranted(
                    packageName,
                    it
                )
            }

        val denied =
            declared.filterNot {
                it in granted
            }

        val grantRatio =
            if (declared.isNotEmpty()) {
                granted.size.toFloat() /
                        declared.size.toFloat()
            } else {
                0f
            }

        val riskLevel =
            calculateGroupRisk(
                group = group,
                grantedPermissions = granted
            )

        return PermissionGroupResult(
            group = group,
            declaredPermissions = declared,
            grantedPermissions = granted,
            deniedPermissions = denied,
            grantRatio = grantRatio,
            riskLevel = riskLevel
        )
    }

    /**
     * Calculates risk for a permission group.
     *
     * Group criticality is defined by the SentriX catalog.
     * A permission being granted does not automatically mean
     * that the application is malicious.
     */
    private fun calculateGroupRisk(
        group: PermissionGroup,
        grantedPermissions: List<String>
    ): PermissionGroupRiskLevel {

        if (grantedPermissions.isEmpty()) {
            return PermissionGroupRiskLevel.LOW
        }

        return when {

            group.criticality >= 90 ->
                PermissionGroupRiskLevel.CRITICAL

            group.criticality >= 70 ->
                PermissionGroupRiskLevel.HIGH

            group.criticality >= 40 ->
                PermissionGroupRiskLevel.MEDIUM

            else ->
                PermissionGroupRiskLevel.LOW
        }
    }

    /**
     * Calculates overall permission-group exposure.
     *
     * Score range: 0..100.
     */
    private fun calculateExposureScore(
        groups: List<PermissionGroupResult>
    ): Int {

        val activeGroups =
            groups.filter {
                it.grantedPermissions.isNotEmpty()
            }

        if (activeGroups.isEmpty()) {
            return 0
        }

        var score = 0

        activeGroups.forEach { result ->

            val group =
                result.group

            val grantedRatio =
                result.grantRatio

            val contribution =
                (
                    group.criticality *
                            grantedRatio
                    ).toInt()

            score += contribution
        }

        /*
         * Multiple high-risk groups increase the overall
         * attack/privacy surface.
         */
        val highRiskGroups =
            activeGroups.count {
                it.riskLevel ==
                        PermissionGroupRiskLevel.HIGH ||
                        it.riskLevel ==
                        PermissionGroupRiskLevel.CRITICAL
            }

        if (highRiskGroups >= 3) {
            score += 15
        }

        if (highRiskGroups >= 5) {
            score += 10
        }

        return score.coerceIn(
            0,
            100
        )
    }

    /**
     * Returns the most security-sensitive active groups.
     */
    fun getHighRiskGroups(
        packageName: String,
        permissions: List<String>
    ): List<PermissionGroup> {

        val grantedGroups =
            findGrantedGroups(
                packageName,
                permissions
            )

        return grantedGroups.filter {
            it.criticality >= 70
        }
    }

    /**
     * Returns whether an application has a particular
     * permission group granted.
     */
    fun hasGrantedGroup(
        packageName: String,
        permissions: List<String>,
        groupId: String
    ): Boolean {

        val group =
            getGroup(groupId)
                ?: return false

        return group.permissions.any { permission ->

            permission in permissions &&
                    permissionChecker.isPermissionGranted(
                        packageName,
                        permission
                    )
        }
    }

    /**
     * Returns granted permissions belonging to a group.
     */
    fun getGrantedPermissionsForGroup(
        packageName: String,
        permissions: List<String>,
        groupId: String
    ): List<String> {

        val group =
            getGroup(groupId)
                ?: return emptyList()

        return permissions.filter { permission ->

            permission in group.permissions &&
                    permissionChecker.isPermissionGranted(
                        packageName,
                        permission
                    )
        }
    }

    /**
     * Returns declared permissions belonging to a group.
     */
    fun getDeclaredPermissionsForGroup(
        permissions: List<String>,
        groupId: String
    ): List<String> {

        val group =
            getGroup(groupId)
                ?: return emptyList()

        return permissions.filter {
            it in group.permissions
        }
    }

    /**
     * Returns requested permissions for a package.
     */
    @Suppress("DEPRECATION")
    private fun getRequestedPermissions(
        packageName: String
    ): List<String> {

        return try {

            val packageInfo =
                if (
                    android.os.Build.VERSION.SDK_INT >=
                    android.os.Build.VERSION_CODES.TIRAMISU
                ) {

                    applicationContext
                        .packageManager
                        .getPackageInfo(
                            packageName,
                            PackageManager.PackageInfoFlags.of(
                                PackageManager.GET_PERMISSIONS
                                    .toLong()
                            )
                        )

                } else {

                    applicationContext
                        .packageManager
                        .getPackageInfo(
                            packageName,
                            PackageManager.GET_PERMISSIONS
                        )
                }

            packageInfo.requestedPermissions
                ?.toList()
                ?: emptyList()

        } catch (_: Exception) {

            emptyList()
        }
    }
}

/**
 * Definition of a SentriX permission group.
 *
 * @param id Unique machine-readable identifier.
 * @param displayName Human-readable group name.
 * @param description Security meaning of the group.
 * @param permissions Android permissions belonging to the group.
 * @param criticality SentriX criticality from 0..100.
 */
data class PermissionGroup(

    val id: String,

    val displayName: String,

    val description: String,

    val permissions: Set<String>,

    val criticality: Int
) {

    init {
        require(
            criticality in 0..100
        ) {
            "Permission group criticality must be between 0 and 100."
        }
    }
}

/**
 * Result of grouping a permission collection.
 */
data class PermissionGroupingResult(

    val groups: Map<PermissionGroup, List<String>>,

    val unknownPermissions: List<String>
)

/**
 * Detailed analysis of one permission group.
 */
data class PermissionGroupResult(

    val group: PermissionGroup,

    val declaredPermissions: List<String>,

    val grantedPermissions: List<String>,

    val deniedPermissions: List<String>,

    val grantRatio: Float,

    val riskLevel: PermissionGroupRiskLevel
) {

    /**
     * Indicates whether this group is active.
     */
    val isActive: Boolean
        get() = grantedPermissions.isNotEmpty()

    /**
     * Indicates whether every declared permission in the group
     * is currently granted.
     */
    val isFullyGranted: Boolean
        get() =
            declaredPermissions.isNotEmpty() &&
                    grantedPermissions.size ==
                    declaredPermissions.size
}

/**
 * Complete group-level permission analysis.
 */
data class PermissionGroupAnalysis(

    val packageName: String,

    val status: PermissionGroupAnalysisStatus,

    val groups: List<PermissionGroupResult>,

    val activeGroupCount: Int,

    val grantedGroupCount: Int,

    val highRiskGroupCount: Int,

    val criticalGroupCount: Int,

    val exposureScore: Int
) {

    /**
     * Returns only active permission groups.
     */
    val activeGroups: List<PermissionGroupResult>
        get() =
            groups.filter {
                it.isActive
            }

    /**
     * Indicates whether the application has
     * high-risk permission exposure.
     */
    val hasHighRiskExposure: Boolean
        get() =
            highRiskGroupCount > 0

    /**
     * Indicates whether critical permission groups
     * are currently granted.
     */
    val hasCriticalExposure: Boolean
        get() =
            criticalGroupCount > 0
}

/**
 * Permission group analysis execution status.
 */
enum class PermissionGroupAnalysisStatus {

    COMPLETED,

    PACKAGE_NOT_FOUND
}

/**
 * Risk level of a permission group.
 */
enum class PermissionGroupRiskLevel {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Central catalog of SentriX permission groups.
 *
 * Keeping permission definitions here avoids scattering
 * permission lists throughout the security module.
 */
object PermissionGroupCatalog {

    /**
     * SMS and messaging permissions.
     */
    val SMS =
        PermissionGroup(
            id = "SMS",
            displayName = "SMS & Messaging",
            description =
                "Permissions that can access, receive or send " +
                "SMS messages.",
            permissions = setOf(
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS
            ),
            criticality = 90
        )

    /**
     * Contacts permissions.
     */
    val CONTACTS =
        PermissionGroup(
            id = "CONTACTS",
            displayName = "Contacts",
            description =
                "Permissions that can access or modify " +
                "device contacts.",
            permissions = setOf(
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.WRITE_CONTACTS
            ),
            criticality = 65
        )

    /**
     * Call and phone permissions.
     */
    val PHONE =
        PermissionGroup(
            id = "PHONE",
            displayName = "Phone & Calls",
            description =
                "Permissions associated with phone calls and " +
                "call-related information.",
            permissions = setOf(
                Manifest.permission.READ_PHONE_STATE,
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.WRITE_CALL_LOG,
                Manifest.permission.CALL_PHONE,
                Manifest.permission.ANSWER_PHONE_CALLS,
                Manifest.permission.ADD_VOICEMAIL
            ),
            criticality = 85
        )

    /**
     * Location permissions.
     */
    val LOCATION =
        PermissionGroup(
            id = "LOCATION",
            displayName = "Location",
            description =
                "Permissions that provide access to approximate " +
                "or precise device location.",
            permissions = setOf(
                Manifest.permission.ACCESS_COARSE_LOCATION,
                Manifest.permission.ACCESS_FINE_LOCATION
            ),
            criticality = 75
        )

    /**
     * Camera permissions.
     */
    val CAMERA =
        PermissionGroup(
            id = "CAMERA",
            displayName = "Camera",
            description =
                "Permissions that provide access to the device camera.",
            permissions = setOf(
                Manifest.permission.CAMERA
            ),
            criticality = 70
        )

    /**
     * Microphone/audio permissions.
     */
    val MICROPHONE =
        PermissionGroup(
            id = "MICROPHONE",
            displayName = "Microphone",
            description =
                "Permissions that provide access to microphone/audio " +
                "recording capabilities.",
            permissions = setOf(
                Manifest.permission.RECORD_AUDIO
            ),
            criticality = 75
        )

    /**
     * Calendar permissions.
     */
    val CALENDAR =
        PermissionGroup(
            id = "CALENDAR",
            displayName = "Calendar",
            description =
                "Permissions that provide access to calendar data.",
            permissions = setOf(
                Manifest.permission.READ_CALENDAR,
                Manifest.permission.WRITE_CALENDAR
            ),
            criticality = 50
        )

    /**
     * Storage permissions.
     *
     * These permissions have changed significantly across Android
     * versions, so downstream analysis should consider API level.
     */
    val STORAGE =
        PermissionGroup(
            id = "STORAGE",
            displayName = "External Storage",
            description =
                "Legacy permissions for reading or writing " +
                "external storage.",
            permissions = setOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            ),
            criticality = 65
        )

    /**
     * Notification-related permission.
     */
    val NOTIFICATIONS =
        PermissionGroup(
            id = "NOTIFICATIONS",
            displayName = "Notifications",
            description =
                "Permission controlling application notification delivery.",
            permissions = setOf(
                Manifest.permission.POST_NOTIFICATIONS
            ),
            criticality = 35
        )

    /**
     * Bluetooth-related permissions.
     *
     * Android 12+ introduced the runtime Bluetooth permission model.
     */
    val BLUETOOTH =
        PermissionGroup(
            id = "BLUETOOTH",
            displayName = "Bluetooth",
            description =
                "Permissions associated with nearby Bluetooth devices.",
            permissions = setOf(
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ),
            criticality = 50
        )

    /**
     * Nearby Wi-Fi/device discovery permissions.
     */
    val NEARBY_DEVICES =
        PermissionGroup(
            id = "NEARBY_DEVICES",
            displayName = "Nearby Devices",
            description =
                "Permissions that allow discovery or communication " +
                "with nearby devices.",
            permissions = setOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ),
            criticality = 55
        )

    /**
     * Media access permissions.
     *
     * Android introduced granular media permissions in newer versions.
     */
    val MEDIA =
        PermissionGroup(
            id = "MEDIA",
            displayName = "Media",
            description =
                "Permissions that provide access to user media files.",
            permissions = setOf(
                Manifest.permission.READ_MEDIA_IMAGES,
                Manifest.permission.READ_MEDIA_VIDEO,
                Manifest.permission.READ_MEDIA_AUDIO
            ),
            criticality = 60
        )

    /**
     * Body sensor permissions.
     */
    val SENSORS =
        PermissionGroup(
            id = "SENSORS",
            displayName = "Body Sensors",
            description =
                "Permissions that provide access to supported " +
                "body-sensor data.",
            permissions = setOf(
                Manifest.permission.BODY_SENSORS,
                Manifest.permission.BODY_SENSORS_BACKGROUND
            ),
            criticality = 65
        )

    /**
     * Activity recognition.
     */
    val ACTIVITY =
        PermissionGroup(
            id = "ACTIVITY",
            displayName = "Physical Activity",
            description =
                "Permission for accessing physical activity information.",
            permissions = setOf(
                Manifest.permission.ACTIVITY_RECOGNITION
            ),
            criticality = 45
        )

    /**
     * All supported SentriX groups.
     *
     * Order is intentionally stable for deterministic reports.
     */
    val allGroups: List<PermissionGroup> =
        listOf(
            SMS,
            CONTACTS,
            PHONE,
            LOCATION,
            CAMERA,
            MICROPHONE,
            CALENDAR,
            STORAGE,
            NOTIFICATIONS,
            BLUETOOTH,
            NEARBY_DEVICES,
            MEDIA,
            SENSORS,
            ACTIVITY
        )
}
