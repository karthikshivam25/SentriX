package com.sentrix.security.permissions

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PermissionManager
 *
 * Centralized manager responsible for inspecting and evaluating
 * Android application permissions.
 *
 * Responsibilities:
 * - Check whether permissions are granted.
 * - Inspect dangerous permissions.
 * - Detect denied permissions.
 * - Identify special permissions where applicable.
 * - Evaluate permission risk.
 * - Provide permission security summaries.
 *
 * This manager intentionally focuses on permission intelligence.
 * It does not request permissions from the user.
 *
 * Package:
 * com.sentrix.security.permissions
 */
class PermissionManager(
    private val context: Context
) {

    private val applicationContext: Context =
        context.applicationContext

    private val packageManager: PackageManager =
        applicationContext.packageManager

    /**
     * Returns all permissions declared by an application.
     */
    suspend fun getDeclaredPermissions(
        packageName: String
    ): List<String> = withContext(Dispatchers.IO) {

        try {
            val packageInfo = getPackageInfo(packageName)

            packageInfo.requestedPermissions
                ?.toList()
                ?: emptyList()

        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Returns permissions declared by an application
     * that are currently granted.
     */
    suspend fun getGrantedPermissions(
        packageName: String
    ): List<String> = withContext(Dispatchers.IO) {

        getDeclaredPermissions(packageName)
            .filter { permission ->
                isPermissionGranted(
                    packageName = packageName,
                    permission = permission
                )
            }
    }

    /**
     * Returns permissions declared by an application
     * that are not currently granted.
     */
    suspend fun getDeniedPermissions(
        packageName: String
    ): List<String> = withContext(Dispatchers.IO) {

        getDeclaredPermissions(packageName)
            .filterNot { permission ->
                isPermissionGranted(
                    packageName = packageName,
                    permission = permission
                )
            }
    }

    /**
     * Checks whether a specific permission is granted.
     */
    fun isPermissionGranted(
        packageName: String,
        permission: String
    ): Boolean {

        return try {
            packageManager.checkPermission(
                permission,
                packageName
            ) == PackageManager.PERMISSION_GRANTED

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Checks whether a permission is granted to SentriX itself.
     */
    fun isSelfPermissionGranted(
        permission: String
    ): Boolean {

        return ContextCompat.checkSelfPermission(
            applicationContext,
            permission
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Returns dangerous permissions declared by an application.
     *
     * Android protection levels can vary between releases,
     * therefore this method also safely handles permissions that
     * cannot be resolved.
     */
    suspend fun getDangerousPermissions(
        packageName: String
    ): List<String> = withContext(Dispatchers.IO) {

        getDeclaredPermissions(packageName)
            .filter { permission ->

                try {
                    val permissionInfo =
                        packageManager.getPermissionInfo(
                            permission,
                            0
                        )

                    val protectionLevel =
                        permissionInfo.protectionLevel and
                                PermissionInfo.PROTECTION_MASK_BASE

                    protectionLevel ==
                            PermissionInfo.PROTECTION_DANGEROUS

                } catch (_: Exception) {
                    false
                }
            }
    }

    /**
     * Returns dangerous permissions that are currently granted.
     */
    suspend fun getGrantedDangerousPermissions(
        packageName: String
    ): List<String> = withContext(Dispatchers.IO) {

        getDangerousPermissions(packageName)
            .filter { permission ->
                isPermissionGranted(
                    packageName,
                    permission
                )
            }
    }

    /**
     * Determines whether an application declares a
     * specific permission.
     */
    fun hasDeclaredPermission(
        packageName: String,
        permission: String
    ): Boolean {

        return try {
            getDeclaredPermissionsSync(packageName)
                .contains(permission)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Synchronous internal permission lookup.
     *
     * Used only for lightweight checks where launching a
     * coroutine would be unnecessary.
     */
    private fun getDeclaredPermissionsSync(
        packageName: String
    ): List<String> {

        return try {
            getPackageInfo(packageName)
                .requestedPermissions
                ?.toList()
                ?: emptyList()

        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Returns a complete permission security summary.
     */
    suspend fun analyzePermissions(
        packageName: String
    ): PermissionAnalysis = withContext(Dispatchers.IO) {

        val declared =
            getDeclaredPermissions(packageName)

        val granted =
            declared.filter { permission ->
                isPermissionGranted(
                    packageName,
                    permission
                )
            }

        val denied =
            declared.filterNot { permission ->
                isPermissionGranted(
                    packageName,
                    permission
                )
            }

        val dangerous =
            getDangerousPermissions(packageName)

        val grantedDangerous =
            dangerous.filter { permission ->
                isPermissionGranted(
                    packageName,
                    permission
                )
            }

        val riskLevel =
            calculatePermissionRisk(
                declaredPermissions = declared,
                dangerousPermissions = dangerous,
                grantedDangerousPermissions = grantedDangerous
            )

        PermissionAnalysis(
            packageName = packageName,
            declaredPermissions = declared,
            grantedPermissions = granted,
            deniedPermissions = denied,
            dangerousPermissions = dangerous,
            grantedDangerousPermissions = grantedDangerous,
            riskLevel = riskLevel
        )
    }

    /**
     * Calculates an overall permission risk level.
     *
     * This is intentionally heuristic.
     * Permission risk should not be treated as proof of malicious
     * behavior. SentriX can combine this result with behavioral,
     * malware, network and threat-intelligence analysis.
     */
    private fun calculatePermissionRisk(
        declaredPermissions: List<String>,
        dangerousPermissions: List<String>,
        grantedDangerousPermissions: List<String>
    ): PermissionRiskLevel {

        var score = 0

        // Large permission surface increases attack surface.
        if (declaredPermissions.size >= 10) {
            score += 15
        }

        if (declaredPermissions.size >= 20) {
            score += 15
        }

        // Dangerous permissions increase risk.
        score += grantedDangerousPermissions.size * 4

        // Particularly sensitive permission groups.
        val sensitivePermissions =
            setOf(
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS,
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.WRITE_CONTACTS,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,
                Manifest.permission.RECORD_AUDIO,
                Manifest.permission.CAMERA,
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.WRITE_CALL_LOG,
                Manifest.permission.READ_PHONE_STATE
            )

        val sensitiveGrantedCount =
            grantedDangerousPermissions.count {
                it in sensitivePermissions
            }

        score += sensitiveGrantedCount * 8

        return when {
            score >= 70 ->
                PermissionRiskLevel.CRITICAL

            score >= 45 ->
                PermissionRiskLevel.HIGH

            score >= 20 ->
                PermissionRiskLevel.MEDIUM

            else ->
                PermissionRiskLevel.LOW
        }
    }

    /**
     * Returns the application label associated with a package.
     */
    fun getApplicationLabel(
        packageName: String
    ): String? {

        return try {
            val applicationInfo =
                packageManager.getApplicationInfo(
                    packageName,
                    0
                )

            packageManager
                .getApplicationLabel(applicationInfo)
                .toString()

        } catch (_: Exception) {
            null
        }
    }

    /**
     * Returns whether the supplied package exists on the device.
     */
    fun isPackageInstalled(
        packageName: String
    ): Boolean {

        return try {
            packageManager.getApplicationInfo(
                packageName,
                0
            )

            true

        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    /**
     * Checks whether the application belongs to the
     * currently running Android process.
     */
    fun isCurrentProcessPackage(
        packageName: String
    ): Boolean {

        return applicationContext.packageName == packageName &&
                Process.myUid() == applicationContext.applicationInfo.uid
    }

    /**
     * Checks AppOps state for a package.
     *
     * AppOps is useful for permissions and operations that
     * require additional runtime policy evaluation.
     */
    fun checkAppOp(
        packageName: String,
        operation: String
    ): AppOpStatus {

        return try {

            val appOps =
                applicationContext.getSystemService(
                    Context.APP_OPS_SERVICE
                ) as AppOpsManager

            val uid =
                packageManager.getApplicationInfo(
                    packageName,
                    0
                ).uid

            @Suppress("DEPRECATION")
            val mode =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    appOps.unsafeCheckOpNoThrow(
                        operation,
                        uid,
                        packageName
                    )
                } else {
                    appOps.checkOpNoThrow(
                        operation,
                        uid,
                        packageName
                    )
                }

            when (mode) {

                AppOpsManager.MODE_ALLOWED ->
                    AppOpStatus.ALLOWED

                AppOpsManager.MODE_IGNORED ->
                    AppOpStatus.IGNORED

                AppOpsManager.MODE_ERRORED ->
                    AppOpStatus.DENIED

                AppOpsManager.MODE_DEFAULT ->
                    AppOpStatus.DEFAULT

                else ->
                    AppOpStatus.UNKNOWN
            }

        } catch (_: Exception) {
            AppOpStatus.UNKNOWN
        }
    }

    /**
     * Returns PackageInfo while handling Android API differences.
     */
    @Suppress("DEPRECATION")
    private fun getPackageInfo(
        packageName: String
    ): android.content.pm.PackageInfo {

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {

            packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(
                    PackageManager.GET_PERMISSIONS.toLong()
                )
            )

        } else {

            packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS
            )
        }
    }
}

/**
 * Result of SentriX permission analysis.
 */
data class PermissionAnalysis(
    val packageName: String,
    val declaredPermissions: List<String>,
    val grantedPermissions: List<String>,
    val deniedPermissions: List<String>,
    val dangerousPermissions: List<String>,
    val grantedDangerousPermissions: List<String>,
    val riskLevel: PermissionRiskLevel
) {

    /**
     * Total number of declared permissions.
     */
    val declaredCount: Int
        get() = declaredPermissions.size

    /**
     * Total number of granted permissions.
     */
    val grantedCount: Int
        get() = grantedPermissions.size

    /**
     * Total number of dangerous permissions.
     */
    val dangerousCount: Int
        get() = dangerousPermissions.size

    /**
     * Total number of granted dangerous permissions.
     */
    val grantedDangerousCount: Int
        get() = grantedDangerousPermissions.size

    /**
     * Indicates whether the application has a large
     * permission footprint.
     */
    val hasLargePermissionFootprint: Boolean
        get() = declaredCount >= 10
}

/**
 * SentriX permission risk classification.
 */
enum class PermissionRiskLevel {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * AppOps evaluation state.
 */
enum class AppOpStatus {

    ALLOWED,

    IGNORED,

    DENIED,

    DEFAULT,

    UNKNOWN
}
