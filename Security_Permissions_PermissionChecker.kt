package com.sentrix.security.permissions

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PermissionChecker
 *
 * Performs detailed permission-level security checks for Android
 * applications.
 *
 * Responsibilities:
 * - Check individual permission states.
 * - Check multiple permissions.
 * - Identify granted and denied permissions.
 * - Identify dangerous permissions.
 * - Identify sensitive permissions.
 * - Check whether permissions are declared.
 * - Evaluate permission states using Android permission APIs.
 * - Provide reusable security-check results.
 *
 * This class does NOT request permissions.
 * Permission requests should be handled by the appropriate Android
 * UI/application layer.
 *
 * Package:
 * com.sentrix.security.permissions
 */
class PermissionChecker(
    private val context: Context
) {

    private val applicationContext: Context =
        context.applicationContext

    private val packageManager: PackageManager =
        applicationContext.packageManager

    /**
     * Checks whether a specific permission is granted
     * to the specified package.
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
     * Checks whether a permission is denied.
     */
    fun isPermissionDenied(
        packageName: String,
        permission: String
    ): Boolean {

        return !isPermissionGranted(
            packageName,
            permission
        )
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
     * Checks multiple permissions and returns their states.
     */
    suspend fun checkPermissions(
        packageName: String,
        permissions: List<String>
    ): Map<String, PermissionState> =
        withContext(Dispatchers.IO) {

            permissions.associateWith { permission ->

                getPermissionState(
                    packageName = packageName,
                    permission = permission
                )
            }
        }

    /**
     * Returns all granted permissions from the supplied list.
     */
    suspend fun getGrantedPermissions(
        packageName: String,
        permissions: List<String>
    ): List<String> =
        withContext(Dispatchers.IO) {

            permissions.filter { permission ->
                isPermissionGranted(
                    packageName,
                    permission
                )
            }
        }

    /**
     * Returns all denied permissions from the supplied list.
     */
    suspend fun getDeniedPermissions(
        packageName: String,
        permissions: List<String>
    ): List<String> =
        withContext(Dispatchers.IO) {

            permissions.filter { permission ->
                isPermissionDenied(
                    packageName,
                    permission
                )
            }
        }

    /**
     * Checks whether an application has declared
     * the supplied permission.
     */
    fun isPermissionDeclared(
        packageName: String,
        permission: String
    ): Boolean {

        return try {

            val packageInfo =
                getPackageInfo(packageName)

            packageInfo.requestedPermissions
                ?.contains(permission)
                ?: false

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Determines the complete state of a permission.
     *
     * A permission can be:
     *
     * - NOT_DECLARED
     * - DENIED
     * - GRANTED
     * - UNKNOWN
     */
    fun getPermissionState(
        packageName: String,
        permission: String
    ): PermissionState {

        return try {

            if (!isPermissionDeclared(
                    packageName,
                    permission
                )
            ) {
                return PermissionState.NOT_DECLARED
            }

            if (isPermissionGranted(
                    packageName,
                    permission
                )
            ) {
                PermissionState.GRANTED
            } else {
                PermissionState.DENIED
            }

        } catch (_: Exception) {

            PermissionState.UNKNOWN
        }
    }

    /**
     * Determines whether a permission is classified as
     * dangerous by Android.
     */
    fun isDangerousPermission(
        permission: String
    ): Boolean {

        return try {

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

    /**
     * Determines whether a permission is considered
     * security-sensitive by SentriX.
     *
     * This is a SentriX security classification and is
     * intentionally stricter than Android's dangerous
     * permission classification.
     */
    fun isSensitivePermission(
        permission: String
    ): Boolean {

        return permission in sensitivePermissions
    }

    /**
     * Determines whether a permission is both granted
     * and security-sensitive.
     */
    fun isGrantedSensitivePermission(
        packageName: String,
        permission: String
    ): Boolean {

        return isSensitivePermission(permission) &&
                isPermissionGranted(
                    packageName,
                    permission
                )
    }

    /**
     * Returns sensitive permissions from a supplied list.
     */
    fun getSensitivePermissions(
        permissions: List<String>
    ): List<String> {

        return permissions.filter {
            isSensitivePermission(it)
        }
    }

    /**
     * Returns dangerous permissions from a supplied list.
     */
    fun getDangerousPermissions(
        permissions: List<String>
    ): List<String> {

        return permissions.filter {
            isDangerousPermission(it)
        }
    }

    /**
     * Returns permissions that are both dangerous and granted.
     */
    fun getGrantedDangerousPermissions(
        packageName: String,
        permissions: List<String>
    ): List<String> {

        return permissions.filter { permission ->

            isDangerousPermission(permission) &&
                    isPermissionGranted(
                        packageName,
                        permission
                    )
        }
    }

    /**
     * Performs a comprehensive security check for
     * one permission.
     */
    fun checkPermission(
        packageName: String,
        permission: String
    ): PermissionCheckResult {

        val declared =
            isPermissionDeclared(
                packageName,
                permission
            )

        val granted =
            if (declared) {
                isPermissionGranted(
                    packageName,
                    permission
                )
            } else {
                false
            }

        val dangerous =
            isDangerousPermission(permission)

        val sensitive =
            isSensitivePermission(permission)

        val risk =
            calculatePermissionRisk(
                declared = declared,
                granted = granted,
                dangerous = dangerous,
                sensitive = sensitive
            )

        return PermissionCheckResult(
            packageName = packageName,
            permission = permission,
            declared = declared,
            granted = granted,
            dangerous = dangerous,
            sensitive = sensitive,
            riskLevel = risk
        )
    }

    /**
     * Performs checks for multiple permissions.
     */
    suspend fun checkPermissionSet(
        packageName: String,
        permissions: List<String>
    ): List<PermissionCheckResult> =
        withContext(Dispatchers.IO) {

            permissions.map { permission ->

                checkPermission(
                    packageName = packageName,
                    permission = permission
                )
            }
        }

    /**
     * Checks the permission footprint of an application.
     */
    suspend fun checkApplicationPermissions(
        packageName: String
    ): PermissionCheckSummary =
        withContext(Dispatchers.IO) {

            val permissions =
                getRequestedPermissions(
                    packageName
                )

            val results =
                permissions.map { permission ->

                    checkPermission(
                        packageName = packageName,
                        permission = permission
                    )
                }

            val granted =
                results.filter {
                    it.granted
                }

            val denied =
                results.filter {
                    it.declared && !it.granted
                }

            val dangerous =
                results.filter {
                    it.dangerous
                }

            val sensitive =
                results.filter {
                    it.sensitive
                }

            val grantedSensitive =
                results.filter {
                    it.sensitive && it.granted
                }

            PermissionCheckSummary(
                packageName = packageName,
                totalPermissions = results.size,
                grantedPermissions = granted.size,
                deniedPermissions = denied.size,
                dangerousPermissions = dangerous.size,
                sensitivePermissions = sensitive.size,
                grantedSensitivePermissions =
                    grantedSensitive.size,
                results = results
            )
        }

    /**
     * Calculates a permission risk level.
     *
     * This is a heuristic indicator and should be combined with
     * other SentriX signals such as:
     *
     * - Malware analysis
     * - Application behavior
     * - Network activity
     * - Threat intelligence
     * - APK analysis
     * - Accessibility abuse
     * - Overlay activity
     */
    private fun calculatePermissionRisk(
        declared: Boolean,
        granted: Boolean,
        dangerous: Boolean,
        sensitive: Boolean
    ): PermissionRiskLevel {

        if (!declared) {
            return PermissionRiskLevel.LOW
        }

        if (!granted) {
            return PermissionRiskLevel.LOW
        }

        if (sensitive && dangerous) {
            return PermissionRiskLevel.HIGH
        }

        if (dangerous) {
            return PermissionRiskLevel.MEDIUM
        }

        if (sensitive) {
            return PermissionRiskLevel.MEDIUM
        }

        return PermissionRiskLevel.LOW
    }

    /**
     * Returns all permissions requested by an application.
     */
    private fun getRequestedPermissions(
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
     * Checks an AppOps operation for a package.
     *
     * Useful for operations where Android's permission state
     * alone does not provide the complete picture.
     */
    fun checkAppOperation(
        packageName: String,
        operation: String
    ): AppOperationState {

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

            val mode =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {

                    appOps.unsafeCheckOpNoThrow(
                        operation,
                        uid,
                        packageName
                    )

                } else {

                    @Suppress("DEPRECATION")
                    appOps.checkOpNoThrow(
                        operation,
                        uid,
                        packageName
                    )
                }

            when (mode) {

                AppOpsManager.MODE_ALLOWED ->
                    AppOperationState.ALLOWED

                AppOpsManager.MODE_IGNORED ->
                    AppOperationState.IGNORED

                AppOpsManager.MODE_ERRORED ->
                    AppOperationState.DENIED

                AppOpsManager.MODE_DEFAULT ->
                    AppOperationState.DEFAULT

                else ->
                    AppOperationState.UNKNOWN
            }

        } catch (_: Exception) {

            AppOperationState.UNKNOWN
        }
    }

    /**
     * Determines whether the package exists on the device.
     */
    fun isPackageAvailable(
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
     * Retrieves PackageInfo with Android-version compatibility.
     */
    @Suppress("DEPRECATION")
    private fun getPackageInfo(
        packageName: String
    ): android.content.pm.PackageInfo {

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.TIRAMISU
        ) {

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

    companion object {

        /**
         * Permissions considered highly sensitive by SentriX.
         *
         * These permissions should receive additional scrutiny
         * during threat analysis.
         */
        private val sensitivePermissions =
            setOf(

                // SMS
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS,

                // Contacts
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.WRITE_CONTACTS,

                // Calls
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.WRITE_CALL_LOG,
                Manifest.permission.CALL_PHONE,

                // Location
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,

                // Sensors / recording
                Manifest.permission.CAMERA,
                Manifest.permission.RECORD_AUDIO,

                // Device information
                Manifest.permission.READ_PHONE_STATE,

                // Calendar
                Manifest.permission.READ_CALENDAR,
                Manifest.permission.WRITE_CALENDAR,

                // Storage
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            )
    }
}

/**
 * Current state of an Android permission.
 */
enum class PermissionState {

    /**
     * Permission has not been declared by the application.
     */
    NOT_DECLARED,

    /**
     * Permission has been declared and granted.
     */
    GRANTED,

    /**
     * Permission has been declared but is not granted.
     */
    DENIED,

    /**
     * Permission state could not be determined.
     */
    UNKNOWN
}

/**
 * Result of checking one permission.
 */
data class PermissionCheckResult(

    val packageName: String,

    val permission: String,

    val declared: Boolean,

    val granted: Boolean,

    val dangerous: Boolean,

    val sensitive: Boolean,

    val riskLevel: PermissionRiskLevel
)

/**
 * Summary of an application's permission footprint.
 */
data class PermissionCheckSummary(

    val packageName: String,

    val totalPermissions: Int,

    val grantedPermissions: Int,

    val deniedPermissions: Int,

    val dangerousPermissions: Int,

    val sensitivePermissions: Int,

    val grantedSensitivePermissions: Int,

    val results: List<PermissionCheckResult>
) {

    /**
     * Indicates whether the application has any
     * sensitive permissions currently granted.
     */
    val hasGrantedSensitivePermissions: Boolean
        get() = grantedSensitivePermissions > 0

    /**
     * Indicates whether the application has a
     * significant permission footprint.
     */
    val hasHighPermissionFootprint: Boolean
        get() = totalPermissions >= 15

    /**
     * Indicates whether the application has dangerous
     * permissions.
     */
    val hasDangerousPermissions: Boolean
        get() = dangerousPermissions > 0
}

/**
 * State returned by an AppOps security check.
 */
enum class AppOperationState {

    ALLOWED,

    IGNORED,

    DENIED,

    DEFAULT,

    UNKNOWN
}
