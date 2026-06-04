package com.sentrix.core.managers

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.sentrix.core.enums.PermissionRisk

/**
 * PermissionManager
 *
 * Responsibilities:
 * - Runtime permission checking
 * - Permission requesting
 * - Permission risk analysis
 * - Dangerous permission detection
 * - Permission status reporting
 */
class PermissionManager(
    private val context: Context
) {

    /**
     * Check if permission is granted.
     */
    fun isPermissionGranted(
        permission: String
    ): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            permission
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Check multiple permissions.
     */
    fun arePermissionsGranted(
        permissions: Array<String>
    ): Boolean {
        return permissions.all {
            isPermissionGranted(it)
        }
    }

    /**
     * Request runtime permissions.
     */
    fun requestPermissions(
        activity: Activity,
        permissions: Array<String>,
        requestCode: Int
    ) {
        ActivityCompat.requestPermissions(
            activity,
            permissions,
            requestCode
        )
    }

    /**
     * Determine if rationale should be shown.
     */
    fun shouldShowRationale(
        activity: Activity,
        permission: String
    ): Boolean {
        return ActivityCompat
            .shouldShowRequestPermissionRationale(
                activity,
                permission
            )
    }

    /**
     * Get denied permissions.
     */
    fun getDeniedPermissions(
        permissions: Array<String>
    ): List<String> {
        return permissions.filterNot {
            isPermissionGranted(it)
        }
    }

    /**
     * Analyze permission risk level.
     */
    fun analyzePermissionRisk(
        permission: String
    ): PermissionRisk {

        return when (permission) {

            // Critical permissions
            android.Manifest.permission.READ_SMS,
            android.Manifest.permission.RECEIVE_SMS,
            android.Manifest.permission.SEND_SMS,
            android.Manifest.permission.READ_CALL_LOG,
            android.Manifest.permission.WRITE_CALL_LOG,
            android.Manifest.permission.PROCESS_OUTGOING_CALLS,
            android.Manifest.permission.SYSTEM_ALERT_WINDOW -> {
                PermissionRisk.CRITICAL
            }

            // High-risk permissions
            android.Manifest.permission.CAMERA,
            android.Manifest.permission.RECORD_AUDIO,
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.ACCESS_COARSE_LOCATION,
            android.Manifest.permission.READ_CONTACTS,
            android.Manifest.permission.WRITE_CONTACTS,
            android.Manifest.permission.READ_EXTERNAL_STORAGE,
            android.Manifest.permission.WRITE_EXTERNAL_STORAGE -> {
                PermissionRisk.HIGH
            }

            // Medium-risk permissions
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.POST_NOTIFICATIONS,
            android.Manifest.permission.READ_MEDIA_IMAGES,
            android.Manifest.permission.READ_MEDIA_VIDEO,
            android.Manifest.permission.READ_MEDIA_AUDIO -> {
                PermissionRisk.MEDIUM
            }

            else -> {
                PermissionRisk.LOW
            }
        }
    }

    /**
     * Calculate overall permission score.
     */
    fun calculatePermissionSecurityScore(
        permissions: Array<String>
    ): Int {

        var score = 100

        permissions.forEach { permission ->

            if (isPermissionGranted(permission)) {

                when (analyzePermissionRisk(permission)) {

                    PermissionRisk.CRITICAL -> score -= 20
                    PermissionRisk.HIGH -> score -= 10
                    PermissionRisk.MEDIUM -> score -= 5
                    PermissionRisk.LOW -> score -= 1
                }
            }
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Generate permission report.
     */
    fun generatePermissionReport(
        permissions: Array<String>
    ): String {

        val granted =
            permissions.count {
                isPermissionGranted(it)
            }

        val denied =
            permissions.size - granted

        return buildString {

            appendLine("Permission Report")
            appendLine("------------------------")
            appendLine("Total Permissions : ${permissions.size}")
            appendLine("Granted           : $granted")
            appendLine("Denied            : $denied")
            appendLine(
                "Security Score    : ${
                    calculatePermissionSecurityScore(
                        permissions
                    )
                }"
            )
        }
    }

    /**
     * Get permissions grouped by risk.
     */
    fun getPermissionsByRisk(
        permissions: Array<String>
    ): Map<PermissionRisk, List<String>> {

        return permissions.groupBy {
            analyzePermissionRisk(it)
        }
    }

    /**
     * Check if any critical permission exists.
     */
    fun hasCriticalPermissions(
        permissions: Array<String>
    ): Boolean {

        return permissions.any {
            analyzePermissionRisk(it) ==
                    PermissionRisk.CRITICAL
        }
    }

    companion object {

        const val DEFAULT_PERMISSION_REQUEST_CODE = 1001
    }
}
