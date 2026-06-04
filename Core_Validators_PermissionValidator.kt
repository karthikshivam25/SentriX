package com.sentrix.core.validators

import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import com.sentrix.core.exceptions.InvalidPermissionException
import com.sentrix.core.exceptions.RequiredFieldException

/**
 * PermissionValidator
 *
 * Responsibilities:
 * - Android permission validation
 * - Runtime permission checks
 * - Permission state verification
 * - Security permission analysis
 * - Permission risk detection
 */
object PermissionValidator {

    /**
     * Validate permission name.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidPermissionException::class
    )
    fun validate(
        permission: String?
    ): Boolean {

        if (permission.isNullOrBlank()) {
            throw RequiredFieldException(
                "Permission"
            )
        }

        if (
            !permission.startsWith(
                "android.permission."
            )
        ) {
            throw InvalidPermissionException(
                "Invalid Android permission."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        permission: String?
    ): Boolean {

        return try {

            validate(permission)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if permission is granted.
     */
    fun isGranted(
        context: Context,
        permission: String
    ): Boolean {

        return ContextCompat.checkSelfPermission(
            context,
            permission
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Check if permission is dangerous.
     */
    fun isDangerous(
        permission: String
    ): Boolean {

        val dangerousPermissions = setOf(
            android.Manifest.permission.CAMERA,
            android.Manifest.permission.RECORD_AUDIO,
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.ACCESS_COARSE_LOCATION,
            android.Manifest.permission.READ_CONTACTS,
            android.Manifest.permission.WRITE_CONTACTS,
            android.Manifest.permission.READ_CALENDAR,
            android.Manifest.permission.WRITE_CALENDAR,
            android.Manifest.permission.READ_SMS,
            android.Manifest.permission.SEND_SMS,
            android.Manifest.permission.RECEIVE_SMS,
            android.Manifest.permission.READ_PHONE_STATE,
            android.Manifest.permission.POST_NOTIFICATIONS
        )

        return dangerousPermissions.contains(
            permission
        )
    }

    /**
     * Get permission risk level.
     */
    fun getRiskLevel(
        permission: String
    ): String {

        return when {

            isDangerous(permission) ->
                "High"

            permission.contains(
                "INTERNET"
            ) ->
                "Medium"

            else ->
                "Low"
        }
    }

    /**
     * Check if permission is location related.
     */
    fun isLocationPermission(
        permission: String
    ): Boolean {

        return permission == android.Manifest.permission.ACCESS_FINE_LOCATION ||
                permission == android.Manifest.permission.ACCESS_COARSE_LOCATION
    }

    /**
     * Check if permission is camera related.
     */
    fun isCameraPermission(
        permission: String
    ): Boolean {

        return permission ==
                android.Manifest.permission.CAMERA
    }

    /**
     * Generate permission summary.
     */
    fun getSummary(
        permission: String
    ): String {

        return buildString {

            appendLine(
                "Permission: $permission"
            )

            appendLine(
                "Dangerous: ${isDangerous(permission)}"
            )

            appendLine(
                "Risk Level: ${getRiskLevel(permission)}"
            )

            appendLine(
                "Location Related: ${
                    isLocationPermission(
                        permission
                    )
                }"
            )
        }
    }
}
