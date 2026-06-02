package com.sentrix.core.helpers

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

object PermissionHelper {

    // Permission Request Codes
    const val STORAGE_PERMISSION_REQUEST = 1001
    const val CAMERA_PERMISSION_REQUEST = 1002
    const val LOCATION_PERMISSION_REQUEST = 1003
    const val NOTIFICATION_PERMISSION_REQUEST = 1004
    const val MICROPHONE_PERMISSION_REQUEST = 1005

    /**
     * Check if a single permission is granted
     */
    fun isPermissionGranted(
        context: Context,
        permission: String
    ): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            permission
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Request a single permission
     */
    fun requestPermission(
        activity: Activity,
        permission: String,
        requestCode: Int
    ) {
        ActivityCompat.requestPermissions(
            activity,
            arrayOf(permission),
            requestCode
        )
    }

    /**
     * Check multiple permissions
     */
    fun arePermissionsGranted(
        context: Context,
        permissions: Array<String>
    ): Boolean {
        return permissions.all {
            isPermissionGranted(context, it)
        }
    }

    /**
     * Request multiple permissions
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
     * Check storage permissions
     */
    fun hasStoragePermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            true
        } else {
            isPermissionGranted(
                context,
                Manifest.permission.READ_EXTERNAL_STORAGE
            )
        }
    }

    /**
     * Request storage permissions
     */
    fun requestStoragePermission(activity: Activity) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            requestPermission(
                activity,
                Manifest.permission.READ_EXTERNAL_STORAGE,
                STORAGE_PERMISSION_REQUEST
            )
        }
    }

    /**
     * Check camera permission
     */
    fun hasCameraPermission(context: Context): Boolean {
        return isPermissionGranted(
            context,
            Manifest.permission.CAMERA
        )
    }

    /**
     * Request camera permission
     */
    fun requestCameraPermission(activity: Activity) {
        requestPermission(
            activity,
            Manifest.permission.CAMERA,
            CAMERA_PERMISSION_REQUEST
        )
    }

    /**
     * Check location permissions
     */
    fun hasLocationPermission(context: Context): Boolean {
        return isPermissionGranted(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    }

    /**
     * Request location permissions
     */
    fun requestLocationPermission(activity: Activity) {
        requestPermission(
            activity,
            Manifest.permission.ACCESS_FINE_LOCATION,
            LOCATION_PERMISSION_REQUEST
        )
    }

    /**
     * Check microphone permission
     */
    fun hasMicrophonePermission(context: Context): Boolean {
        return isPermissionGranted(
            context,
            Manifest.permission.RECORD_AUDIO
        )
    }

    /**
     * Request microphone permission
     */
    fun requestMicrophonePermission(activity: Activity) {
        requestPermission(
            activity,
            Manifest.permission.RECORD_AUDIO,
            MICROPHONE_PERMISSION_REQUEST
        )
    }

    /**
     * Check notification permission (Android 13+)
     */
    fun hasNotificationPermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            isPermissionGranted(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            )
        } else {
            true
        }
    }

    /**
     * Request notification permission
     */
    fun requestNotificationPermission(activity: Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermission(
                activity,
                Manifest.permission.POST_NOTIFICATIONS,
                NOTIFICATION_PERMISSION_REQUEST
            )
        }
    }

    /**
     * Check if permission rationale should be shown
     */
    fun shouldShowRationale(
        activity: Activity,
        permission: String
    ): Boolean {
        return ActivityCompat.shouldShowRequestPermissionRationale(
            activity,
            permission
        )
    }
}
