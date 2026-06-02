package com.sentrix.ui.common

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

object PermissionUtils {

    // ----------------------------------------------------------------
    // PERMISSION REQUEST CODES
    // ----------------------------------------------------------------

    const val STORAGE_PERMISSION_REQUEST = 1001
    const val CAMERA_PERMISSION_REQUEST = 1002
    const val MICROPHONE_PERMISSION_REQUEST = 1003
    const val LOCATION_PERMISSION_REQUEST = 1004
    const val NOTIFICATION_PERMISSION_REQUEST = 1005

    // ----------------------------------------------------------------
    // STORAGE
    // ----------------------------------------------------------------

    fun hasStoragePermission(
        context: Context
    ): Boolean {

        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.READ_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED
    }

    fun requestStoragePermission(
        activity: Activity
    ) {

        ActivityCompat.requestPermissions(
            activity,
            arrayOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            ),
            STORAGE_PERMISSION_REQUEST
        )
    }

    // ----------------------------------------------------------------
    // CAMERA
    // ----------------------------------------------------------------

    fun hasCameraPermission(
        context: Context
    ): Boolean {

        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
    }

    fun requestCameraPermission(
        activity: Activity
    ) {

        ActivityCompat.requestPermissions(
            activity,
            arrayOf(
                Manifest.permission.CAMERA
            ),
            CAMERA_PERMISSION_REQUEST
        )
    }

    // ----------------------------------------------------------------
    // MICROPHONE
    // ----------------------------------------------------------------

    fun hasMicrophonePermission(
        context: Context
    ): Boolean {

        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED
    }

    fun requestMicrophonePermission(
        activity: Activity
    ) {

        ActivityCompat.requestPermissions(
            activity,
            arrayOf(
                Manifest.permission.RECORD_AUDIO
            ),
            MICROPHONE_PERMISSION_REQUEST
        )
    }

    // ----------------------------------------------------------------
    // LOCATION
    // ----------------------------------------------------------------

    fun hasLocationPermission(
        context: Context
    ): Boolean {

        val fineLocation =
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.ACCESS_FINE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED

        val coarseLocation =
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.ACCESS_COARSE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED

        return fineLocation || coarseLocation
    }

    fun requestLocationPermission(
        activity: Activity
    ) {

        ActivityCompat.requestPermissions(
            activity,
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            ),
            LOCATION_PERMISSION_REQUEST
        )
    }

    // ----------------------------------------------------------------
    // NOTIFICATIONS
    // ----------------------------------------------------------------

    fun hasNotificationPermission(
        context: Context
    ): Boolean {

        return if (android.os.Build.VERSION.SDK_INT >=
            android.os.Build.VERSION_CODES.TIRAMISU
        ) {

            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED

        } else {
            true
        }
    }

    fun requestNotificationPermission(
        activity: Activity
    ) {

        if (android.os.Build.VERSION.SDK_INT >=
            android.os.Build.VERSION_CODES.TIRAMISU
        ) {

            ActivityCompat.requestPermissions(
                activity,
                arrayOf(
                    Manifest.permission.POST_NOTIFICATIONS
                ),
                NOTIFICATION_PERMISSION_REQUEST
            )
        }
    }

    // ----------------------------------------------------------------
    // ALL CRITICAL PERMISSIONS
    // ----------------------------------------------------------------

    fun hasAllCriticalPermissions(
        context: Context
    ): Boolean {

        return hasStoragePermission(context) &&
                hasCameraPermission(context) &&
                hasMicrophonePermission(context) &&
                hasLocationPermission(context)
    }

    // ----------------------------------------------------------------
    // REQUEST ALL CRITICAL PERMISSIONS
    // ----------------------------------------------------------------

    fun requestAllCriticalPermissions(
        activity: Activity
    ) {

        val permissions = mutableListOf<String>()

        if (!hasStoragePermission(activity)) {

            permissions.add(
                Manifest.permission.READ_EXTERNAL_STORAGE
            )

            permissions.add(
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            )
        }

        if (!hasCameraPermission(activity)) {

            permissions.add(
                Manifest.permission.CAMERA
            )
        }

        if (!hasMicrophonePermission(activity)) {

            permissions.add(
                Manifest.permission.RECORD_AUDIO
            )
        }

        if (!hasLocationPermission(activity)) {

            permissions.add(
                Manifest.permission.ACCESS_FINE_LOCATION
            )

            permissions.add(
                Manifest.permission.ACCESS_COARSE_LOCATION
            )
        }

        if (
            android.os.Build.VERSION.SDK_INT >=
            android.os.Build.VERSION_CODES.TIRAMISU
        ) {

            if (!hasNotificationPermission(activity)) {

                permissions.add(
                    Manifest.permission.POST_NOTIFICATIONS
                )
            }
        }

        if (permissions.isNotEmpty()) {

            ActivityCompat.requestPermissions(
                activity,
                permissions.toTypedArray(),
                9999
            )
        }
    }

    // ----------------------------------------------------------------
    // SHOULD SHOW RATIONALE
    // ----------------------------------------------------------------

    fun shouldShowPermissionRationale(
        activity: Activity,
        permission: String
    ): Boolean {

        return ActivityCompat.shouldShowRequestPermissionRationale(
            activity,
            permission
        )
    }
}
