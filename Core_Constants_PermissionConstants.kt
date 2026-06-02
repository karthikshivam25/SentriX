package com.sentrix.core.constants

object PermissionConstants {

    /* ============================================================
     * CAMERA PERMISSIONS
     * ============================================================ */

    const val CAMERA =
        android.Manifest.permission.CAMERA

    /* ============================================================
     * STORAGE PERMISSIONS
     * ============================================================ */

    const val READ_EXTERNAL_STORAGE =
        android.Manifest.permission.READ_EXTERNAL_STORAGE

    const val WRITE_EXTERNAL_STORAGE =
        android.Manifest.permission.WRITE_EXTERNAL_STORAGE

    const val MANAGE_EXTERNAL_STORAGE =
        android.Manifest.permission.MANAGE_EXTERNAL_STORAGE

    /* ============================================================
     * LOCATION PERMISSIONS
     * ============================================================ */

    const val ACCESS_FINE_LOCATION =
        android.Manifest.permission.ACCESS_FINE_LOCATION

    const val ACCESS_COARSE_LOCATION =
        android.Manifest.permission.ACCESS_COARSE_LOCATION

    const val ACCESS_BACKGROUND_LOCATION =
        android.Manifest.permission.ACCESS_BACKGROUND_LOCATION

    /* ============================================================
     * MICROPHONE PERMISSIONS
     * ============================================================ */

    const val RECORD_AUDIO =
        android.Manifest.permission.RECORD_AUDIO

    /* ============================================================
     * PHONE & DEVICE PERMISSIONS
     * ============================================================ */

    const val READ_PHONE_STATE =
        android.Manifest.permission.READ_PHONE_STATE

    const val CALL_PHONE =
        android.Manifest.permission.CALL_PHONE

    const val READ_CONTACTS =
        android.Manifest.permission.READ_CONTACTS

    const val READ_SMS =
        android.Manifest.permission.READ_SMS

    const val RECEIVE_SMS =
        android.Manifest.permission.RECEIVE_SMS

    const val SEND_SMS =
        android.Manifest.permission.SEND_SMS

    /* ============================================================
     * NETWORK PERMISSIONS
     * ============================================================ */

    const val INTERNET =
        android.Manifest.permission.INTERNET

    const val ACCESS_NETWORK_STATE =
        android.Manifest.permission.ACCESS_NETWORK_STATE

    const val ACCESS_WIFI_STATE =
        android.Manifest.permission.ACCESS_WIFI_STATE

    const val CHANGE_WIFI_STATE =
        android.Manifest.permission.CHANGE_WIFI_STATE

    /* ============================================================
     * BLUETOOTH PERMISSIONS
     * ============================================================ */

    const val BLUETOOTH =
        android.Manifest.permission.BLUETOOTH

    const val BLUETOOTH_ADMIN =
        android.Manifest.permission.BLUETOOTH_ADMIN

    const val BLUETOOTH_CONNECT =
        android.Manifest.permission.BLUETOOTH_CONNECT

    const val BLUETOOTH_SCAN =
        android.Manifest.permission.BLUETOOTH_SCAN

    /* ============================================================
     * BIOMETRIC & SECURITY
     * ============================================================ */

    const val USE_BIOMETRIC =
        android.Manifest.permission.USE_BIOMETRIC

    const val USE_FINGERPRINT =
        android.Manifest.permission.USE_FINGERPRINT

    /* ============================================================
     * NOTIFICATION PERMISSIONS
     * ============================================================ */

    const val POST_NOTIFICATIONS =
        android.Manifest.permission.POST_NOTIFICATIONS

    /* ============================================================
     * PACKAGE & APP ANALYSIS
     * ============================================================ */

    const val QUERY_ALL_PACKAGES =
        android.Manifest.permission.QUERY_ALL_PACKAGES

    /* ============================================================
     * FOREGROUND SERVICE
     * ============================================================ */

    const val FOREGROUND_SERVICE =
        android.Manifest.permission.FOREGROUND_SERVICE

    /* ============================================================
     * PERMISSION GROUPS
     * ============================================================ */

    val STORAGE_PERMISSIONS = arrayOf(
        READ_EXTERNAL_STORAGE,
        WRITE_EXTERNAL_STORAGE
    )

    val LOCATION_PERMISSIONS = arrayOf(
        ACCESS_FINE_LOCATION,
        ACCESS_COARSE_LOCATION
    )

    val BLUETOOTH_PERMISSIONS = arrayOf(
        BLUETOOTH_CONNECT,
        BLUETOOTH_SCAN
    )

    val NETWORK_PERMISSIONS = arrayOf(
        INTERNET,
        ACCESS_NETWORK_STATE,
        ACCESS_WIFI_STATE
    )

    /* ============================================================
     * HIGH RISK PERMISSIONS
     * ============================================================ */

    val HIGH_RISK_PERMISSIONS = listOf(
        READ_SMS,
        RECEIVE_SMS,
        SEND_SMS,
        READ_CONTACTS,
        RECORD_AUDIO,
        ACCESS_BACKGROUND_LOCATION,
        QUERY_ALL_PACKAGES
    )

    /* ============================================================
     * SECURITY PERMISSION STATUS
     * ============================================================ */

    const val PERMISSION_GRANTED = "GRANTED"
    const val PERMISSION_DENIED = "DENIED"
    const val PERMISSION_BLOCKED = "BLOCKED"

}
