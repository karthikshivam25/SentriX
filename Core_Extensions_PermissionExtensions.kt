package com.sentrix.core.extensions

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.result.ActivityResultLauncher
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * Permission Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Permission Checks
 * ------------------------------------------------------------------------- */

fun Context.hasPermission(
    permission: String
): Boolean {
    return ContextCompat.checkSelfPermission(
        this,
        permission
    ) == PackageManager.PERMISSION_GRANTED
}

fun Context.hasPermissions(
    vararg permissions: String
): Boolean {
    return permissions.all {
        hasPermission(it)
    }
}

fun Context.missingPermissions(
    vararg permissions: String
): List<String> {
    return permissions.filterNot {
        hasPermission(it)
    }
}

/* -------------------------------------------------------------------------
 * Permission Request Helpers
 * ------------------------------------------------------------------------- */

fun Activity.requestPermission(
    permission: String,
    requestCode: Int
) {
    ActivityCompat.requestPermissions(
        this,
        arrayOf(permission),
        requestCode
    )
}

fun Activity.requestPermissions(
    permissions: Array<String>,
    requestCode: Int
) {
    ActivityCompat.requestPermissions(
        this,
        permissions,
        requestCode
    )
}

fun Activity.requestMissingPermissions(
    requestCode: Int,
    vararg permissions: String
) {
    val missing = permissions.filterNot {
        hasPermission(it)
    }

    if (missing.isNotEmpty()) {
        ActivityCompat.requestPermissions(
            this,
            missing.toTypedArray(),
            requestCode
        )
    }
}

/* -------------------------------------------------------------------------
 * Permission Rationale Helpers
 * ------------------------------------------------------------------------- */

fun Activity.shouldShowPermissionRationale(
    permission: String
): Boolean {
    return ActivityCompat
        .shouldShowRequestPermissionRationale(
            this,
            permission
        )
}

fun Activity.shouldShowAnyRationale(
    vararg permissions: String
): Boolean {
    return permissions.any {
        shouldShowPermissionRationale(it)
    }
}

/* -------------------------------------------------------------------------
 * Activity Result API Helpers
 * ------------------------------------------------------------------------- */

fun ActivityResultLauncher<String>.request(
    permission: String
) {
    launch(permission)
}

fun ActivityResultLauncher<Array<String>>.request(
    permissions: Array<String>
) {
    launch(permissions)
}

/* -------------------------------------------------------------------------
 * Permission Result Helpers
 * ------------------------------------------------------------------------- */

fun IntArray.allGranted(): Boolean {
    return all {
        it == PackageManager.PERMISSION_GRANTED
    }
}

fun IntArray.anyDenied(): Boolean {
    return any {
        it != PackageManager.PERMISSION_GRANTED
    }
}

fun Map<String, Boolean>.allGranted(): Boolean {
    return values.all { it }
}

fun Map<String, Boolean>.deniedPermissions(): List<String> {
    return filterValues { granted ->
        !granted
    }.keys.toList()
}

/* -------------------------------------------------------------------------
 * Security Risk Classification
 * ------------------------------------------------------------------------- */

fun String.isHighRiskPermission(): Boolean {
    return this in setOf(
        android.Manifest.permission.READ_SMS,
        android.Manifest.permission.RECEIVE_SMS,
        android.Manifest.permission.SEND_SMS,
        android.Manifest.permission.READ_CONTACTS,
        android.Manifest.permission.WRITE_CONTACTS,
        android.Manifest.permission.RECORD_AUDIO,
        android.Manifest.permission.CAMERA,
        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.ACCESS_BACKGROUND_LOCATION,
        android.Manifest.permission.READ_CALL_LOG,
        android.Manifest.permission.WRITE_CALL_LOG
    )
}

fun String.permissionRiskLevel(): String {
    return when {
        isHighRiskPermission() -> "High"
        contains("LOCATION") -> "Medium"
        contains("STORAGE") -> "Medium"
        else -> "Low"
    }
}

/* -------------------------------------------------------------------------
 * SentriX Permission Analysis
 * ------------------------------------------------------------------------- */

fun Collection<String>.countHighRiskPermissions(): Int {
    return count { it.isHighRiskPermission() }
}

fun Collection<String>.permissionSecurityScore(): Int {

    val highRiskCount = countHighRiskPermissions()

    return when {
        highRiskCount == 0 -> 100
        highRiskCount <= 2 -> 80
        highRiskCount <= 5 -> 60
        highRiskCount <= 8 -> 40
        else -> 20
    }
}

fun Collection<String>.permissionRiskSummary(): String {

    val count = countHighRiskPermissions()

    return when {
        count == 0 ->
            "No high-risk permissions detected."

        count <= 2 ->
            "Low permission exposure."

        count <= 5 ->
            "Moderate permission exposure."

        count <= 8 ->
            "High permission exposure."

        else ->
            "Critical permission exposure."
    }
}

/* -------------------------------------------------------------------------
 * Permission Categories
 * ------------------------------------------------------------------------- */

fun String.permissionCategory(): String {

    return when (this) {

        android.Manifest.permission.CAMERA ->
            "Camera"

        android.Manifest.permission.RECORD_AUDIO ->
            "Microphone"

        android.Manifest.permission.READ_CONTACTS,
        android.Manifest.permission.WRITE_CONTACTS ->
            "Contacts"

        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.ACCESS_COARSE_LOCATION,
        android.Manifest.permission.ACCESS_BACKGROUND_LOCATION ->
            "Location"

        android.Manifest.permission.READ_SMS,
        android.Manifest.permission.RECEIVE_SMS,
        android.Manifest.permission.SEND_SMS ->
            "SMS"

        android.Manifest.permission.READ_CALL_LOG,
        android.Manifest.permission.WRITE_CALL_LOG ->
            "Call Logs"

        android.Manifest.permission.READ_EXTERNAL_STORAGE,
        android.Manifest.permission.WRITE_EXTERNAL_STORAGE ->
            "Storage"

        else ->
            "Other"
    }
}

/* -------------------------------------------------------------------------
 * Dangerous Permission Detection
 * ------------------------------------------------------------------------- */

fun String.isDangerousPermission(): Boolean {
    return permissionCategory() != "Other"
}

fun Collection<String>.dangerousPermissions(): List<String> {
    return filter {
        it.isDangerousPermission()
    }
}

/* -------------------------------------------------------------------------
 * Permission Health Score
 * ------------------------------------------------------------------------- */

fun Collection<String>.permissionHealthStatus(): String {

    return when (permissionSecurityScore()) {
        in 90..100 -> "Excellent"
        in 75..89 -> "Good"
        in 50..74 -> "Moderate"
        in 25..49 -> "Poor"
        else -> "Critical"
    }
}

/* -------------------------------------------------------------------------
 * Utility Helpers
 * ------------------------------------------------------------------------- */

fun String.permissionDisplayName(): String {
    return substringAfterLast(".")
        .replace("_", " ")
        .lowercase()
        .split(" ")
        .joinToString(" ") {
            it.replaceFirstChar { char ->
                char.uppercase()
            }
        }
}

fun Collection<String>.groupByPermissionCategory():
        Map<String, List<String>> {

    return groupBy {
        it.permissionCategory()
    }
}
