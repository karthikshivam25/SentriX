package com.sentrix.core.extensions

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.provider.Settings
import android.widget.Toast

/**
 * ------------------------------------------------------------
 * SentriX - ContextExtensions
 * Package: com.sentrix.core.extensions
 * ------------------------------------------------------------
 */

fun Context.showToast(
    message: String,
    duration: Int = Toast.LENGTH_SHORT
) {
    Toast.makeText(this, message, duration).show()
}

fun Context.isInternetAvailable(): Boolean {
    val connectivityManager =
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val network = connectivityManager.activeNetwork ?: return false
        val capabilities =
            connectivityManager.getNetworkCapabilities(network) ?: return false

        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    } else {
        @Suppress("DEPRECATION")
        val networkInfo = connectivityManager.activeNetworkInfo
        @Suppress("DEPRECATION")
        return networkInfo != null && networkInfo.isConnected
    }
}

fun Context.getBatteryPercentage(): Int {
    val batteryManager =
        getSystemService(Context.BATTERY_SERVICE) as BatteryManager

    return batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
}

fun Context.openAppSettings() {
    val intent = Intent(
        Settings.ACTION_APPLICATION_DETAILS_SETTINGS
    ).apply {
        data = android.net.Uri.parse("package:$packageName")
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    startActivity(intent)
}

fun Context.openWifiSettings() {
    val intent = Intent(Settings.ACTION_WIFI_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    startActivity(intent)
}

fun Context.openSecuritySettings() {
    val intent = Intent(Settings.ACTION_SECURITY_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    startActivity(intent)
}

fun Context.dpToPx(dp: Float): Float {
    return dp * resources.displayMetrics.density
}

fun Context.pxToDp(px: Float): Float {
    return px / resources.displayMetrics.density
}

fun Context.getDeviceName(): String {
    return "${Build.MANUFACTURER} ${Build.MODEL}"
}

fun Context.getAndroidVersion(): String {
    return Build.VERSION.RELEASE ?: "Unknown"
}

fun Context.isDarkModeEnabled(): Boolean {
    val nightModeFlags =
        resources.configuration.uiMode and
                android.content.res.Configuration.UI_MODE_NIGHT_MASK

    return nightModeFlags ==
            android.content.res.Configuration.UI_MODE_NIGHT_YES
}

fun Context.restartApplication() {
    val packageManager = packageManager
    val intent = packageManager.getLaunchIntentForPackage(packageName)

    intent?.addFlags(
        Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_NEW_TASK
    )

    startActivity(intent)
    Runtime.getRuntime().exit(0)
}
