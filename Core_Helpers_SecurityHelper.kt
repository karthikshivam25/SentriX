package com.sentrix.core.helpers

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import com.sentrix.core.enums.ConnectionType
import com.sentrix.core.enums.DeviceHealth
import com.sentrix.core.enums.PermissionRisk
import com.sentrix.core.enums.SecurityStatus
import java.io.File
import java.security.MessageDigest
import java.util.Locale

/**
 * Helper class for security-related utilities and checks
 */
object SecurityHelper {

    private val suspiciousPackages = listOf(
        "com.android.vending.billing.InAppBillingService.COIN",
        "com.chelpus.lackypatch",
        "com.dimonvideo.luckypatcher",
        "com.blackmartalpha",
        "org.creeplays.hack",
        "com.topjohnwu.magisk"
    )

    /**
     * Detect rooted device indicators
     */
    fun isDeviceRooted(): Boolean {

        val rootPaths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )

        return rootPaths.any { File(it).exists() }
    }

    /**
     * Detect emulator environment
     */
    fun isRunningOnEmulator(): Boolean {

        return (
            Build.FINGERPRINT.contains("generic") ||
            Build.MODEL.lowercase(Locale.getDefault()).contains("emulator") ||
            Build.MANUFACTURER.lowercase(Locale.getDefault()).contains("genymotion") ||
            Build.BRAND.startsWith("generic") ||
            Build.DEVICE.startsWith("generic") ||
            "google_sdk" == Build.PRODUCT
        )
    }

    /**
     * Check if developer options are enabled
     */
    fun isDeveloperOptionsEnabled(context: Context): Boolean {

        return Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0
        ) != 0
    }

    /**
     * Detect suspicious installed applications
     */
    fun detectSuspiciousApps(context: Context): List<String> {

        val installedApps = context.packageManager.getInstalledApplications(0)

        return installedApps.map { it.packageName }
            .filter { packageName ->
                suspiciousPackages.any {
                    packageName.contains(it, ignoreCase = true)
                }
            }
    }

    /**
     * Returns current active connection type
     */
    fun getConnectionType(context: Context): ConnectionType {

        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork
            ?: return ConnectionType.OFFLINE

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return ConnectionType.UNKNOWN

        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ->
                ConnectionType.WIFI

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                ConnectionType.MOBILE_DATA

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ->
                ConnectionType.ETHERNET

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ->
                ConnectionType.VPN

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) ->
                ConnectionType.BLUETOOTH

            else -> ConnectionType.UNKNOWN
        }
    }

    /**
     * Generate SHA-256 checksum
     */
    fun generateChecksum(input: String): String {

        val digest = MessageDigest.getInstance("SHA-256")

        val hashBytes = digest.digest(input.toByteArray())

        return hashBytes.joinToString("") {
            "%02x".format(it)
        }
    }

    /**
     * Determine permission risk level
     */
    fun getPermissionRisk(permission: String): PermissionRisk {

        return when {

            permission.contains("CAMERA", true) ||
            permission.contains("RECORD_AUDIO", true) ||
            permission.contains("READ_SMS", true) ||
            permission.contains("READ_CONTACTS", true) ->
                PermissionRisk.CRITICAL

            permission.contains("ACCESS_FINE_LOCATION", true) ||
            permission.contains("READ_CALL_LOG", true) ->
                PermissionRisk.HIGH

            permission.contains("READ_EXTERNAL_STORAGE", true) ||
            permission.contains("WRITE_EXTERNAL_STORAGE", true) ->
                PermissionRisk.MODERATE

            permission.contains("INTERNET", true) ->
                PermissionRisk.LOW

            else -> PermissionRisk.SAFE
        }
    }

    /**
     * Returns overall security status
     */
    fun evaluateSecurityStatus(
        rooted: Boolean,
        suspiciousApps: Int,
        dangerousPermissions: Int
    ): SecurityStatus {

        return when {

            rooted && suspiciousApps > 3 ->
                SecurityStatus.COMPROMISED

            rooted || suspiciousApps > 1 ->
                SecurityStatus.INFECTED

            dangerousPermissions > 10 ->
                SecurityStatus.VULNERABLE

            dangerousPermissions > 5 ->
                SecurityStatus.AT_RISK

            dangerousPermissions > 0 ->
                SecurityStatus.WARNING

            else ->
                SecurityStatus.SECURE
        }
    }

    /**
     * Returns overall device health status
     */
    fun evaluateDeviceHealth(
        batteryLevel: Int,
        storageUsagePercent: Int,
        memoryUsagePercent: Int
    ): DeviceHealth {

        return when {

            batteryLevel > 80 &&
            storageUsagePercent < 50 &&
            memoryUsagePercent < 50 ->
                DeviceHealth.EXCELLENT

            batteryLevel > 60 &&
            storageUsagePercent < 70 ->
                DeviceHealth.GOOD

            batteryLevel > 40 ->
                DeviceHealth.FAIR

            batteryLevel > 20 ->
                DeviceHealth.POOR

            else ->
                DeviceHealth.CRITICAL
        }
    }

    /**
     * Checks whether application is debuggable
     */
    fun isAppDebuggable(context: Context): Boolean {

        return (
            context.applicationInfo.flags and
            ApplicationInfo.FLAG_DEBUGGABLE
        ) != 0
    }
}
