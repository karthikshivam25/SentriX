package com.sentrix.ui.common

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.provider.Settings
import java.io.File

object DeviceUtils { 

    // ----------------------------------------------------------------
    // DEVICE INFORMATION
    // ----------------------------------------------------------------

    fun getDeviceModel(): String {

        return "${Build.MANUFACTURER} ${Build.MODEL}"
    }

    fun getAndroidVersion(): String {

        return "Android ${Build.VERSION.RELEASE}"
    }

    fun getDeviceBrand(): String {

        return Build.BRAND
    }

    fun getDeviceSDKVersion(): Int {

        return Build.VERSION.SDK_INT
    }

    // ----------------------------------------------------------------
    // DEVICE ID
    // ----------------------------------------------------------------

    fun getAndroidId(
        context: Context
    ): String {

        return Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID
        )
    }

    // ----------------------------------------------------------------
    // BATTERY INFORMATION
    // ----------------------------------------------------------------

    fun getBatteryPercentage(
        context: Context
    ): Int {

        val batteryManager =
            context.getSystemService(
                Context.BATTERY_SERVICE
            ) as BatteryManager

        return batteryManager.getIntProperty(
            BatteryManager.BATTERY_PROPERTY_CAPACITY
        )
    }

    fun isBatteryCharging(
        context: Context
    ): Boolean {

        val batteryManager =
            context.getSystemService(
                Context.BATTERY_SERVICE
            ) as BatteryManager

        return batteryManager.isCharging
    }

    // ----------------------------------------------------------------
    // STORAGE INFORMATION
    // ----------------------------------------------------------------

    fun getAvailableStorage(): Long {

        return File("/").freeSpace
    }

    fun getTotalStorage(): Long {

        return File("/").totalSpace
    }

    fun getUsedStorage(): Long {

        return getTotalStorage() -
                getAvailableStorage()
    }

    // ----------------------------------------------------------------
    // MEMORY INFORMATION
    // ----------------------------------------------------------------

    fun getAvailableMemory(
        context: Context
    ): Long {

        val activityManager =
            context.getSystemService(
                Context.ACTIVITY_SERVICE
            ) as ActivityManager

        val memoryInfo =
            ActivityManager.MemoryInfo()

        activityManager.getMemoryInfo(
            memoryInfo
        )

        return memoryInfo.availMem
    }

    fun getTotalMemory(
        context: Context
    ): Long {

        val activityManager =
            context.getSystemService(
                Context.ACTIVITY_SERVICE
            ) as ActivityManager

        val memoryInfo =
            ActivityManager.MemoryInfo()

        activityManager.getMemoryInfo(
            memoryInfo
        )

        return memoryInfo.totalMem
    }

    // ----------------------------------------------------------------
    // NETWORK STATUS
    // ----------------------------------------------------------------

    fun isInternetAvailable(
        context: Context
    ): Boolean {

        val connectivityManager =
            context.getSystemService(
                Context.CONNECTIVITY_SERVICE
            ) as ConnectivityManager

        val network =
            connectivityManager.activeNetwork
                ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(
                network
            ) ?: return false

        return capabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_INTERNET
            ) &&
                capabilities.hasCapability(
                    NetworkCapabilities.NET_CAPABILITY_VALIDATED
                )
    }

    fun isWifiConnected(
        context: Context
    ): Boolean {

        val connectivityManager =
            context.getSystemService(
                Context.CONNECTIVITY_SERVICE
            ) as ConnectivityManager

        val network =
            connectivityManager.activeNetwork
                ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(
                network
            ) ?: return false

        return capabilities.hasTransport(
            NetworkCapabilities.TRANSPORT_WIFI
        )
    }

    fun isMobileDataConnected(
        context: Context
    ): Boolean {

        val connectivityManager =
            context.getSystemService(
                Context.CONNECTIVITY_SERVICE
            ) as ConnectivityManager

        val network =
            connectivityManager.activeNetwork
                ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(
                network
            ) ?: return false

        return capabilities.hasTransport(
            NetworkCapabilities.TRANSPORT_CELLULAR
        )
    }

    // ----------------------------------------------------------------
    // SECURITY CHECKS
    // ----------------------------------------------------------------

    fun isDeveloperModeEnabled(
        context: Context
    ): Boolean {

        return try {

            Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0
            ) != 0

        } catch (exception: Exception) {

            false
        }
    }

    fun isUsbDebuggingEnabled(
        context: Context
    ): Boolean {

        return try {

            Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.ADB_ENABLED,
                0
            ) != 0

        } catch (exception: Exception) {

            false
        }
    }

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

        return rootPaths.any { path ->

            File(path).exists()
        }
    }

    // ----------------------------------------------------------------
    // CPU INFORMATION
    // ----------------------------------------------------------------

    fun getCpuArchitecture(): String {

        return Build.SUPPORTED_ABIS.firstOrNull()
            ?: "Unknown"
    }

    fun getNumberOfCores(): Int {

        return Runtime.getRuntime()
            .availableProcessors()
    }

    // ----------------------------------------------------------------
    // DEVICE SUMMARY
    // ----------------------------------------------------------------

    fun getDeviceSummary(
        context: Context
    ): String {

        return buildString {

            appendLine("Model: ${getDeviceModel()}")

            appendLine("Android: ${getAndroidVersion()}")

            appendLine("Battery: ${
                getBatteryPercentage(context)
            }%")

            appendLine("WiFi Connected: ${
                isWifiConnected(context)
            }")

            appendLine("Developer Mode: ${
                isDeveloperModeEnabled(context)
            }")

            appendLine("Rooted: ${
                isDeviceRooted()
            }")
        }
    }
}
