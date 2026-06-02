package com.sentrix.core.helpers

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.provider.Settings
import java.io.File
import java.util.UUID

object DeviceHelper {

    /**
     * Get device manufacturer
     */
    fun getManufacturer(): String {
        return Build.MANUFACTURER ?: "Unknown"
    }

    /**
     * Get device model
     */
    fun getDeviceModel(): String {
        return Build.MODEL ?: "Unknown"
    }

    /**
     * Get Android version name
     */
    fun getAndroidVersion(): String {
        return Build.VERSION.RELEASE ?: "Unknown"
    }

    /**
     * Get Android SDK version
     */
    fun getSdkVersion(): Int {
        return Build.VERSION.SDK_INT
    }

    /**
     * Get device brand
     */
    fun getDeviceBrand(): String {
        return Build.BRAND ?: "Unknown"
    }

    /**
     * Get hardware name
     */
    fun getHardware(): String {
        return Build.HARDWARE ?: "Unknown"
    }

    /**
     * Get device fingerprint
     */
    fun getFingerprint(): String {
        return Build.FINGERPRINT ?: "Unknown"
    }

    /**
     * Check if device is rooted
     */
    fun isDeviceRooted(): Boolean {
        return checkRootFiles() || checkSuExists()
    }

    private fun checkRootFiles(): Boolean {
        val paths = arrayOf(
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

        return paths.any { File(it).exists() }
    }

    private fun checkSuExists(): Boolean {
        return try {
            Runtime.getRuntime()
                .exec(arrayOf("/system/xbin/which", "su"))
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if emulator
     */
    fun isEmulator(): Boolean {
        return (
            Build.FINGERPRINT.startsWith("generic") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for x86") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            Build.HARDWARE.contains("goldfish") ||
            Build.HARDWARE.contains("ranchu") ||
            Build.PRODUCT.contains("sdk") ||
            Build.PRODUCT.contains("emulator")
        )
    }

    /**
     * Get unique device ID
     */
    fun getDeviceId(context: Context): String {
        return try {
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ANDROID_ID
            ) ?: UUID.randomUUID().toString()
        } catch (e: Exception) {
            UUID.randomUUID().toString()
        }
    }

    /**
     * Get available RAM in MB
     */
    fun getAvailableRam(context: Context): Long {
        val activityManager =
            context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager

        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)

        return memoryInfo.availMem / (1024 * 1024)
    }

    /**
     * Get total RAM in MB
     */
    fun getTotalRam(context: Context): Long {
        val activityManager =
            context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager

        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)

        return memoryInfo.totalMem / (1024 * 1024)
    }

    /**
     * Get battery percentage
     */
    fun getBatteryPercentage(context: Context): Int {
        val batteryManager =
            context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager

        return batteryManager.getIntProperty(
            BatteryManager.BATTERY_PROPERTY_CAPACITY
        )
    }

    /**
     * Check internet connectivity
     */
    fun isInternetAvailable(context: Context): Boolean {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE)
                    as ConnectivityManager

        val network = connectivityManager.activeNetwork ?: return false

        val capabilities =
            connectivityManager.getNetworkCapabilities(network)
                ?: return false

        return capabilities.hasCapability(
            NetworkCapabilities.NET_CAPABILITY_INTERNET
        )
    }

    /**
     * Get CPU ABI
     */
    fun getCpuArchitecture(): String {
        return Build.SUPPORTED_ABIS.joinToString(", ")
    }

    /**
     * Get device bootloader
     */
    fun getBootloader(): String {
        return Build.BOOTLOADER ?: "Unknown"
    }

    /**
     * Check if device supports biometric authentication
     */
    fun supportsBiometric(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
    }
}
