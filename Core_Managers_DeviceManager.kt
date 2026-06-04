package com.sentrix.core.managers

import android.app.ActivityManager
import android.content.Context
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import java.io.File

/**
 * DeviceManager
 *
 * Responsibilities:
 * - Device information collection
 * - Storage monitoring
 * - Memory monitoring
 * - Battery monitoring
 * - Device health evaluation
 * - Security-related device insights
 */
class DeviceManager(
    private val context: Context
) {

    /**
     * Get complete device information.
     */
    fun getDeviceInfo(): DeviceInfo {

        return DeviceInfo(
            manufacturer = Build.MANUFACTURER,
            brand = Build.BRAND,
            model = Build.MODEL,
            device = Build.DEVICE,
            product = Build.PRODUCT,
            hardware = Build.HARDWARE,
            androidVersion = Build.VERSION.RELEASE ?: "Unknown",
            sdkVersion = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "Unknown"
        )
    }

    /**
     * Get battery percentage.
     */
    fun getBatteryLevel(): Int {

        val batteryManager =
            context.getSystemService(
                Context.BATTERY_SERVICE
            ) as BatteryManager

        return batteryManager.getIntProperty(
            BatteryManager.BATTERY_PROPERTY_CAPACITY
        )
    }

    /**
     * Is device charging.
     */
    fun isCharging(): Boolean {

        val batteryManager =
            context.getSystemService(
                Context.BATTERY_SERVICE
            ) as BatteryManager

        return batteryManager.isCharging
    }

    /**
     * Available internal storage.
     */
    fun getAvailableStorageBytes(): Long {

        val statFs = StatFs(
            Environment.getDataDirectory().path
        )

        return statFs.availableBytes
    }

    /**
     * Total internal storage.
     */
    fun getTotalStorageBytes(): Long {

        val statFs = StatFs(
            Environment.getDataDirectory().path
        )

        return statFs.totalBytes
    }

    /**
     * Used storage.
     */
    fun getUsedStorageBytes(): Long {
        return getTotalStorageBytes() -
                getAvailableStorageBytes()
    }

    /**
     * Storage usage percentage.
     */
    fun getStorageUsagePercent(): Int {

        val total = getTotalStorageBytes()

        if (total == 0L) return 0

        return (
                getUsedStorageBytes() * 100 / total
                ).toInt()
    }

    /**
     * Available RAM.
     */
    fun getAvailableMemoryBytes(): Long {

        val activityManager =
            context.getSystemService(
                Context.ACTIVITY_SERVICE
            ) as ActivityManager

        val memoryInfo =
            ActivityManager.MemoryInfo()

        activityManager.getMemoryInfo(memoryInfo)

        return memoryInfo.availMem
    }

    /**
     * Total RAM.
     */
    fun getTotalMemoryBytes(): Long {

        val activityManager =
            context.getSystemService(
                Context.ACTIVITY_SERVICE
            ) as ActivityManager

        val memoryInfo =
            ActivityManager.MemoryInfo()

        activityManager.getMemoryInfo(memoryInfo)

        return memoryInfo.totalMem
    }

    /**
     * RAM usage percentage.
     */
    fun getMemoryUsagePercent(): Int {

        val total = getTotalMemoryBytes()

        if (total == 0L) return 0

        val used =
            total - getAvailableMemoryBytes()

        return ((used * 100) / total).toInt()
    }

    /**
     * Determine overall device health.
     */
    fun getDeviceHealth(): DeviceHealth {

        val battery = getBatteryLevel()
        val storageUsage = getStorageUsagePercent()
        val memoryUsage = getMemoryUsagePercent()

        return when {

            battery < 10 ||
                    storageUsage > 95 ||
                    memoryUsage > 95 ->
                DeviceHealth.CRITICAL

            battery < 20 ||
                    storageUsage > 85 ||
                    memoryUsage > 85 ->
                DeviceHealth.POOR

            battery < 40 ||
                    storageUsage > 70 ||
                    memoryUsage > 70 ->
                DeviceHealth.FAIR

            else ->
                DeviceHealth.GOOD
        }
    }

    /**
     * Generate device report.
     */
    fun generateDeviceReport(): String {

        val info = getDeviceInfo()

        return buildString {

            appendLine("Device Report")
            appendLine("--------------------------")
            appendLine("Manufacturer : ${info.manufacturer}")
            appendLine("Brand        : ${info.brand}")
            appendLine("Model        : ${info.model}")
            appendLine("Android      : ${info.androidVersion}")
            appendLine("SDK          : ${info.sdkVersion}")
            appendLine("Battery      : ${getBatteryLevel()}%")
            appendLine("Charging     : ${isCharging()}")
            appendLine("Storage Used : ${getStorageUsagePercent()}%")
            appendLine("RAM Used     : ${getMemoryUsagePercent()}%")
            appendLine("Health       : ${getDeviceHealth()}")
        }
    }

    /**
     * Format bytes to human-readable string.
     */
    fun formatBytes(bytes: Long): String {

        if (bytes <= 0) return "0 B"

        val units =
            arrayOf("B", "KB", "MB", "GB", "TB")

        val digitGroups =
            (Math.log10(bytes.toDouble()) /
                    Math.log10(1024.0)).toInt()

        return String.format(
            "%.2f %s",
            bytes / Math.pow(
                1024.0,
                digitGroups.toDouble()
            ),
            units[digitGroups]
        )
    }

    /**
     * Device information model.
     */
    data class DeviceInfo(
        val manufacturer: String,
        val brand: String,
        val model: String,
        val device: String,
        val product: String,
        val hardware: String,
        val androidVersion: String,
        val sdkVersion: Int,
        val securityPatch: String
    )

    /**
     * Device health status.
     */
    enum class DeviceHealth {
        GOOD,
        FAIR,
        POOR,
        CRITICAL
    }
}
