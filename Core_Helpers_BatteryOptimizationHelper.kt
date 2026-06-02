package com.sentrix.core.helpers

import android.content.Context
import android.os.BatteryManager
import android.os.PowerManager
import kotlin.math.roundToInt

object BatteryOptimizationHelper {

    /**
     * Get battery percentage
     */
    fun getBatteryPercentage(
        context: Context
    ): Int {

        return try {

            val batteryManager =
                context.getSystemService(Context.BATTERY_SERVICE)
                        as BatteryManager

            batteryManager.getIntProperty(
                BatteryManager.BATTERY_PROPERTY_CAPACITY
            )

        } catch (e: Exception) {
            0
        }
    }

    /**
     * Check if device is charging
     */
    fun isCharging(
        context: Context
    ): Boolean {

        return try {

            val batteryManager =
                context.getSystemService(Context.BATTERY_SERVICE)
                        as BatteryManager

            val status = batteryManager.getIntProperty(
                BatteryManager.BATTERY_PROPERTY_STATUS
            )

            status == BatteryManager.BATTERY_STATUS_CHARGING ||
                    status == BatteryManager.BATTERY_STATUS_FULL

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get battery health status
     */
    fun getBatteryHealth(
        batteryHealth: Int
    ): String {

        return when (batteryHealth) {

            BatteryManager.BATTERY_HEALTH_GOOD -> {
                "Good"
            }

            BatteryManager.BATTERY_HEALTH_OVERHEAT -> {
                "Overheating"
            }

            BatteryManager.BATTERY_HEALTH_DEAD -> {
                "Dead"
            }

            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> {
                "Over Voltage"
            }

            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> {
                "Failure"
            }

            else -> {
                "Unknown"
            }
        }
    }

    /**
     * Check power save mode
     */
    fun isPowerSaveModeEnabled(
        context: Context
    ): Boolean {

        return try {

            val powerManager =
                context.getSystemService(Context.POWER_SERVICE)
                        as PowerManager

            powerManager.isPowerSaveMode

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check battery optimization ignored
     */
    fun isIgnoringBatteryOptimizations(
        context: Context
    ): Boolean {

        return try {

            val powerManager =
                context.getSystemService(Context.POWER_SERVICE)
                        as PowerManager

            powerManager.isIgnoringBatteryOptimizations(
                context.packageName
            )

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Estimate battery usage level
     */
    fun getBatteryUsageLevel(
        batteryPercentage: Int
    ): String {

        return when {

            batteryPercentage >= 80 -> {
                "Excellent"
            }

            batteryPercentage >= 60 -> {
                "Good"
            }

            batteryPercentage >= 40 -> {
                "Moderate"
            }

            batteryPercentage >= 20 -> {
                "Low"
            }

            else -> {
                "Critical"
            }
        }
    }

    /**
     * Calculate estimated remaining battery time
     */
    fun estimateRemainingTime(
        batteryPercentage: Int,
        averageDrainPerHour: Double = 10.0
    ): String {

        return try {

            val remainingHours =
                batteryPercentage / averageDrainPerHour

            val hours = remainingHours.toInt()

            val minutes =
                ((remainingHours - hours) * 60).roundToInt()

            "${hours}h ${minutes}m remaining"

        } catch (e: Exception) {
            "Unknown"
        }
    }

    /**
     * Generate battery optimization recommendation
     */
    fun getOptimizationRecommendation(
        context: Context
    ): String {

        val batteryPercentage =
            getBatteryPercentage(context)

        return when {

            batteryPercentage <= 15 -> {
                "Enable battery saver and reduce background activity."
            }

            isPowerSaveModeEnabled(context).not() &&
                    batteryPercentage <= 30 -> {
                "Consider enabling power saving mode."
            }

            isIgnoringBatteryOptimizations(context) -> {
                "Application is excluded from battery optimization."
            }

            else -> {
                "Battery performance is stable."
            }
        }
    }

    /**
     * Get battery summary report
     */
    fun getBatterySummary(
        context: Context
    ): BatterySummary {

        val batteryPercentage =
            getBatteryPercentage(context)

        return BatterySummary(
            batteryPercentage = batteryPercentage,
            batteryLevel =
                getBatteryUsageLevel(batteryPercentage),
            isCharging = isCharging(context),
            powerSaveEnabled =
                isPowerSaveModeEnabled(context),
            ignoringOptimizations =
                isIgnoringBatteryOptimizations(context),
            estimatedRemainingTime =
                estimateRemainingTime(batteryPercentage),
            recommendation =
                getOptimizationRecommendation(context)
        )
    }

    /**
     * Battery summary model
     */
    data class BatterySummary(
        val batteryPercentage: Int,
        val batteryLevel: String,
        val isCharging: Boolean,
        val powerSaveEnabled: Boolean,
        val ignoringOptimizations: Boolean,
        val estimatedRemainingTime: String,
        val recommendation: String
    )
}
