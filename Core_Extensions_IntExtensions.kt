package com.sentrix.core.extensions

import java.text.DecimalFormat
import kotlin.math.absoluteValue

/**
 * Int Extensions
 * SentriX Core Module
 */

/**
 * Boolean Checks
 */
fun Int.isPositive(): Boolean {
    return this > 0
}

fun Int.isNegative(): Boolean {
    return this < 0
}

fun Int.isZero(): Boolean {
    return this == 0
}

fun Int.isEven(): Boolean {
    return this % 2 == 0
}

fun Int.isOdd(): Boolean {
    return this % 2 != 0
}

/**
 * Safe Conversions
 */
fun Int.toLongSafe(): Long {
    return this.toLong()
}

fun Int.toFloatSafe(): Float {
    return this.toFloat()
}

fun Int.toDoubleSafe(): Double {
    return this.toDouble()
}

fun Int.toStringSafe(): String {
    return this.toString()
}

/**
 * Percentage Helpers
 */
fun Int.toPercentage(total: Int): Float {
    if (total <= 0) return 0f
    return (this.toFloat() / total.toFloat()) * 100f
}

fun Int.percentageOf(value: Int): Int {
    return (value * this) / 100
}

/**
 * Range Helpers
 */
fun Int.isBetween(
    min: Int,
    max: Int
): Boolean {
    return this in min..max
}

fun Int.coerceInRange(
    min: Int,
    max: Int
): Int {
    return this.coerceIn(min, max)
}

/**
 * Formatting
 */
fun Int.formatWithCommas(): String {
    return DecimalFormat("#,###").format(this)
}

fun Int.padZero(length: Int = 2): String {
    return toString().padStart(length, '0')
}

/**
 * File Size Helpers
 */
fun Int.toReadableBytes(): String {

    if (this <= 0) return "0 B"

    val units = arrayOf(
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    )

    var size = this.toDouble()
    var unitIndex = 0

    while (size >= 1024 && unitIndex < units.lastIndex) {
        size /= 1024
        unitIndex++
    }

    return String.format("%.1f %s", size, units[unitIndex])
}

/**
 * Security Score Helpers
 */
fun Int.toSecurityRiskLevel(): String {
    return when {
        this >= 90 -> "Excellent"
        this >= 75 -> "Good"
        this >= 50 -> "Moderate"
        this >= 25 -> "High Risk"
        else -> "Critical"
    }
}

fun Int.toThreatSeverity(): String {
    return when {
        this >= 90 -> "Critical"
        this >= 70 -> "High"
        this >= 50 -> "Medium"
        this >= 30 -> "Low"
        else -> "Safe"
    }
}

/**
 * Time Helpers
 */
fun Int.secondsToMinutes(): Int {
    return this / 60
}

fun Int.minutesToSeconds(): Int {
    return this * 60
}

fun Int.hoursToMinutes(): Int {
    return this * 60
}

fun Int.daysToHours(): Int {
    return this * 24
}

/**
 * Math Helpers
 */
fun Int.square(): Int {
    return this * this
}

fun Int.cube(): Int {
    return this * this * this
}

fun Int.absolute(): Int {
    return absoluteValue
}

fun Int.clamp(
    min: Int,
    max: Int
): Int {
    return when {
        this < min -> min
        this > max -> max
        else -> this
    }
}

/**
 * Progress Helpers
 */
fun Int.progressFraction(
    maxValue: Int
): Float {

    if (maxValue <= 0) return 0f

    return this.toFloat() / maxValue.toFloat()
}

/**
 * Battery Helpers
 */
fun Int.isLowBattery(): Boolean {
    return this in 1..20
}

fun Int.isCriticalBattery(): Boolean {
    return this in 1..10
}

/**
 * Device Health Helpers
 */
fun Int.toDeviceHealthStatus(): String {
    return when {
        this >= 90 -> "Excellent"
        this >= 75 -> "Healthy"
        this >= 50 -> "Average"
        this >= 25 -> "Poor"
        else -> "Critical"
    }
}

/**
 * Network Signal Helpers
 */
fun Int.toSignalStrengthLabel(): String {
    return when {
        this >= 80 -> "Excellent"
        this >= 60 -> "Strong"
        this >= 40 -> "Moderate"
        this >= 20 -> "Weak"
        else -> "Very Weak"
    }
}

/**
 * Threat Count Helpers
 */
fun Int.hasThreats(): Boolean {
    return this > 0
}

fun Int.isThreatFree(): Boolean {
    return this == 0
}

/**
 * Retry Helpers
 */
fun Int.isMaxRetryReached(
    maxRetries: Int
): Boolean {
    return this >= maxRetries
}

/**
 * Version Helpers
 */
fun Int.toVersionName(): String {
    return "v$this"
}
