package com.sentrix.core.extensions

import java.text.DecimalFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlin.math.absoluteValue

/**
 * Long Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Validation
 * ------------------------------------------------------------------------- */

fun Long.isPositive(): Boolean = this > 0L

fun Long.isNegative(): Boolean = this < 0L

fun Long.isZero(): Boolean = this == 0L

fun Long.isEven(): Boolean = this % 2L == 0L

fun Long.isOdd(): Boolean = this % 2L != 0L

/* -------------------------------------------------------------------------
 * Safe Conversions
 * ------------------------------------------------------------------------- */

fun Long.toIntSafe(): Int =
    when {
        this > Int.MAX_VALUE -> Int.MAX_VALUE
        this < Int.MIN_VALUE -> Int.MIN_VALUE
        else -> this.toInt()
    }

fun Long.toFloatSafe(): Float = this.toFloat()

fun Long.toDoubleSafe(): Double = this.toDouble()

fun Long.toStringSafe(): String = this.toString()

/* -------------------------------------------------------------------------
 * Date & Time Helpers
 * ------------------------------------------------------------------------- */

fun Long.toDate(
    pattern: String = "dd MMM yyyy"
): String {
    return SimpleDateFormat(
        pattern,
        Locale.getDefault()
    ).format(Date(this))
}

fun Long.toDateTime(
    pattern: String = "dd MMM yyyy HH:mm:ss"
): String {
    return SimpleDateFormat(
        pattern,
        Locale.getDefault()
    ).format(Date(this))
}

fun Long.toTime(
    pattern: String = "HH:mm:ss"
): String {
    return SimpleDateFormat(
        pattern,
        Locale.getDefault()
    ).format(Date(this))
}

fun Long.toRelativeDuration(): String {

    val days = TimeUnit.MILLISECONDS.toDays(this)
    val hours = TimeUnit.MILLISECONDS.toHours(this) % 24
    val minutes = TimeUnit.MILLISECONDS.toMinutes(this) % 60
    val seconds = TimeUnit.MILLISECONDS.toSeconds(this) % 60

    return buildString {
        if (days > 0) append("${days}d ")
        if (hours > 0) append("${hours}h ")
        if (minutes > 0) append("${minutes}m ")
        if (seconds > 0) append("${seconds}s")
    }.trim()
}

/* -------------------------------------------------------------------------
 * File Size Helpers
 * ------------------------------------------------------------------------- */

fun Long.toReadableFileSize(): String {

    if (this <= 0L) return "0 B"

    val units = arrayOf(
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
        "PB"
    )

    var size = this.toDouble()
    var unitIndex = 0

    while (size >= 1024 && unitIndex < units.lastIndex) {
        size /= 1024
        unitIndex++
    }

    return "${DecimalFormat("#,##0.##").format(size)} ${units[unitIndex]}"
}

/* -------------------------------------------------------------------------
 * Security & Analytics Helpers
 * ------------------------------------------------------------------------- */

fun Long.toThreatCountLabel(): String {
    return when {
        this == 0L -> "No Threats"
        this == 1L -> "1 Threat"
        else -> "$this Threats"
    }
}

fun Long.toScanDurationLabel(): String {
    return when {
        this < 1000 -> "${this}ms"
        this < 60000 -> "${this / 1000}s"
        else -> "${this / 60000}m"
    }
}

fun Long.toSecurityScore(): Int {
    return when {
        this >= 100L -> 100
        this <= 0L -> 0
        else -> this.toInt()
    }
}

/* -------------------------------------------------------------------------
 * Formatting
 * ------------------------------------------------------------------------- */

fun Long.formatWithCommas(): String {
    return DecimalFormat("#,###").format(this)
}

fun Long.padZero(length: Int = 2): String {
    return toString().padStart(length, '0')
}

fun Long.toCurrency(
    symbol: String = "₹"
): String {
    return "$symbol${DecimalFormat("#,##0.00").format(this)}"
}

/* -------------------------------------------------------------------------
 * Math Helpers
 * ------------------------------------------------------------------------- */

fun Long.square(): Long = this * this

fun Long.cube(): Long = this * this * this

fun Long.absolute(): Long = absoluteValue

fun Long.clamp(
    min: Long,
    max: Long
): Long {
    return when {
        this < min -> min
        this > max -> max
        else -> this
    }
}

/* -------------------------------------------------------------------------
 * Duration Conversions
 * ------------------------------------------------------------------------- */

fun Long.millisToSeconds(): Long =
    TimeUnit.MILLISECONDS.toSeconds(this)

fun Long.millisToMinutes(): Long =
    TimeUnit.MILLISECONDS.toMinutes(this)

fun Long.millisToHours(): Long =
    TimeUnit.MILLISECONDS.toHours(this)

fun Long.secondsToMillis(): Long =
    TimeUnit.SECONDS.toMillis(this)

fun Long.minutesToMillis(): Long =
    TimeUnit.MINUTES.toMillis(this)

fun Long.hoursToMillis(): Long =
    TimeUnit.HOURS.toMillis(this)

/* -------------------------------------------------------------------------
 * Network Helpers
 * ------------------------------------------------------------------------- */

fun Long.toNetworkSpeed(): String {

    if (this <= 0L) return "0 B/s"

    val units = arrayOf(
        "B/s",
        "KB/s",
        "MB/s",
        "GB/s"
    )

    var speed = this.toDouble()
    var unitIndex = 0

    while (speed >= 1024 && unitIndex < units.lastIndex) {
        speed /= 1024
        unitIndex++
    }

    return String.format(
        Locale.getDefault(),
        "%.2f %s",
        speed,
        units[unitIndex]
    )
}

/* -------------------------------------------------------------------------
 * Storage Helpers
 * ------------------------------------------------------------------------- */

fun Long.isLowStorage(
    thresholdBytes: Long = 1_073_741_824L // 1 GB
): Boolean {
    return this <= thresholdBytes
}

/* -------------------------------------------------------------------------
 * Retry Helpers
 * ------------------------------------------------------------------------- */

fun Long.isMaxLimitReached(
    maxLimit: Long
): Boolean {
    return this >= maxLimit
}

/* -------------------------------------------------------------------------
 * Version Helpers
 * ------------------------------------------------------------------------- */

fun Long.toBuildVersion(): String {
    return "Build-$this"
}
