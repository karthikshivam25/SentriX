package com.sentrix.core.extensions

import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Date Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Date Formatting
 * ------------------------------------------------------------------------- */

fun Date.format(
    pattern: String = "dd MMM yyyy"
): String {
    return SimpleDateFormat(
        pattern,
        Locale.getDefault()
    ).format(this)
}

fun Date.formatDateTime(): String {
    return format("dd MMM yyyy HH:mm:ss")
}

fun Date.formatTime(): String {
    return format("HH:mm:ss")
}

fun Date.formatIso8601(): String {
    return format("yyyy-MM-dd'T'HH:mm:ss")
}

/* -------------------------------------------------------------------------
 * Timestamp Conversion
 * ------------------------------------------------------------------------- */

fun Date.toTimestamp(): Long {
    return time
}

fun Long.toDate(): Date {
    return Date(this)
}

/* -------------------------------------------------------------------------
 * Relative Time Helpers
 * ------------------------------------------------------------------------- */

fun Date.timeAgo(): String {

    val diff = System.currentTimeMillis() - time

    return when {
        diff < TimeUnit.MINUTES.toMillis(1) ->
            "Just now"

        diff < TimeUnit.HOURS.toMillis(1) ->
            "${TimeUnit.MILLISECONDS.toMinutes(diff)} min ago"

        diff < TimeUnit.DAYS.toMillis(1) ->
            "${TimeUnit.MILLISECONDS.toHours(diff)} hr ago"

        diff < TimeUnit.DAYS.toMillis(7) ->
            "${TimeUnit.MILLISECONDS.toDays(diff)} day(s) ago"

        else ->
            format("dd MMM yyyy")
    }
}

/* -------------------------------------------------------------------------
 * Calendar Helpers
 * ------------------------------------------------------------------------- */

fun Date.isToday(): Boolean {

    val today = Calendar.getInstance()
    val target = Calendar.getInstance().apply {
        time = this@isToday
    }

    return today.get(Calendar.YEAR) == target.get(Calendar.YEAR) &&
            today.get(Calendar.DAY_OF_YEAR) == target.get(Calendar.DAY_OF_YEAR)
}

fun Date.isYesterday(): Boolean {

    val yesterday = Calendar.getInstance().apply {
        add(Calendar.DAY_OF_YEAR, -1)
    }

    val target = Calendar.getInstance().apply {
        time = this@isYesterday
    }

    return yesterday.get(Calendar.YEAR) == target.get(Calendar.YEAR) &&
            yesterday.get(Calendar.DAY_OF_YEAR) == target.get(Calendar.DAY_OF_YEAR)
}

fun Date.isFuture(): Boolean {
    return after(Date())
}

fun Date.isPast(): Boolean {
    return before(Date())
}

/* -------------------------------------------------------------------------
 * Date Arithmetic
 * ------------------------------------------------------------------------- */

fun Date.addDays(days: Int): Date {
    return Calendar.getInstance().apply {
        time = this@addDays
        add(Calendar.DAY_OF_MONTH, days)
    }.time
}

fun Date.addHours(hours: Int): Date {
    return Calendar.getInstance().apply {
        time = this@addHours
        add(Calendar.HOUR_OF_DAY, hours)
    }.time
}

fun Date.addMinutes(minutes: Int): Date {
    return Calendar.getInstance().apply {
        time = this@addMinutes
        add(Calendar.MINUTE, minutes)
    }.time
}

fun Date.addMonths(months: Int): Date {
    return Calendar.getInstance().apply {
        time = this@addMonths
        add(Calendar.MONTH, months)
    }.time
}

fun Date.addYears(years: Int): Date {
    return Calendar.getInstance().apply {
        time = this@addYears
        add(Calendar.YEAR, years)
    }.time
}

/* -------------------------------------------------------------------------
 * Difference Helpers
 * ------------------------------------------------------------------------- */

fun Date.daysBetween(other: Date): Long {
    val diff = kotlin.math.abs(time - other.time)
    return TimeUnit.MILLISECONDS.toDays(diff)
}

fun Date.hoursBetween(other: Date): Long {
    val diff = kotlin.math.abs(time - other.time)
    return TimeUnit.MILLISECONDS.toHours(diff)
}

fun Date.minutesBetween(other: Date): Long {
    val diff = kotlin.math.abs(time - other.time)
    return TimeUnit.MILLISECONDS.toMinutes(diff)
}

/* -------------------------------------------------------------------------
 * Start / End Helpers
 * ------------------------------------------------------------------------- */

fun Date.startOfDay(): Date {
    return Calendar.getInstance().apply {
        time = this@startOfDay
        set(Calendar.HOUR_OF_DAY, 0)
        set(Calendar.MINUTE, 0)
        set(Calendar.SECOND, 0)
        set(Calendar.MILLISECOND, 0)
    }.time
}

fun Date.endOfDay(): Date {
    return Calendar.getInstance().apply {
        time = this@endOfDay
        set(Calendar.HOUR_OF_DAY, 23)
        set(Calendar.MINUTE, 59)
        set(Calendar.SECOND, 59)
        set(Calendar.MILLISECOND, 999)
    }.time
}

/* -------------------------------------------------------------------------
 * Security Scan Helpers
 * ------------------------------------------------------------------------- */

fun Date.isOlderThanDays(days: Int): Boolean {
    val threshold = Calendar.getInstance().apply {
        add(Calendar.DAY_OF_YEAR, -days)
    }.time

    return before(threshold)
}

fun Date.isRecentScan(
    maxAgeHours: Int = 24
): Boolean {
    val diff = System.currentTimeMillis() - time
    return diff <= TimeUnit.HOURS.toMillis(maxAgeHours.toLong())
}

/* -------------------------------------------------------------------------
 * Week / Month Helpers
 * ------------------------------------------------------------------------- */

fun Date.isCurrentWeek(): Boolean {

    val current = Calendar.getInstance()
    val target = Calendar.getInstance().apply {
        time = this@isCurrentWeek
    }

    return current.get(Calendar.YEAR) == target.get(Calendar.YEAR) &&
            current.get(Calendar.WEEK_OF_YEAR) == target.get(Calendar.WEEK_OF_YEAR)
}

fun Date.isCurrentMonth(): Boolean {

    val current = Calendar.getInstance()
    val target = Calendar.getInstance().apply {
        time = this@isCurrentMonth
    }

    return current.get(Calendar.YEAR) == target.get(Calendar.YEAR) &&
            current.get(Calendar.MONTH) == target.get(Calendar.MONTH)
}

/* -------------------------------------------------------------------------
 * Parsing Helpers
 * ------------------------------------------------------------------------- */

fun String.toDate(
    pattern: String = "dd/MM/yyyy"
): Date? {
    return try {
        SimpleDateFormat(
            pattern,
            Locale.getDefault()
        ).parse(this)
    } catch (_: Exception) {
        null
    }
}

/* -------------------------------------------------------------------------
 * Logging Helpers
 * ------------------------------------------------------------------------- */

fun Date.toLogTimestamp(): String {
    return format("yyyy-MM-dd HH:mm:ss.SSS")
}

fun Date.toThreatReportDate(): String {
    return format("dd MMM yyyy HH:mm")
}
