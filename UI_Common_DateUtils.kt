package com.sentrix.ui.common

import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

object DateUtils {

    // ----------------------------------------------------------------
    // DEFAULT FORMATS
    // ----------------------------------------------------------------

    private const val FORMAT_DATE =
        "dd MMM yyyy"

    private const val FORMAT_TIME =
        "hh:mm a"

    private const val FORMAT_DATE_TIME =
        "dd MMM yyyy, hh:mm a"

    private const val FORMAT_SERVER =
        "yyyy-MM-dd HH:mm:ss"

    // ----------------------------------------------------------------
    // CURRENT DATE
    // ----------------------------------------------------------------

    fun getCurrentDate(): String {

        return formatDate(
            Date(),
            FORMAT_DATE
        )
    }

    fun getCurrentTime(): String {

        return formatDate(
            Date(),
            FORMAT_TIME
        )
    }

    fun getCurrentDateTime(): String {

        return formatDate(
            Date(),
            FORMAT_DATE_TIME
        )
    }

    // ----------------------------------------------------------------
    // FORMAT DATE
    // ----------------------------------------------------------------

    fun formatDate(
        date: Date,
        pattern: String = FORMAT_DATE_TIME
    ): String {

        return try {

            val formatter = SimpleDateFormat(
                pattern,
                Locale.getDefault()
            )

            formatter.format(date)

        } catch (exception: Exception) {

            ""
        }
    }

    // ----------------------------------------------------------------
    // PARSE DATE
    // ----------------------------------------------------------------

    fun parseDate(
        value: String,
        pattern: String = FORMAT_SERVER
    ): Date? {

        return try {

            val formatter = SimpleDateFormat(
                pattern,
                Locale.getDefault()
            )

            formatter.parse(value)

        } catch (exception: Exception) {

            null
        }
    }

    // ----------------------------------------------------------------
    // TIME AGO
    // ----------------------------------------------------------------

    fun getTimeAgo(
        date: Date
    ): String {

        val currentTime = System.currentTimeMillis()

        val difference =
            currentTime - date.time

        return when {

            difference < TimeUnit.MINUTES.toMillis(1) -> {
                "Just now"
            }

            difference < TimeUnit.HOURS.toMillis(1) -> {

                val minutes =
                    TimeUnit.MILLISECONDS.toMinutes(
                        difference
                    )

                "$minutes min ago"
            }

            difference < TimeUnit.DAYS.toMillis(1) -> {

                val hours =
                    TimeUnit.MILLISECONDS.toHours(
                        difference
                    )

                "$hours hr ago"
            }

            difference < TimeUnit.DAYS.toMillis(7) -> {

                val days =
                    TimeUnit.MILLISECONDS.toDays(
                        difference
                    )

                "$days day ago"
            }

            else -> {

                formatDate(
                    date,
                    FORMAT_DATE
                )
            }
        }
    }

    // ----------------------------------------------------------------
    // TODAY CHECK
    // ----------------------------------------------------------------

    fun isToday(
        date: Date
    ): Boolean {

        val today = Calendar.getInstance()

        val targetDate = Calendar.getInstance()

        targetDate.time = date

        return today.get(Calendar.YEAR) ==
                targetDate.get(Calendar.YEAR) &&
                today.get(Calendar.DAY_OF_YEAR) ==
                targetDate.get(Calendar.DAY_OF_YEAR)
    }

    // ----------------------------------------------------------------
    // YESTERDAY CHECK
    // ----------------------------------------------------------------

    fun isYesterday(
        date: Date
    ): Boolean {

        val yesterday = Calendar.getInstance()

        yesterday.add(
            Calendar.DAY_OF_YEAR,
            -1
        )

        val targetDate = Calendar.getInstance()

        targetDate.time = date

        return yesterday.get(Calendar.YEAR) ==
                targetDate.get(Calendar.YEAR) &&
                yesterday.get(Calendar.DAY_OF_YEAR) ==
                targetDate.get(Calendar.DAY_OF_YEAR)
    }

    // ----------------------------------------------------------------
    // DAYS BETWEEN
    // ----------------------------------------------------------------

    fun getDaysBetween(
        startDate: Date,
        endDate: Date
    ): Long {

        val difference =
            endDate.time - startDate.time

        return TimeUnit.MILLISECONDS.toDays(
            difference
        )
    }

    // ----------------------------------------------------------------
    // FORMAT SERVER DATE
    // ----------------------------------------------------------------

    fun formatServerDate(
        value: String
    ): String {

        val parsedDate = parseDate(value)

        return if (parsedDate != null) {

            formatDate(
                parsedDate,
                FORMAT_DATE_TIME
            )

        } else {

            value
        }
    }

    // ----------------------------------------------------------------
    // GET SECURITY SCAN LABEL
    // ----------------------------------------------------------------

    fun getLastScanText(
        lastScanDate: Date?
    ): String {

        return if (lastScanDate == null) {

            "No scans performed"

        } else {

            "Last scanned ${
                getTimeAgo(lastScanDate)
            }"
        }
    }

    // ----------------------------------------------------------------
    // CONVERT TIMEZONE
    // ----------------------------------------------------------------

    fun convertToTimezone(
        date: Date,
        timezone: String
    ): String {

        return try {

            val formatter = SimpleDateFormat(
                FORMAT_DATE_TIME,
                Locale.getDefault()
            )

            formatter.timeZone =
                TimeZone.getTimeZone(timezone)

            formatter.format(date)

        } catch (exception: Exception) {

            formatDate(date)
        }
    }

    // ----------------------------------------------------------------
    // GENERATE TIMESTAMP
    // ----------------------------------------------------------------

    fun generateTimestamp(): String {

        return SimpleDateFormat(
            "yyyyMMdd_HHmmss",
            Locale.getDefault()
        ).format(Date())
    }
}
