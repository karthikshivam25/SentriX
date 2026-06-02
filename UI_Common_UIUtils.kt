package com.sentrix.ui.common

import android.content.Context
import android.widget.Toast
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

object UIUtils {

    // ----------------------------------------------------------------
    // DATE & TIME
    // ----------------------------------------------------------------

    fun getCurrentFormattedTime(): String {

        return SimpleDateFormat(
            "hh:mm a",
            Locale.getDefault()
        ).format(Date())
    }

    fun getCurrentFormattedDate(): String {

        return SimpleDateFormat(
            "dd MMM yyyy",
            Locale.getDefault()
        ).format(Date())
    }

    // ----------------------------------------------------------------
    // TOAST
    // ----------------------------------------------------------------

    fun showToast(
        context: Context,
        message: String
    ) {

        Toast.makeText(
            context,
            message,
            Toast.LENGTH_SHORT
        ).show()
    }

    // ----------------------------------------------------------------
    // SECURITY SCORE FORMAT
    // ----------------------------------------------------------------

    fun formatSecurityScore(
        score: Int
    ): String {

        return "$score%"
    }

    // ----------------------------------------------------------------
    // THREAT COUNT FORMAT
    // ----------------------------------------------------------------

    fun formatThreatCount(
        count: Int
    ): String {

        return when {

            count >= 1_000_000 -> {
                "${(count / 1_000_000f).roundToInt()}M"
            }

            count >= 1_000 -> {
                "${(count / 1_000f).roundToInt()}K"
            }

            else -> {
                count.toString()
            }
        }
    }

    // ----------------------------------------------------------------
    // FILE SIZE FORMAT
    // ----------------------------------------------------------------

    fun formatFileSize(
        bytes: Long
    ): String {

        return when {

            bytes >= 1024L * 1024L * 1024L -> {
                String.format(
                    "%.2f GB",
                    bytes / (1024f * 1024f * 1024f)
                )
            }

            bytes >= 1024L * 1024L -> {
                String.format(
                    "%.2f MB",
                    bytes / (1024f * 1024f)
                )
            }

            bytes >= 1024L -> {
                String.format(
                    "%.2f KB",
                    bytes / 1024f
                )
            }

            else -> {
                "$bytes B"
            }
        }
    }

    // ----------------------------------------------------------------
    // NETWORK SPEED FORMAT
    // ----------------------------------------------------------------

    fun formatNetworkSpeed(
        speedKbps: Float
    ): String {

        return when {

            speedKbps >= 1024f -> {
                String.format(
                    "%.2f MB/s",
                    speedKbps / 1024f
                )
            }

            else -> {
                String.format(
                    "%.0f KB/s",
                    speedKbps
                )
            }
        }
    }

    // ----------------------------------------------------------------
    // RISK LEVEL TEXT
    // ----------------------------------------------------------------

    fun getRiskLevel(
        score: Int
    ): String {

        return when {

            score >= 85 -> {
                "Low Risk"
            }

            score >= 60 -> {
                "Moderate Risk"
            }

            score >= 35 -> {
                "High Risk"
            }

            else -> {
                "Critical Risk"
            }
        }
    }

    // ----------------------------------------------------------------
    // SECURITY COLOR
    // ----------------------------------------------------------------

    fun getSecurityColor(
        score: Int
    ): Color {

        return when {

            score >= 85 -> {
                UIConstants.SuccessGreen
            }

            score >= 60 -> {
                UIConstants.WarningYellow
            }

            else -> {
                UIConstants.DangerRed
            }
        }
    }

    // ----------------------------------------------------------------
    // ANIMATED COLOR TRANSITION
    // ----------------------------------------------------------------

    fun interpolateColor(
        startColor: Color,
        endColor: Color,
        fraction: Float
    ): Color {

        return lerp(
            start = startColor,
            stop = endColor,
            fraction = fraction
        )
    }

    // ----------------------------------------------------------------
    // MASK EMAIL
    // ----------------------------------------------------------------

    fun maskEmail(
        email: String
    ): String {

        val parts = email.split("@")

        if (parts.size != 2) {
            return email
        }

        val username = parts[0]

        val maskedName = when {

            username.length <= 2 -> {
                "*".repeat(username.length)
            }

            else -> {
                username.take(2) +
                        "*".repeat(username.length - 2)
            }
        }

        return "$maskedName@${parts[1]}"
    }

    // ----------------------------------------------------------------
    // MASK PHONE NUMBER
    // ----------------------------------------------------------------

    fun maskPhoneNumber(
        phone: String
    ): String {

        return if (phone.length >= 4) {

            "*".repeat(phone.length - 4) +
                    phone.takeLast(4)

        } else {
            phone
        }
    }

    // ----------------------------------------------------------------
    // THREAT STATUS
    // ----------------------------------------------------------------

    fun getThreatStatusMessage(
        threatCount: Int
    ): String {

        return when {

            threatCount == 0 -> {
                "Your device is fully protected"
            }

            threatCount <= 3 -> {
                "Minor threats detected"
            }

            threatCount <= 10 -> {
                "Potential risks identified"
            }

            else -> {
                "Critical threats detected"
            }
        }
    }
}
