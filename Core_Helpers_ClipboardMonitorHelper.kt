package com.sentrix.core.helpers

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import java.util.Locale

object ClipboardMonitorHelper {

    /**
     * Suspicious clipboard keywords
     */
    private val suspiciousKeywords = listOf(
        "password",
        "otp",
        "bank",
        "credit card",
        "cvv",
        "upi",
        "crypto",
        "wallet",
        "private key",
        "seed phrase"
    )

    /**
     * Get current clipboard text
     */
    fun getClipboardText(
        context: Context
    ): String? {

        return try {

            val clipboardManager =
                context.getSystemService(Context.CLIPBOARD_SERVICE)
                        as ClipboardManager

            if (!clipboardManager.hasPrimaryClip()) {
                return null
            }

            val clipData = clipboardManager.primaryClip
                ?: return null

            val item = clipData.getItemAt(0)

            item.text?.toString()

        } catch (e: Exception) {
            null
        }
    }

    /**
     * Copy text to clipboard
     */
    fun copyToClipboard(
        context: Context,
        label: String,
        text: String
    ) {

        try {

            val clipboardManager =
                context.getSystemService(Context.CLIPBOARD_SERVICE)
                        as ClipboardManager

            val clipData =
                ClipData.newPlainText(label, text)

            clipboardManager.setPrimaryClip(clipData)

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * Clear clipboard contents
     */
    fun clearClipboard(
        context: Context
    ) {

        try {

            val clipboardManager =
                context.getSystemService(Context.CLIPBOARD_SERVICE)
                        as ClipboardManager

            val emptyClip =
                ClipData.newPlainText("", "")

            clipboardManager.setPrimaryClip(emptyClip)

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * Check if clipboard contains sensitive data
     */
    fun containsSensitiveData(
        clipboardText: String?
    ): Boolean {

        if (clipboardText.isNullOrBlank()) {
            return false
        }

        val lowerCaseText =
            clipboardText.lowercase(Locale.getDefault())

        return suspiciousKeywords.any {
            lowerCaseText.contains(it)
        }
    }

    /**
     * Detect possible OTP code
     */
    fun containsOtp(
        clipboardText: String?
    ): Boolean {

        if (clipboardText.isNullOrBlank()) {
            return false
        }

        val otpRegex = Regex("\\b\\d{4,8}\\b")

        return otpRegex.containsMatchIn(clipboardText)
    }

    /**
     * Detect possible credit card number
     */
    fun containsCreditCard(
        clipboardText: String?
    ): Boolean {

        if (clipboardText.isNullOrBlank()) {
            return false
        }

        val cardRegex =
            Regex("\\b(?:\\d[ -]*?){13,16}\\b")

        return cardRegex.containsMatchIn(clipboardText)
    }

    /**
     * Detect crypto wallet keywords
     */
    fun containsCryptoData(
        clipboardText: String?
    ): Boolean {

        if (clipboardText.isNullOrBlank()) {
            return false
        }

        val cryptoKeywords = listOf(
            "wallet",
            "seed",
            "private key",
            "mnemonic",
            "btc",
            "eth"
        )

        val lowerCaseText =
            clipboardText.lowercase(Locale.getDefault())

        return cryptoKeywords.any {
            lowerCaseText.contains(it)
        }
    }

    /**
     * Analyze clipboard content
     */
    fun analyzeClipboard(
        context: Context
    ): ClipboardAnalysis {

        val clipboardText =
            getClipboardText(context)

        val sensitiveData =
            containsSensitiveData(clipboardText)

        val otpDetected =
            containsOtp(clipboardText)

        val creditCardDetected =
            containsCreditCard(clipboardText)

        val cryptoDetected =
            containsCryptoData(clipboardText)

        return ClipboardAnalysis(
            clipboardText = clipboardText ?: "",
            containsSensitiveData = sensitiveData,
            containsOtp = otpDetected,
            containsCreditCard = creditCardDetected,
            containsCryptoData = cryptoDetected,
            recommendation = generateRecommendation(
                sensitiveData,
                otpDetected,
                creditCardDetected,
                cryptoDetected
            )
        )
    }

    /**
     * Generate clipboard security recommendation
     */
    private fun generateRecommendation(
        sensitiveData: Boolean,
        otpDetected: Boolean,
        creditCardDetected: Boolean,
        cryptoDetected: Boolean
    ): String {

        return when {

            cryptoDetected -> {
                "Sensitive crypto wallet information detected. Clear clipboard immediately."
            }

            creditCardDetected -> {
                "Possible payment card data detected in clipboard. Use caution."
            }

            otpDetected -> {
                "OTP or verification code detected. Avoid sharing clipboard contents."
            }

            sensitiveData -> {
                "Sensitive information detected in clipboard."
            }

            else -> {
                "Clipboard appears safe."
            }
        }
    }

    /**
     * Clipboard analysis model
     */
    data class ClipboardAnalysis(
        val clipboardText: String,
        val containsSensitiveData: Boolean,
        val containsOtp: Boolean,
        val containsCreditCard: Boolean,
        val containsCryptoData: Boolean,
        val recommendation: String
    )
}
