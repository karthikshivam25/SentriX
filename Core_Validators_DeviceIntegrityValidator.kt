package com.sentrix.core.validators

import android.content.Context
import android.os.Build
import com.sentrix.core.exceptions.InvalidDeviceIntegrityException
import com.sentrix.core.exceptions.RequiredFieldException
import com.sentrix.core.helpers.EmulatorDetectionHelper
import com.sentrix.core.helpers.RootDetectionHelper

/**
 * DeviceIntegrityValidator
 *
 * Responsibilities:
 * - Device integrity validation
 * - Root detection verification
 * - Emulator detection
 * - System security checks
 * - Device trust assessment
 */
object DeviceIntegrityValidator {

    /**
     * Validate device integrity.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidDeviceIntegrityException::class
    )
    fun validate(
        context: Context?
    ): Boolean {

        if (context == null) {
            throw RequiredFieldException(
                "Context"
            )
        }

        if (
            RootDetectionHelper.isRooted()
        ) {
            throw InvalidDeviceIntegrityException(
                "Rooted device detected."
            )
        }

        if (
            EmulatorDetectionHelper.isEmulator()
        ) {
            throw InvalidDeviceIntegrityException(
                "Emulator detected."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        context: Context?
    ): Boolean {

        return try {

            validate(context)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check root status.
     */
    fun isRooted(): Boolean {

        return RootDetectionHelper
            .isRooted()
    }

    /**
     * Check emulator status.
     */
    fun isEmulator(): Boolean {

        return EmulatorDetectionHelper
            .isEmulator()
    }

    /**
     * Check if device is physical.
     */
    fun isPhysicalDevice(): Boolean {

        return !isEmulator()
    }

    /**
     * Get Android version.
     */
    fun getAndroidVersion(): String {

        return Build.VERSION.RELEASE
    }

    /**
     * Get SDK version.
     */
    fun getSdkVersion(): Int {

        return Build.VERSION.SDK_INT
    }

    /**
     * Calculate integrity score.
     */
    fun getIntegrityScore(): Int {

        var score = 100

        if (isRooted()) {
            score -= 50
        }

        if (isEmulator()) {
            score -= 30
        }

        if (
            Build.VERSION.SDK_INT <
            Build.VERSION_CODES.O
        ) {
            score -= 10
        }

        return score.coerceAtLeast(0)
    }

    /**
     * Get integrity level.
     */
    fun getIntegrityLevel(): String {

        return when (
            getIntegrityScore()
        ) {

            in 90..100 ->
                "Trusted"

            in 70..89 ->
                "Secure"

            in 50..69 ->
                "Moderate"

            in 30..49 ->
                "Compromised"

            else ->
                "Critical"
        }
    }

    /**
     * Generate integrity summary.
     */
    fun getSummary(): String {

        return buildString {

            appendLine(
                "Rooted: ${isRooted()}"
            )

            appendLine(
                "Emulator: ${isEmulator()}"
            )

            appendLine(
                "Physical Device: ${
                    isPhysicalDevice()
                }"
            )

            appendLine(
                "Android Version: ${
                    getAndroidVersion()
                }"
            )

            appendLine(
                "SDK Version: ${
                    getSdkVersion()
                }"
            )

            appendLine(
                "Integrity Score: ${
                    getIntegrityScore()
                }"
            )

            appendLine(
                "Integrity Level: ${
                    getIntegrityLevel()
                }"
            )
        }
    }
}
