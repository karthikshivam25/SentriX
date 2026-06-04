package com.sentrix.core.validators

import android.content.Context
import com.sentrix.core.exceptions.InvalidSecurityException
import com.sentrix.core.exceptions.RequiredFieldException
import com.sentrix.core.helpers.RootDetectionHelper
import com.sentrix.core.helpers.EmulatorDetectionHelper
import com.sentrix.core.helpers.VPNHelper

/**
 * SecurityValidator
 *
 * Responsibilities:
 * - Device security validation
 * - Root detection verification
 * - Emulator detection
 * - VPN security validation
 * - Security posture assessment
 */
object SecurityValidator {

    /**
     * Validate device security.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidSecurityException::class
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
            throw InvalidSecurityException(
                "Rooted device detected."
            )
        }

        if (
            EmulatorDetectionHelper.isEmulator()
        ) {
            throw InvalidSecurityException(
                "Emulator environment detected."
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
     * Check device root status.
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
     * Check VPN status.
     */
    fun isVpnActive(
        context: Context
    ): Boolean {

        return VPNHelper
            .isVpnConnected(
                context
            )
    }

    /**
     * Calculate security score.
     */
    fun getSecurityScore(
        context: Context
    ): Int {

        var score = 100

        if (isRooted()) {
            score -= 40
        }

        if (isEmulator()) {
            score -= 30
        }

        if (!isVpnActive(context)) {
            score -= 10
        }

        return score.coerceAtLeast(0)
    }

    /**
     * Get security level.
     */
    fun getSecurityLevel(
        context: Context
    ): String {

        return when (
            getSecurityScore(context)
        ) {

            in 90..100 ->
                "Excellent"

            in 70..89 ->
                "Good"

            in 50..69 ->
                "Moderate"

            in 30..49 ->
                "Poor"

            else ->
                "Critical"
        }
    }

    /**
     * Generate security summary.
     */
    fun getSummary(
        context: Context
    ): String {

        return buildString {

            appendLine(
                "Rooted: ${isRooted()}"
            )

            appendLine(
                "Emulator: ${isEmulator()}"
            )

            appendLine(
                "VPN Active: ${
                    isVpnActive(
                        context
                    )
                }"
            )

            appendLine(
                "Security Score: ${
                    getSecurityScore(
                        context
                    )
                }"
            )

            appendLine(
                "Security Level: ${
                    getSecurityLevel(
                        context
                    )
                }"
            )
        }
    }
}
