package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Device Integrity Engine
 *
 * Responsible for:
 * - Root detection analysis
 * - Emulator detection
 * - Debugger detection
 * - Bootloader validation
 * - Device trust assessment
 */
class DeviceIntegrityEngine {

    private val integrityReports =
        ConcurrentHashMap<String, IntegrityReport>()

    data class IntegrityReport(
        val deviceId: String,
        val isRooted: Boolean,
        val isEmulator: Boolean,
        val isDebuggerAttached: Boolean,
        val isBootloaderUnlocked: Boolean,
        val trustScore: Int,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Performs device integrity analysis.
     */
    suspend fun analyzeDevice(
        deviceId: String,
        isRooted: Boolean,
        isEmulator: Boolean,
        isDebuggerAttached: Boolean,
        isBootloaderUnlocked: Boolean
    ): NetworkResult<IntegrityReport> = withContext(Dispatchers.Default) {

        try {

            val trustScore = calculateTrustScore(
                isRooted = isRooted,
                isEmulator = isEmulator,
                isDebuggerAttached = isDebuggerAttached,
                isBootloaderUnlocked = isBootloaderUnlocked
            )

            val report = IntegrityReport(
                deviceId = deviceId,
                isRooted = isRooted,
                isEmulator = isEmulator,
                isDebuggerAttached = isDebuggerAttached,
                isBootloaderUnlocked = isBootloaderUnlocked,
                trustScore = trustScore
            )

            integrityReports[deviceId] = report

            NetworkResult.Success(report)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Device integrity analysis failed"
            )
        }
    }

    /**
     * Registers an integrity report.
     */
    fun registerReport(
        report: IntegrityReport
    ) {
        integrityReports[report.deviceId] = report
    }

    /**
     * Retrieves an integrity report.
     */
    fun getReport(
        deviceId: String
    ): IntegrityReport? {
        return integrityReports[deviceId]
    }

    /**
     * Returns all integrity reports.
     */
    fun getReports(): List<IntegrityReport> {
        return integrityReports.values.toList()
    }

    /**
     * Calculates device trust score.
     */
    fun calculateTrustScore(
        isRooted: Boolean,
        isEmulator: Boolean,
        isDebuggerAttached: Boolean,
        isBootloaderUnlocked: Boolean
    ): Int {

        var score = 100

        if (isRooted) score -= 40
        if (isEmulator) score -= 25
        if (isDebuggerAttached) score -= 20
        if (isBootloaderUnlocked) score -= 15

        return score.coerceIn(0, 100)
    }

    /**
     * Determines whether device is trusted.
     */
    fun isTrustedDevice(
        trustScore: Int,
        minimumTrustScore: Int = 75
    ): Boolean {
        return trustScore >= minimumTrustScore
    }

    /**
     * Returns trust level.
     */
    fun getTrustLevel(
        trustScore: Int
    ): String {
        return when {
            trustScore >= 90 -> "TRUSTED"
            trustScore >= 75 -> "SECURE"
            trustScore >= 50 -> "WARNING"
            trustScore >= 25 -> "HIGH_RISK"
            else -> "UNTRUSTED"
        }
    }

    /**
     * Detects integrity violations.
     */
    fun detectViolations(
        report: IntegrityReport
    ): List<String> {

        val violations = mutableListOf<String>()

        if (report.isRooted) {
            violations.add("Root access detected")
        }

        if (report.isEmulator) {
            violations.add("Emulator detected")
        }

        if (report.isDebuggerAttached) {
            violations.add("Debugger attached")
        }

        if (report.isBootloaderUnlocked) {
            violations.add("Bootloader unlocked")
        }

        return violations
    }

    /**
     * Generates security recommendations.
     */
    fun generateRecommendations(
        trustScore: Int
    ): List<String> {

        return when {
            trustScore >= 90 -> listOf(
                "Device integrity is excellent."
            )

            trustScore >= 75 -> listOf(
                "Device integrity is secure.",
                "Continue monitoring device status."
            )

            trustScore >= 50 -> listOf(
                "Review device security configuration.",
                "Investigate detected anomalies."
            )

            trustScore >= 25 -> listOf(
                "Restrict sensitive operations.",
                "Perform a full security audit."
            )

            else -> listOf(
                "Device is not trusted.",
                "Block access to sensitive resources.",
                "Immediate remediation required."
            )
        }
    }

    /**
     * Removes a report.
     */
    fun removeReport(
        deviceId: String
    ) {
        integrityReports.remove(deviceId)
    }

    /**
     * Clears all reports.
     */
    fun clearReports() {
        integrityReports.clear()
    }

    /**
     * Returns report count.
     */
    fun getReportCount(): Int {
        return integrityReports.size
    }

    /**
     * Returns untrusted devices.
     */
    fun getUntrustedDevices(): List<IntegrityReport> {
        return integrityReports.values.filter {
            !isTrustedDevice(it.trustScore)
        }
    }
}
