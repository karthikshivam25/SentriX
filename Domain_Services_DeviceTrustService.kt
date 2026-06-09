package com.sentrix.domain.services

import com.sentrix.domain.models.DeviceTrust
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for device trust evaluation.
 *
 * This service verifies device trustworthiness,
 * calculates trust scores,
 * and identifies potentially risky devices.
 */
class DeviceTrustService {

    /**
     * Calculates trust score for a device.
     *
     * Maximum score = 100
     */
    suspend fun calculateTrustScore(
        deviceTrust: DeviceTrust
    ): Int = withContext(Dispatchers.Default) {

        var score = 100

        if (deviceTrust.isRooted) {
            score -= 40
        }

        if (deviceTrust.isEmulator) {
            score -= 25
        }

        if (!deviceTrust.isEncrypted) {
            score -= 15
        }

        if (!deviceTrust.isScreenLockEnabled) {
            score -= 10
        }

        if (deviceTrust.hasSuspiciousApps) {
            score -= 10
        }

        score.coerceIn(0, 100)
    }

    /**
     * Determines trust level based on score.
     */
    suspend fun determineTrustLevel(
        trustScore: Int
    ): String = withContext(Dispatchers.Default) {

        when {
            trustScore >= 90 -> "TRUSTED"
            trustScore >= 75 -> "SECURE"
            trustScore >= 50 -> "MODERATE"
            trustScore >= 25 -> "LOW"
            else -> "UNTRUSTED"
        }
    }

    /**
     * Checks whether device is trusted.
     */
    suspend fun isDeviceTrusted(
        deviceTrust: DeviceTrust
    ): Boolean = withContext(Dispatchers.Default) {

        calculateTrustScore(deviceTrust) >= 75
    }

    /**
     * Returns trusted devices.
     */
    suspend fun getTrustedDevices(
        devices: List<DeviceTrust>
    ): List<DeviceTrust> = withContext(Dispatchers.Default) {

        devices.filter {
            calculateTrustScore(it) >= 75
        }
    }

    /**
     * Returns untrusted devices.
     */
    suspend fun getUntrustedDevices(
        devices: List<DeviceTrust>
    ): List<DeviceTrust> = withContext(Dispatchers.Default) {

        devices.filter {
            calculateTrustScore(it) < 75
        }
    }

    /**
     * Returns rooted devices.
     */
    suspend fun getRootedDevices(
        devices: List<DeviceTrust>
    ): List<DeviceTrust> = withContext(Dispatchers.Default) {

        devices.filter {
            it.isRooted
        }
    }

    /**
     * Returns emulator devices.
     */
    suspend fun getEmulatorDevices(
        devices: List<DeviceTrust>
    ): List<DeviceTrust> = withContext(Dispatchers.Default) {

        devices.filter {
            it.isEmulator
        }
    }

    /**
     * Calculates average trust score.
     */
    suspend fun calculateAverageTrustScore(
        devices: List<DeviceTrust>
    ): Double = withContext(Dispatchers.Default) {

        if (devices.isEmpty()) {
            return@withContext 0.0
        }

        devices
            .map { calculateTrustScore(it) }
            .average()
    }

    /**
     * Generates trust assessment report.
     */
    suspend fun generateTrustReport(
        devices: List<DeviceTrust>
    ): String = withContext(Dispatchers.Default) {

        val trustedDevices =
            getTrustedDevices(devices).size

        val untrustedDevices =
            getUntrustedDevices(devices).size

        val averageScore =
            calculateAverageTrustScore(devices)

        buildString {

            appendLine("SentriX Device Trust Report")
            appendLine("===========================")
            appendLine("Total Devices: ${devices.size}")
            appendLine("Trusted Devices: $trustedDevices")
            appendLine("Untrusted Devices: $untrustedDevices")
            appendLine(
                "Average Trust Score: ${
                    String.format("%.2f", averageScore)
                }"
            )
        }
    }

    /**
     * Returns devices requiring attention.
     */
    suspend fun getDevicesRequiringAttention(
        devices: List<DeviceTrust>
    ): List<DeviceTrust> = withContext(Dispatchers.Default) {

        devices.filter {
            calculateTrustScore(it) < 50
        }
    }

    /**
     * Determines whether all devices
     * satisfy trust requirements.
     */
    suspend fun areAllDevicesTrusted(
        devices: List<DeviceTrust>
    ): Boolean = withContext(Dispatchers.Default) {

        devices.all {
            calculateTrustScore(it) >= 75
        }
    }

    /**
     * Generates recommendations
     * for improving device trust.
     */
    suspend fun generateTrustRecommendations(
        deviceTrust: DeviceTrust
    ): List<String> = withContext(Dispatchers.Default) {

        val recommendations = mutableListOf<String>()

        if (deviceTrust.isRooted) {
            recommendations.add(
                "Remove root access to improve device security."
            )
        }

        if (deviceTrust.isEmulator) {
            recommendations.add(
                "Use a physical device instead of an emulator."
            )
        }

        if (!deviceTrust.isEncrypted) {
            recommendations.add(
                "Enable device encryption."
            )
        }

        if (!deviceTrust.isScreenLockEnabled) {
            recommendations.add(
                "Enable screen lock protection."
            )
        }

        if (deviceTrust.hasSuspiciousApps) {
            recommendations.add(
                "Remove suspicious applications."
            )
        }

        if (recommendations.isEmpty()) {
            recommendations.add(
                "Device meets trust requirements."
            )
        }

        recommendations
    }
}
