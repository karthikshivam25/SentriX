package com.cyberdefender.domain.services

import com.cyberdefender.domain.models.DeviceIntegrity
import com.cyberdefender.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for validating device integrity.
 *
 * This service checks device security status,
 * detects integrity violations, and generates
 * security threat indicators.
 */
class DeviceIntegrityService {

    /**
     * Analyzes device integrity information and
     * generates corresponding threat indicators.
     *
     * Rules:
     * - Rooted devices → CRITICAL threat.
     * - Bootloader unlocked → HIGH threat.
     * - Emulator detected → MEDIUM threat.
     * - Developer mode enabled → LOW threat.
     */
    suspend fun analyzeIntegrity(
        integrityList: List<DeviceIntegrity>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        integrityList.mapNotNull { integrity ->

            when {

                // Device is rooted
                integrity.isRooted -> {
                    ThreatIndicator(
                        id = integrity.deviceId,
                        threatName = "Rooted Device",
                        severity = "CRITICAL",
                        description = "Device root access detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Bootloader is unlocked
                integrity.isBootloaderUnlocked -> {
                    ThreatIndicator(
                        id = integrity.deviceId,
                        threatName = "Unlocked Bootloader",
                        severity = "HIGH",
                        description = "Device bootloader is unlocked",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Emulator environment detected
                integrity.isEmulator -> {
                    ThreatIndicator(
                        id = integrity.deviceId,
                        threatName = "Emulator Detected",
                        severity = "MEDIUM",
                        description = "Application is running inside an emulator",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Developer mode enabled
                integrity.isDeveloperModeEnabled -> {
                    ThreatIndicator(
                        id = integrity.deviceId,
                        threatName = "Developer Mode Enabled",
                        severity = "LOW",
                        description = "Developer options are enabled on device",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Determines whether device integrity has been compromised.
     */
    suspend fun isDeviceCompromised(
        integrity: DeviceIntegrity
    ): Boolean = withContext(Dispatchers.Default) {

        integrity.isRooted ||
        integrity.isBootloaderUnlocked ||
        integrity.isEmulator
    }

    /**
     * Returns all rooted devices.
     */
    suspend fun getRootedDevices(
        integrityList: List<DeviceIntegrity>
    ): List<DeviceIntegrity> = withContext(Dispatchers.Default) {

        integrityList.filter {
            it.isRooted
        }
    }

    /**
     * Returns devices with unlocked bootloaders.
     */
    suspend fun getUnlockedBootloaderDevices(
        integrityList: List<DeviceIntegrity>
    ): List<DeviceIntegrity> = withContext(Dispatchers.Default) {

        integrityList.filter {
            it.isBootloaderUnlocked
        }
    }

    /**
     * Returns emulator devices.
     */
    suspend fun getEmulatorDevices(
        integrityList: List<DeviceIntegrity>
    ): List<DeviceIntegrity> = withContext(Dispatchers.Default) {

        integrityList.filter {
            it.isEmulator
        }
    }

    /**
     * Calculates overall integrity risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateIntegrityRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf {
            when (it.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Generates a device integrity summary.
     */
    suspend fun generateIntegritySummary(
        integrityList: List<DeviceIntegrity>
    ): String = withContext(Dispatchers.Default) {

        val totalDevices = integrityList.size

        val rootedDevices = integrityList.count {
            it.isRooted
        }

        val unlockedDevices = integrityList.count {
            it.isBootloaderUnlocked
        }

        val emulatorDevices = integrityList.count {
            it.isEmulator
        }

        buildString {
            appendLine("Device Integrity Summary")
            appendLine("------------------------")
            appendLine("Total Devices: $totalDevices")
            appendLine("Rooted Devices: $rootedDevices")
            appendLine("Unlocked Bootloaders: $unlockedDevices")
            appendLine("Emulator Devices: $emulatorDevices")
            appendLine(
                if (rootedDevices > 0 || unlockedDevices > 0)
                    "Status: Security Risk Detected"
                else
                    "Status: Secure"
            )
        }
    }

    /**
     * Checks whether all devices pass integrity verification.
     */
    suspend fun areDevicesSecure(
        integrityList: List<DeviceIntegrity>
    ): Boolean = withContext(Dispatchers.Default) {

        integrityList.none {
            it.isRooted ||
            it.isBootloaderUnlocked ||
            it.isEmulator
        }
    }

    /**
     * Returns only critical integrity threats.
     */
    suspend fun getCriticalIntegrityThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }
}
