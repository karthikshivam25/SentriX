package com.sentrix.domain.services

import com.sentrix.domain.models.DeviceIntegrity
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for root detection analysis.
 *
 * This service evaluates device root status,
 * identifies root-related security risks,
 * and generates threat indicators.
 */
class RootDetectionService {

    /**
     * Analyzes devices and generates root-related threats.
     *
     * Rules:
     * - Rooted device -> CRITICAL threat.
     * - Root management application detected -> HIGH threat.
     * - Suspicious system modification -> MEDIUM threat.
     */
    suspend fun analyzeRootStatus(
        devices: List<DeviceIntegrity>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        devices.mapNotNull { device ->

            when {

                // Device has root access
                device.isRooted -> {
                    ThreatIndicator(
                        id = device.deviceId,
                        threatName = "Root Access Detected",
                        severity = "CRITICAL",
                        description = "Device has elevated root privileges",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Root management application found
                device.hasRootManagementApp -> {
                    ThreatIndicator(
                        id = device.deviceId,
                        threatName = "Root Management App Detected",
                        severity = "HIGH",
                        description = "Root management application found on device",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Suspicious system modification
                device.hasSystemModification -> {
                    ThreatIndicator(
                        id = device.deviceId,
                        threatName = "System Modification Detected",
                        severity = "MEDIUM",
                        description = "Potential unauthorized system modification detected",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Checks whether the device is rooted.
     */
    suspend fun isRooted(
        device: DeviceIntegrity
    ): Boolean = withContext(Dispatchers.Default) {

        device.isRooted
    }

    /**
     * Returns all rooted devices.
     */
    suspend fun getRootedDevices(
        devices: List<DeviceIntegrity>
    ): List<DeviceIntegrity> = withContext(Dispatchers.Default) {

        devices.filter {
            it.isRooted
        }
    }

    /**
     * Returns devices with root management apps installed.
     */
    suspend fun getDevicesWithRootApps(
        devices: List<DeviceIntegrity>
    ): List<DeviceIntegrity> = withContext(Dispatchers.Default) {

        devices.filter {
            it.hasRootManagementApp
        }
    }

    /**
     * Returns devices with suspicious system modifications.
     */
    suspend fun getModifiedDevices(
        devices: List<DeviceIntegrity>
    ): List<DeviceIntegrity> = withContext(Dispatchers.Default) {

        devices.filter {
            it.hasSystemModification
        }
    }

    /**
     * Calculates overall root risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateRootRiskScore(
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
     * Determines if any root-related threats exist.
     */
    suspend fun hasRootThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns only critical root threats.
     */
    suspend fun getCriticalRootThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Generates a root detection summary.
     */
    suspend fun generateRootSummary(
        devices: List<DeviceIntegrity>
    ): String = withContext(Dispatchers.Default) {

        val totalDevices = devices.size

        val rootedDevices = devices.count {
            it.isRooted
        }

        val rootAppsDetected = devices.count {
            it.hasRootManagementApp
        }

        val modifiedDevices = devices.count {
            it.hasSystemModification
        }

        buildString {
            appendLine("Root Detection Summary")
            appendLine("----------------------")
            appendLine("Total Devices: $totalDevices")
            appendLine("Rooted Devices: $rootedDevices")
            appendLine("Root Management Apps: $rootAppsDetected")
            appendLine("Modified Devices: $modifiedDevices")
            appendLine(
                if (rootedDevices > 0)
                    "Status: Root Risk Detected"
                else
                    "Status: No Root Threats Found"
            )
        }
    }

    /**
     * Checks whether all devices pass root verification.
     */
    suspend fun areDevicesRootSafe(
        devices: List<DeviceIntegrity>
    ): Boolean = withContext(Dispatchers.Default) {

        devices.none {
            it.isRooted ||
            it.hasRootManagementApp ||
            it.hasSystemModification
        }
    }
} 
