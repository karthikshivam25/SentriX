package com.sentrix.domain.repositories

import com.sentrix.domain.models.DeviceIntegrity
import com.sentrix.domain.models.DeviceTrustLevel
import com.sentrix.domain.models.DeviceType

/**
 * DeviceRepository
 *
 * Repository responsible for
 * managing device-related
 * information within the
 * SentriX cybersecurity platform.
 *
 * Used by:
 * - ValidateDeviceTrustUseCase
 * - DeviceIntegrityManager
 * - SecurityDashboard
 * - CyberDefenseManager
 * - DeviceMonitoringEngine
 *
 * Responsibilities:
 * - Retrieve device information
 * - Monitor device integrity
 * - Validate trust status
 * - Store device records
 * - Support security analysis
 */
interface DeviceRepository {

    /**
     * Retrieves current device.
     *
     * @return Device information.
     */
    suspend fun getDevice():
        DeviceInfo?

    /**
     * Saves device information.
     *
     * @param device Device information.
     */
    suspend fun saveDevice(
        device: DeviceInfo
    )

    /**
     * Updates device information.
     *
     * @param device Device information.
     */
    suspend fun updateDevice(
        device: DeviceInfo
    )

    /**
     * Retrieves device integrity.
     *
     * @return Device integrity.
     */
    suspend fun getDeviceIntegrity():
        DeviceIntegrity

    /**
     * Retrieves device trust level.
     *
     * @return Trust level.
     */
    suspend fun getTrustLevel():
        DeviceTrustLevel

    /**
     * Checks whether device
     * is trusted.
     *
     * @return Trust status.
     */
    suspend fun isDeviceTrusted():
        Boolean

    /**
     * Retrieves registered devices.
     *
     * @return Device list.
     */
    suspend fun getRegisteredDevices():
        List<DeviceInfo>

    /**
     * Deletes device.
     *
     * @param deviceId Device ID.
     */
    suspend fun deleteDevice(
        deviceId: String
    )
}

/**
 * DeviceInfo
 *
 * Represents device
 * information.
 */
data class DeviceInfo(

    /**
     * Device identifier.
     */
    val deviceId: String,

    /**
     * Device name.
     */
    val deviceName: String,

    /**
     * Device manufacturer.
     */
    val manufacturer: String,

    /**
     * Device model.
     */
    val model: String,

    /**
     * Operating system.
     */
    val operatingSystem: String,

    /**
     * Device type.
     */
    val deviceType:
        DeviceType,

    /**
     * Registration timestamp.
     */
    val registeredAt: Long,

    /**
     * Device trust level.
     */
    val trustLevel:
        DeviceTrustLevel
)

/**
 * Device types.
 */
enum class DeviceType {

    /**
     * Android device.
     */
    ANDROID,

    /**
     * iOS device.
     */
    IOS,

    /**
     * Windows device.
     */
    WINDOWS,

    /**
     * macOS device.
     */
    MACOS,

    /**
     * Linux device.
     */
    LINUX,

    /**
     * Unknown device.
     */
    UNKNOWN
}

/**
 * Device trust levels.
 */
enum class DeviceTrustLevel {

    /**
     * Fully trusted device.
     */
    TRUSTED,

    /**
     * Secure device.
     */
    SECURE,

    /**
     * Moderate trust.
     */
    MODERATE,

    /**
     * Untrusted device.
     */
    UNTRUSTED,

    /**
     * Compromised device.
     */
    COMPROMISED
}
