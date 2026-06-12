package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.DeviceTrustEntity

import kotlinx.coroutines.flow.Flow

/**
 * DeviceTrustDao
 *
 * Data Access Object responsible
 * for managing device trust
 * information within SentriX.
 *
 * Responsibilities:
 * - Store device trust records
 * - Monitor trusted devices
 * - Track trust scores
 * - Manage device verification
 * - Support zero-trust security
 */
@Dao
interface DeviceTrustDao {

    /**
     * Inserts device record.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertDevice(
        device: DeviceTrustEntity
    )

    /**
     * Inserts multiple devices.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertDevices(
        devices: List<DeviceTrustEntity>
    )

    /**
     * Updates device trust.
     */
    @Update
    suspend fun updateDevice(
        device: DeviceTrustEntity
    )

    /**
     * Deletes device.
     */
    @Delete
    suspend fun deleteDevice(
        device: DeviceTrustEntity
    )

    /**
     * Retrieves all devices.
     */
    @Query(
        """
        SELECT *
        FROM device_trust
        ORDER BY lastVerifiedAt DESC
        """
    )
    fun getAllDevices():
        Flow<List<DeviceTrustEntity>>

    /**
     * Retrieves device by id.
     */
    @Query(
        """
        SELECT *
        FROM device_trust
        WHERE deviceId = :deviceId
        LIMIT 1
        """
    )
    suspend fun getDeviceById(
        deviceId: String
    ): DeviceTrustEntity?

    /**
     * Retrieves trusted devices.
     */
    @Query(
        """
        SELECT *
        FROM device_trust
        WHERE isTrusted = 1
        ORDER BY trustScore DESC
        """
    )
    fun getTrustedDevices():
        Flow<List<DeviceTrustEntity>>

    /**
     * Retrieves untrusted devices.
     */
    @Query(
        """
        SELECT *
        FROM device_trust
        WHERE isTrusted = 0
        ORDER BY lastVerifiedAt DESC
        """
    )
    fun getUntrustedDevices():
        Flow<List<DeviceTrustEntity>>

    /**
     * Counts all devices.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM device_trust
        """
    )
    suspend fun getDeviceCount():
        Int

    /**
     * Counts trusted devices.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM device_trust
        WHERE isTrusted = 1
        """
    )
    suspend fun getTrustedDeviceCount():
        Int

    /**
     * Retrieves average trust score.
     */
    @Query(
        """
        SELECT AVG(trustScore)
        FROM device_trust
        """
    )
    suspend fun getAverageTrustScore():
        Double?

    /**
     * Updates trust score.
     */
    @Query(
        """
        UPDATE device_trust
        SET trustScore = :trustScore
        WHERE deviceId = :deviceId
        """
    )
    suspend fun updateTrustScore(
        deviceId: String,
        trustScore: Int
    )

    /**
     * Deletes all device records.
     */
    @Query(
        """
        DELETE FROM device_trust
        """
    )
    suspend fun clearDevices()
}
