package com.sentrix.data.local.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

import com.sentrix.data.local.entities.VPNConnectionEntity

import kotlinx.coroutines.flow.Flow

/**
 * VPNConnectionDao
 *
 * Data Access Object responsible
 * for managing VPN connection
 * records within SentriX.
 *
 * Responsibilities:
 * - Store VPN sessions
 * - Retrieve connection history
 * - Monitor VPN activity
 * - Track VPN usage statistics
 * - Support privacy analytics
 */
@Dao
interface VPNConnectionDao {

    /**
     * Inserts VPN connection.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertVPNConnection(
        connection: VPNConnectionEntity
    )

    /**
     * Inserts multiple VPN connections.
     */
    @Insert(
        onConflict =
            OnConflictStrategy.REPLACE
    )
    suspend fun insertVPNConnections(
        connections:
            List<VPNConnectionEntity>
    )

    /**
     * Updates VPN connection.
     */
    @Update
    suspend fun updateVPNConnection(
        connection: VPNConnectionEntity
    )

    /**
     * Deletes VPN connection.
     */
    @Delete
    suspend fun deleteVPNConnection(
        connection: VPNConnectionEntity
    )

    /**
     * Retrieves all VPN connections.
     */
    @Query(
        """
        SELECT *
        FROM vpn_connections
        ORDER BY connectedAt DESC
        """
    )
    fun getAllVPNConnections():
        Flow<List<VPNConnectionEntity>>

    /**
     * Retrieves VPN connection by id.
     */
    @Query(
        """
        SELECT *
        FROM vpn_connections
        WHERE connectionId = :connectionId
        LIMIT 1
        """
    )
    suspend fun getVPNConnectionById(
        connectionId: String
    ): VPNConnectionEntity?

    /**
     * Retrieves active VPN session.
     */
    @Query(
        """
        SELECT *
        FROM vpn_connections
        WHERE isConnected = 1
        LIMIT 1
        """
    )
    suspend fun getActiveVPNConnection():
        VPNConnectionEntity?

    /**
     * Retrieves recent VPN sessions.
     */
    @Query(
        """
        SELECT *
        FROM vpn_connections
        ORDER BY connectedAt DESC
        LIMIT :limit
        """
    )
    suspend fun getRecentVPNConnections(
        limit: Int = 10
    ): List<VPNConnectionEntity>

    /**
     * Counts total VPN sessions.
     */
    @Query(
        """
        SELECT COUNT(*)
        FROM vpn_connections
        """
    )
    suspend fun getVPNConnectionCount():
        Int

    /**
     * Calculates total VPN usage.
     */
    @Query(
        """
        SELECT SUM(sessionDuration)
        FROM vpn_connections
        """
    )
    suspend fun getTotalUsageDuration():
        Long?

    /**
     * Retrieves VPN sessions
     * by server location.
     */
    @Query(
        """
        SELECT *
        FROM vpn_connections
        WHERE serverLocation = :location
        ORDER BY connectedAt DESC
        """
    )
    fun getVPNConnectionsByLocation(
        location: String
    ): Flow<List<VPNConnectionEntity>>

    /**
     * Deletes all VPN history.
     */
    @Query(
        """
        DELETE FROM vpn_connections
        """
    )
    suspend fun clearVPNConnections()
}
