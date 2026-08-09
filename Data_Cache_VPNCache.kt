package com.sentrix.data.cache

import com.sentrix.domain.models.VPNConnection
import com.sentrix.domain.models.VPNServer
import com.sentrix.domain.models.VPNStatistics
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - VPN Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Feature-specific cache for the SentriX VPN subsystem.
 *
 * VPNCache provides a strongly typed caching abstraction over
 * the generic CacheManager.
 *
 * Cached information includes:
 *
 * - Current VPN connection.
 * - VPN connection state.
 * - Active VPN server.
 * - Available VPN servers.
 * - Recommended VPN servers.
 * - Server details.
 * - VPN connection history.
 * - VPN statistics.
 * - VPN latency information.
 * - VPN bandwidth information.
 * - VPN security status.
 * - VPN dashboard information.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class does NOT:
 *
 * - Establish VPN connections.
 * - Disconnect the VPN.
 * - Select a VPN server based on security policy.
 * - Calculate security decisions.
 * - Perform network requests.
 * - Modify Android VPN configuration.
 *
 * Those responsibilities belong to the appropriate service,
 * manager, repository, or Domain layer.
 *
 * VPNCache only manages cached VPN DATA.
 *
 * Clean Architecture:
 *
 * VPNRepositoryImpl
 *       │
 *       ▼
 *    VPNCache
 *       │
 *       ▼
 *  CacheManager
 *       │
 *       ▼
 * In-Memory Cache
 */
@Singleton
class VPNCache @Inject constructor(
    private val cacheManager: CacheManager
) {

    // -------------------------------------------------------------------------
    // Cache Namespace
    // -------------------------------------------------------------------------

    /**
     * Root namespace for all SentriX VPN cache entries.
     *
     * Using a dedicated prefix allows complete VPN cache
     * invalidation without affecting Threat, Privacy,
     * Scanner, or Analytics caches.
     */
    private companion object {

        const val PREFIX =
            "vpn:"

        const val CURRENT_CONNECTION_KEY =
            "${PREFIX}current_connection"

        const val CONNECTION_STATE_KEY =
            "${PREFIX}connection_state"

        const val ACTIVE_SERVER_KEY =
            "${PREFIX}active_server"

        const val SERVER_LIST_KEY =
            "${PREFIX}server_list"

        const val RECOMMENDED_SERVERS_KEY =
            "${PREFIX}recommended_servers"

        const val CONNECTION_HISTORY_KEY =
            "${PREFIX}connection_history"

        const val STATISTICS_KEY =
            "${PREFIX}statistics"

        const val SECURITY_STATUS_KEY =
            "${PREFIX}security_status"

        const val DASHBOARD_KEY =
            "${PREFIX}dashboard"

        const val SERVER_PREFIX =
            "${PREFIX}server:"

        const val REGION_PREFIX =
            "${PREFIX}region:"

        const val COUNTRY_PREFIX =
            "${PREFIX}country:"

        const val RANGE_PREFIX =
            "${PREFIX}range:"

        /**
         * VPN connection state is highly dynamic.
         */
        const val CONNECTION_TTL =
            CacheManager.SHORT_TTL_MILLIS

        /**
         * Server metadata changes less frequently.
         */
        const val SERVER_TTL =
            CacheManager.LONG_TTL_MILLIS

        /**
         * Historical data can use a medium TTL.
         */
        const val HISTORY_TTL =
            CacheManager.MEDIUM_TTL_MILLIS
    }

    // -------------------------------------------------------------------------
    // Current VPN Connection
    // -------------------------------------------------------------------------

    /**
     * Stores the current VPN connection.
     *
     * This should contain the latest known connection state,
     * not the VPN operation itself.
     */
    fun putCurrentConnection(
        connection: VPNConnection,
        ttlMillis: Long = CONNECTION_TTL
    ) {

        cacheManager.put(
            key = CURRENT_CONNECTION_KEY,
            value = connection,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the current VPN connection.
     */
    fun getCurrentConnection():
        VPNConnection? {

        return cacheManager.get(
            CURRENT_CONNECTION_KEY
        )
    }

    /**
     * Checks whether current VPN connection information
     * exists in the cache.
     */
    fun containsCurrentConnection(): Boolean {

        return cacheManager.contains(
            CURRENT_CONNECTION_KEY
        )
    }

    /**
     * Removes current VPN connection information.
     */
    fun removeCurrentConnection(): Boolean {

        return cacheManager.remove(
            CURRENT_CONNECTION_KEY
        )
    }

    /**
     * Refreshes current VPN connection information.
     */
    fun refreshCurrentConnection(
        connection: VPNConnection,
        ttlMillis: Long = CONNECTION_TTL
    ) {

        cacheManager.refresh(
            key = CURRENT_CONNECTION_KEY,
            value = connection,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads current VPN connection using cache-aside behavior.
     */
    suspend fun getCurrentConnectionOrLoad(
        ttlMillis: Long = CONNECTION_TTL,
        loader: suspend () -> VPNConnection
    ): VPNConnection {

        return cacheManager.getOrPut(
            key = CURRENT_CONNECTION_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // VPN Connection State
    // -------------------------------------------------------------------------

    /**
     * Stores a simple VPN connection state.
     *
     * Examples:
     *
     * - CONNECTED
     * - CONNECTING
     * - DISCONNECTING
     * - DISCONNECTED
     * - FAILED
     */
    fun putConnectionState(
        state: String,
        ttlMillis: Long = CONNECTION_TTL
    ) {

        if (state.isBlank()) {
            return
        }

        cacheManager.put(
            key = CONNECTION_STATE_KEY,
            value = state,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached VPN connection state.
     */
    fun getConnectionState():
        String? {

        return cacheManager.get(
            CONNECTION_STATE_KEY
        )
    }

    /**
     * Removes cached VPN connection state.
     */
    fun removeConnectionState(): Boolean {

        return cacheManager.remove(
            CONNECTION_STATE_KEY
        )
    }

    /**
     * Stores connection state and current connection
     * together.
     */
    fun refreshConnectionState(
        state: String,
        connection: VPNConnection? = null,
        ttlMillis: Long = CONNECTION_TTL
    ) {

        if (state.isNotBlank()) {

            cacheManager.refresh(
                key = CONNECTION_STATE_KEY,
                value = state,
                ttlMillis = ttlMillis
            )
        }

        if (connection != null) {

            cacheManager.refresh(
                key = CURRENT_CONNECTION_KEY,
                value = connection,
                ttlMillis = ttlMillis
            )
        }
    }

    // -------------------------------------------------------------------------
    // Active VPN Server
    // -------------------------------------------------------------------------

    /**
     * Stores the currently selected VPN server.
     */
    fun putActiveServer(
        server: VPNServer,
        ttlMillis: Long = SERVER_TTL
    ) {

        cacheManager.put(
            key = ACTIVE_SERVER_KEY,
            value = server,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the currently selected VPN server.
     */
    fun getActiveServer():
        VPNServer? {

        return cacheManager.get(
            ACTIVE_SERVER_KEY
        )
    }

    /**
     * Checks whether an active server exists in cache.
     */
    fun containsActiveServer(): Boolean {

        return cacheManager.contains(
            ACTIVE_SERVER_KEY
        )
    }

    /**
     * Removes the active server.
     */
    fun removeActiveServer(): Boolean {

        return cacheManager.remove(
            ACTIVE_SERVER_KEY
        )
    }

    /**
     * Refreshes the active server cache.
     */
    fun refreshActiveServer(
        server: VPNServer,
        ttlMillis: Long = SERVER_TTL
    ) {

        cacheManager.refresh(
            key = ACTIVE_SERVER_KEY,
            value = server,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // VPN Server List
    // -------------------------------------------------------------------------

    /**
     * Stores all available VPN servers.
     */
    fun putServerList(
        servers: List<VPNServer>,
        ttlMillis: Long = SERVER_TTL
    ) {

        cacheManager.put(
            key = SERVER_LIST_KEY,
            value = servers,
            ttlMillis = ttlMillis
        )

        /**
         * Populate individual server entries as well.
         *
         * This allows direct server lookup after the list has
         * been loaded.
         */
        servers.forEach { server ->

            putServer(
                server = server,
                ttlMillis = ttlMillis
            )
        }
    }

    /**
     * Retrieves all cached VPN servers.
     */
    fun getServerList():
        List<VPNServer>? {

        return cacheManager.get(
            SERVER_LIST_KEY
        )
    }

    /**
     * Checks whether the server list is cached.
     */
    fun containsServerList(): Boolean {

        return cacheManager.contains(
            SERVER_LIST_KEY
        )
    }

    /**
     * Removes the cached server list.
     */
    fun removeServerList(): Boolean {

        return cacheManager.remove(
            SERVER_LIST_KEY
        )
    }

    /**
     * Refreshes the VPN server list.
     */
    fun refreshServerList(
        servers: List<VPNServer>,
        ttlMillis: Long = SERVER_TTL
    ) {

        cacheManager.refresh(
            key = SERVER_LIST_KEY,
            value = servers,
            ttlMillis = ttlMillis
        )

        servers.forEach { server ->

            putServer(
                server = server,
                ttlMillis = ttlMillis
            )
        }
    }

    /**
     * Loads the server list using cache-aside behavior.
     */
    suspend fun getServerListOrLoad(
        ttlMillis: Long = SERVER_TTL,
        loader: suspend () -> List<VPNServer>
    ): List<VPNServer> {

        return cacheManager.getOrPut(
            key = SERVER_LIST_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Individual VPN Server
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for an individual VPN server.
     */
    private fun serverKey(
        serverId: String
    ): String {

        return SERVER_PREFIX +
            serverId.trim()
    }

    /**
     * Stores an individual VPN server.
     */
    fun putServer(
        server: VPNServer,
        ttlMillis: Long = SERVER_TTL
    ) {

        if (server.serverId.isBlank()) {
            return
        }

        cacheManager.put(
            key = serverKey(
                server.serverId
            ),
            value = server,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves an individual VPN server.
     */
    fun getServer(
        serverId: String
    ): VPNServer? {

        if (serverId.isBlank()) {
            return null
        }

        return cacheManager.get(
            serverKey(
                serverId
            )
        )
    }

    /**
     * Checks whether an individual server is cached.
     */
    fun containsServer(
        serverId: String
    ): Boolean {

        if (serverId.isBlank()) {
            return false
        }

        return cacheManager.contains(
            serverKey(
                serverId
            )
        )
    }

    /**
     * Removes an individual VPN server.
     */
    fun removeServer(
        serverId: String
    ): Boolean {

        if (serverId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            serverKey(
                serverId
            )
        )
    }

    // -------------------------------------------------------------------------
    // Recommended VPN Servers
    // -------------------------------------------------------------------------

    /**
     * Stores recommended VPN servers.
     *
     * The recommendation itself should have been produced by
     * Domain logic. This cache only stores the result.
     */
    fun putRecommendedServers(
        servers: List<VPNServer>,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = RECOMMENDED_SERVERS_KEY,
            value = servers,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached recommended VPN servers.
     */
    fun getRecommendedServers():
        List<VPNServer>? {

        return cacheManager.get(
            RECOMMENDED_SERVERS_KEY
        )
    }

    /**
     * Removes recommended server cache.
     */
    fun removeRecommendedServers(): Boolean {

        return cacheManager.remove(
            RECOMMENDED_SERVERS_KEY
        )
    }

    /**
     * Refreshes recommended VPN servers.
     */
    fun refreshRecommendedServers(
        servers: List<VPNServer>,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.refresh(
            key = RECOMMENDED_SERVERS_KEY,
            value = servers,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Region-Based Server Cache
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for region-filtered servers.
     */
    private fun regionKey(
        region: String
    ): String {

        return REGION_PREFIX +
            region.trim().lowercase()
    }

    /**
     * Stores servers for a region.
     */
    fun putServersByRegion(
        region: String,
        servers: List<VPNServer>,
        ttlMillis: Long = SERVER_TTL
    ) {

        if (region.isBlank()) {
            return
        }

        cacheManager.put(
            key = regionKey(
                region
            ),
            value = servers,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves servers for a region.
     */
    fun getServersByRegion(
        region: String
    ): List<VPNServer>? {

        if (region.isBlank()) {
            return null
        }

        return cacheManager.get(
            regionKey(
                region
            )
        )
    }

    /**
     * Removes servers for a region.
     */
    fun removeServersByRegion(
        region: String
    ): Boolean {

        if (region.isBlank()) {
            return false
        }

        return cacheManager.remove(
            regionKey(
                region
            )
        )
    }

    // -------------------------------------------------------------------------
    // Country-Based Server Cache
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for country-filtered servers.
     */
    private fun countryKey(
        countryCode: String
    ): String {

        return COUNTRY_PREFIX +
            countryCode.trim().uppercase()
    }

    /**
     * Stores servers for a country.
     */
    fun putServersByCountry(
        countryCode: String,
        servers: List<VPNServer>,
        ttlMillis: Long = SERVER_TTL
    ) {

        if (countryCode.isBlank()) {
            return
        }

        cacheManager.put(
            key = countryKey(
                countryCode
            ),
            value = servers,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves servers for a country.
     */
    fun getServersByCountry(
        countryCode: String
    ): List<VPNServer>? {

        if (countryCode.isBlank()) {
            return null
        }

        return cacheManager.get(
            countryKey(
                countryCode
            )
        )
    }

    /**
     * Removes country-specific server cache.
     */
    fun removeServersByCountry(
        countryCode: String
    ): Boolean {

        if (countryCode.isBlank()) {
            return false
        }

        return cacheManager.remove(
            countryKey(
                countryCode
            )
        )
    }

    // -------------------------------------------------------------------------
    // Connection History
    // -------------------------------------------------------------------------

    /**
     * Stores VPN connection history.
     */
    fun putConnectionHistory(
        history: List<VPNConnection>,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.put(
            key = CONNECTION_HISTORY_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached VPN connection history.
     */
    fun getConnectionHistory():
        List<VPNConnection>? {

        return cacheManager.get(
            CONNECTION_HISTORY_KEY
        )
    }

    /**
     * Checks whether connection history is cached.
     */
    fun containsConnectionHistory(): Boolean {

        return cacheManager.contains(
            CONNECTION_HISTORY_KEY
        )
    }

    /**
     * Removes VPN connection history.
     */
    fun removeConnectionHistory(): Boolean {

        return cacheManager.remove(
            CONNECTION_HISTORY_KEY
        )
    }

    /**
     * Refreshes VPN connection history.
     */
    fun refreshConnectionHistory(
        history: List<VPNConnection>,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.refresh(
            key = CONNECTION_HISTORY_KEY,
            value = history,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads VPN connection history using cache-aside behavior.
     */
    suspend fun getConnectionHistoryOrLoad(
        ttlMillis: Long = HISTORY_TTL,
        loader: suspend () -> List<VPNConnection>
    ): List<VPNConnection> {

        return cacheManager.getOrPut(
            key = CONNECTION_HISTORY_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // VPN Statistics
    // -------------------------------------------------------------------------

    /**
     * Stores current VPN statistics.
     *
     * Statistics are dynamic, so a short TTL is preferred.
     */
    fun putStatistics(
        statistics: VPNStatistics,
        ttlMillis: Long = CONNECTION_TTL
    ) {

        cacheManager.put(
            key = STATISTICS_KEY,
            value = statistics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached VPN statistics.
     */
    fun getStatistics():
        VPNStatistics? {

        return cacheManager.get(
            STATISTICS_KEY
        )
    }

    /**
     * Checks whether VPN statistics exist.
     */
    fun containsStatistics(): Boolean {

        return cacheManager.contains(
            STATISTICS_KEY
        )
    }

    /**
     * Removes VPN statistics.
     */
    fun removeStatistics(): Boolean {

        return cacheManager.remove(
            STATISTICS_KEY
        )
    }

    /**
     * Refreshes VPN statistics.
     */
    fun refreshStatistics(
        statistics: VPNStatistics,
        ttlMillis: Long = CONNECTION_TTL
    ) {

        cacheManager.refresh(
            key = STATISTICS_KEY,
            value = statistics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads VPN statistics using cache-aside behavior.
     */
    suspend fun getStatisticsOrLoad(
        ttlMillis: Long = CONNECTION_TTL,
        loader: suspend () -> VPNStatistics
    ): VPNStatistics {

        return cacheManager.getOrPut(
            key = STATISTICS_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Time-Range Statistics
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for time-range statistics.
     */
    private fun rangeKey(
        startTime: Long,
        endTime: Long
    ): String {

        return RANGE_PREFIX +
            "$startTime:$endTime"
    }

    /**
     * Stores VPN statistics for a specific period.
     */
    fun putRangeStatistics(
        startTime: Long,
        endTime: Long,
        statistics: VPNStatistics,
        ttlMillis: Long = HISTORY_TTL
    ) {

        if (startTime > endTime) {
            return
        }

        cacheManager.put(
            key = rangeKey(
                startTime,
                endTime
            ),
            value = statistics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves VPN statistics for a specific period.
     */
    fun getRangeStatistics(
        startTime: Long,
        endTime: Long
    ): VPNStatistics? {

        if (startTime > endTime) {
            return null
        }

        return cacheManager.get(
            rangeKey(
                startTime,
                endTime
            )
        )
    }

    /**
     * Removes VPN statistics for a time range.
     */
    fun removeRangeStatistics(
        startTime: Long,
        endTime: Long
    ): Boolean {

        if (startTime > endTime) {
            return false
        }

        return cacheManager.remove(
            rangeKey(
                startTime,
                endTime
            )
        )
    }

    /**
     * Loads range statistics using cache-aside behavior.
     */
    suspend fun getRangeStatisticsOrLoad(
        startTime: Long,
        endTime: Long,
        ttlMillis: Long = HISTORY_TTL,
        loader: suspend () -> VPNStatistics
    ): VPNStatistics {

        require(startTime <= endTime) {
            "Start time cannot be after end time."
        }

        return cacheManager.getOrPut(
            key = rangeKey(
                startTime,
                endTime
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // VPN Security Status
    // -------------------------------------------------------------------------

    /**
     * Stores VPN security status.
     *
     * The security status should be determined by Domain
     * security logic before being passed here.
     */
    fun putSecurityStatus(
        status: String,
        ttlMillis: Long = CONNECTION_TTL
    ) {

        if (status.isBlank()) {
            return
        }

        cacheManager.put(
            key = SECURITY_STATUS_KEY,
            value = status,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached VPN security status.
     */
    fun getSecurityStatus():
        String? {

        return cacheManager.get(
            SECURITY_STATUS_KEY
        )
    }

    /**
     * Removes cached VPN security status.
     */
    fun removeSecurityStatus(): Boolean {

        return cacheManager.remove(
            SECURITY_STATUS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // VPN Dashboard
    // -------------------------------------------------------------------------

    /**
     * Stores dashboard-oriented VPN information.
     *
     * The domain model is used directly here so this cache
     * does not introduce another presentation-layer model.
     */
    fun putDashboardData(
        data: VPNStatistics,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        cacheManager.put(
            key = DASHBOARD_KEY,
            value = data,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves dashboard-oriented VPN information.
     */
    fun getDashboardData():
        VPNStatistics? {

        return cacheManager.get(
            DASHBOARD_KEY
        )
    }

    /**
     * Removes VPN dashboard data.
     */
    fun removeDashboardData(): Boolean {

        return cacheManager.remove(
            DASHBOARD_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Cache Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates every VPN-related cache entry.
     *
     * This does not affect:
     *
     * - Threat cache.
     * - Privacy cache.
     * - Scanner cache.
     * - Analytics cache.
     */
    suspend fun invalidateAll() {

        cacheManager.invalidatePrefix(
            PREFIX
        )
    }

    /**
     * Invalidates connection-related information.
     *
     * Should be called when:
     *
     * - VPN connects.
     * - VPN disconnects.
     * - VPN connection fails.
     * - Active server changes.
     */
    suspend fun invalidateConnectionData() {

        cacheManager.remove(
            CURRENT_CONNECTION_KEY
        )

        cacheManager.remove(
            CONNECTION_STATE_KEY
        )

        cacheManager.remove(
            ACTIVE_SERVER_KEY
        )

        cacheManager.remove(
            STATISTICS_KEY
        )

        cacheManager.remove(
            SECURITY_STATUS_KEY
        )

        cacheManager.remove(
            DASHBOARD_KEY
        )
    }

    /**
     * Invalidates VPN server list and server metadata.
     */
    suspend fun invalidateServerData() {

        cacheManager.remove(
            SERVER_LIST_KEY
        )

        cacheManager.remove(
            RECOMMENDED_SERVERS_KEY
        )

        cacheManager.invalidatePrefix(
            SERVER_PREFIX
        )

        cacheManager.invalidatePrefix(
            REGION_PREFIX
        )

        cacheManager.invalidatePrefix(
            COUNTRY_PREFIX
        )
    }

    /**
     * Invalidates connection history.
     */
    suspend fun invalidateConnectionHistory() {

        cacheManager.remove(
            CONNECTION_HISTORY_KEY
        )

        cacheManager.invalidatePrefix(
            RANGE_PREFIX
        )
    }

    /**
     * Invalidates statistics.
     */
    suspend fun invalidateStatistics() {

        cacheManager.remove(
            STATISTICS_KEY
        )

        cacheManager.remove(
            DASHBOARD_KEY
        )

        cacheManager.invalidatePrefix(
            RANGE_PREFIX
        )
    }

    /**
     * Invalidates everything related to a specific VPN server.
     */
    suspend fun invalidateServer(
        serverId: String
    ) {

        if (serverId.isBlank()) {
            return
        }

        cacheManager.remove(
            serverKey(
                serverId
            )
        )

        /**
         * Server-list and recommendation caches may now be stale.
         */
        cacheManager.remove(
            SERVER_LIST_KEY
        )

        cacheManager.remove(
            RECOMMENDED_SERVERS_KEY
        )
    }

    /**
     * Removes expired VPN cache entries.
     */
    suspend fun removeExpiredEntries(): Int {

        return cacheManager.removeExpiredEntries()
    }

    /**
     * Returns global cache statistics.
     */
    fun getStatistics():
        CacheStatistics {

        return cacheManager.getStatistics()
    }
}
