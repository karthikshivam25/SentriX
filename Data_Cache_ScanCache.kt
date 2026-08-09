package com.sentrix.data.cache

import com.sentrix.domain.models.ScanConfiguration
import com.sentrix.domain.models.ScanResult
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Scan Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Feature-specific cache for the SentriX scanning subsystem.
 *
 * ScanCache provides a strongly typed caching abstraction over
 * the generic CacheManager.
 *
 * Cached information includes:
 *
 * - Latest scan result.
 * - Quick scan result.
 * - Smart scan result.
 * - Active scan state.
 * - Scan configuration.
 * - Application-specific scan results.
 * - Scan results by scan ID.
 * - Recent scan results.
 * - Scan statistics.
 * - Scan optimization information.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class does NOT:
 *
 * - Execute scans.
 * - Analyze malware.
 * - Determine threat severity.
 * - Make security decisions.
 * - Start background scanning.
 * - Stop running scan services.
 *
 * Those responsibilities belong to the Scanner/Domain layers.
 *
 * ScanCache only manages cached scan DATA.
 *
 * Clean Architecture:
 *
 * QuickScanRepositoryImpl
 * SmartScanRepositoryImpl
 * ScanHistoryRepositoryImpl
 * ScanOptimizationRepositoryImpl
 *          │
 *          ▼
 *       ScanCache
 *          │
 *          ▼
 *     CacheManager
 *          │
 *          ▼
 *    In-Memory Cache
 */
@Singleton
class ScanCache @Inject constructor(
    private val cacheManager: CacheManager
) {

    // -------------------------------------------------------------------------
    // Cache Namespace
    // -------------------------------------------------------------------------

    private companion object {

        const val PREFIX =
            "scan:"

        const val LATEST_RESULT_KEY =
            "${PREFIX}latest_result"

        const val QUICK_SCAN_RESULT_KEY =
            "${PREFIX}quick_result"

        const val SMART_SCAN_RESULT_KEY =
            "${PREFIX}smart_result"

        const val ACTIVE_SCAN_KEY =
            "${PREFIX}active"

        const val SCAN_STATE_KEY =
            "${PREFIX}state"

        const val SCAN_CONFIGURATION_KEY =
            "${PREFIX}configuration"

        const val RECENT_RESULTS_KEY =
            "${PREFIX}recent_results"

        const val STATISTICS_KEY =
            "${PREFIX}statistics"

        const val OPTIMIZATION_KEY =
            "${PREFIX}optimization"

        const val RESULT_PREFIX =
            "${PREFIX}result:"

        const val PACKAGE_PREFIX =
            "${PREFIX}package:"

        const val RANGE_PREFIX =
            "${PREFIX}range:"

        /**
         * Scan results can become stale quickly.
         */
        const val RESULT_TTL =
            CacheManager.SHORT_TTL_MILLIS

        /**
         * Scan configuration is relatively stable.
         */
        const val CONFIGURATION_TTL =
            CacheManager.MEDIUM_TTL_MILLIS

        /**
         * Historical scan information can use a medium TTL.
         */
        const val HISTORY_TTL =
            CacheManager.MEDIUM_TTL_MILLIS
    }

    // -------------------------------------------------------------------------
    // Latest Scan Result
    // -------------------------------------------------------------------------

    /**
     * Stores the latest completed scan result.
     */
    fun putLatestResult(
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        cacheManager.put(
            key = LATEST_RESULT_KEY,
            value = result,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the latest scan result.
     */
    fun getLatestResult():
        ScanResult? {

        return cacheManager.get(
            LATEST_RESULT_KEY
        )
    }

    /**
     * Checks whether the latest scan result exists.
     */
    fun containsLatestResult(): Boolean {

        return cacheManager.contains(
            LATEST_RESULT_KEY
        )
    }

    /**
     * Removes the latest scan result.
     */
    fun removeLatestResult(): Boolean {

        return cacheManager.remove(
            LATEST_RESULT_KEY
        )
    }

    /**
     * Refreshes the latest scan result.
     */
    fun refreshLatestResult(
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        cacheManager.refresh(
            key = LATEST_RESULT_KEY,
            value = result,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Quick Scan
    // -------------------------------------------------------------------------

    /**
     * Stores the latest Quick Scan result.
     */
    fun putQuickScanResult(
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        cacheManager.put(
            key = QUICK_SCAN_RESULT_KEY,
            value = result,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the cached Quick Scan result.
     */
    fun getQuickScanResult():
        ScanResult? {

        return cacheManager.get(
            QUICK_SCAN_RESULT_KEY
        )
    }

    /**
     * Checks whether Quick Scan result exists.
     */
    fun containsQuickScanResult(): Boolean {

        return cacheManager.contains(
            QUICK_SCAN_RESULT_KEY
        )
    }

    /**
     * Removes the Quick Scan result.
     */
    fun removeQuickScanResult(): Boolean {

        return cacheManager.remove(
            QUICK_SCAN_RESULT_KEY
        )
    }

    /**
     * Refreshes Quick Scan result.
     */
    fun refreshQuickScanResult(
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        cacheManager.refresh(
            key = QUICK_SCAN_RESULT_KEY,
            value = result,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads Quick Scan result using cache-aside behavior.
     */
    suspend fun getQuickScanResultOrLoad(
        ttlMillis: Long = RESULT_TTL,
        loader: suspend () -> ScanResult
    ): ScanResult {

        return cacheManager.getOrPut(
            key = QUICK_SCAN_RESULT_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Smart Scan
    // -------------------------------------------------------------------------

    /**
     * Stores the latest Smart Scan result.
     */
    fun putSmartScanResult(
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        cacheManager.put(
            key = SMART_SCAN_RESULT_KEY,
            value = result,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the Smart Scan result.
     */
    fun getSmartScanResult():
        ScanResult? {

        return cacheManager.get(
            SMART_SCAN_RESULT_KEY
        )
    }

    /**
     * Checks whether Smart Scan result exists.
     */
    fun containsSmartScanResult(): Boolean {

        return cacheManager.contains(
            SMART_SCAN_RESULT_KEY
        )
    }

    /**
     * Removes Smart Scan result.
     */
    fun removeSmartScanResult(): Boolean {

        return cacheManager.remove(
            SMART_SCAN_RESULT_KEY
        )
    }

    /**
     * Refreshes Smart Scan result.
     */
    fun refreshSmartScanResult(
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        cacheManager.refresh(
            key = SMART_SCAN_RESULT_KEY,
            value = result,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads Smart Scan result using cache-aside behavior.
     */
    suspend fun getSmartScanResultOrLoad(
        ttlMillis: Long = RESULT_TTL,
        loader: suspend () -> ScanResult
    ): ScanResult {

        return cacheManager.getOrPut(
            key = SMART_SCAN_RESULT_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Scan Result by ID
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for an individual scan result.
     */
    private fun resultKey(
        scanId: String
    ): String {

        return RESULT_PREFIX +
            scanId.trim()
    }

    /**
     * Stores an individual scan result.
     */
    fun putResult(
        scanId: String,
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        if (scanId.isBlank()) {
            return
        }

        cacheManager.put(
            key = resultKey(scanId),
            value = result,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves a scan result by scan ID.
     */
    fun getResult(
        scanId: String
    ): ScanResult? {

        if (scanId.isBlank()) {
            return null
        }

        return cacheManager.get(
            resultKey(scanId)
        )
    }

    /**
     * Checks whether a scan result is cached.
     */
    fun containsResult(
        scanId: String
    ): Boolean {

        if (scanId.isBlank()) {
            return false
        }

        return cacheManager.contains(
            resultKey(scanId)
        )
    }

    /**
     * Removes a scan result by ID.
     */
    fun removeResult(
        scanId: String
    ): Boolean {

        if (scanId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            resultKey(scanId)
        )
    }

    /**
     * Loads a scan result using cache-aside behavior.
     */
    suspend fun getResultOrLoad(
        scanId: String,
        ttlMillis: Long = RESULT_TTL,
        loader: suspend () -> ScanResult
    ): ScanResult {

        require(scanId.isNotBlank()) {
            "Scan ID cannot be blank."
        }

        return cacheManager.getOrPut(
            key = resultKey(scanId),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Application-Specific Scan Results
    // -------------------------------------------------------------------------

    /**
     * Generates a package-specific scan cache key.
     */
    private fun packageResultKey(
        packageName: String
    ): String {

        return PACKAGE_PREFIX +
            packageName.trim().lowercase()
    }

    /**
     * Stores the latest scan result for an Android package.
     */
    fun putPackageResult(
        packageName: String,
        result: ScanResult,
        ttlMillis: Long = RESULT_TTL
    ) {

        if (packageName.isBlank()) {
            return
        }

        cacheManager.put(
            key = packageResultKey(packageName),
            value = result,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the latest scan result for an application.
     */
    fun getPackageResult(
        packageName: String
    ): ScanResult? {

        if (packageName.isBlank()) {
            return null
        }

        return cacheManager.get(
            packageResultKey(packageName)
        )
    }

    /**
     * Checks whether an application's scan result exists.
     */
    fun containsPackageResult(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.contains(
            packageResultKey(packageName)
        )
    }

    /**
     * Removes an application's scan result.
     */
    fun removePackageResult(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.remove(
            packageResultKey(packageName)
        )
    }

    /**
     * Loads an application's scan result using cache-aside.
     */
    suspend fun getPackageResultOrLoad(
        packageName: String,
        ttlMillis: Long = RESULT_TTL,
        loader: suspend () -> ScanResult
    ): ScanResult {

        require(packageName.isNotBlank()) {
            "Package name cannot be blank."
        }

        return cacheManager.getOrPut(
            key = packageResultKey(packageName),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Active Scan
    // -------------------------------------------------------------------------

    /**
     * Stores information about the currently running scan.
     *
     * The type is generic because ActiveScanState may be
     * represented by a dedicated Domain model later.
     */
    fun <T : Any> putActiveScan(
        activeScan: T,
        ttlMillis: Long = RESULT_TTL
    ) {

        cacheManager.put(
            key = ACTIVE_SCAN_KEY,
            value = activeScan,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves active scan information.
     */
    inline fun <reified T : Any> getActiveScan():
        T? {

        return cacheManager.get(
            ACTIVE_SCAN_KEY
        )
    }

    /**
     * Checks whether an active scan is cached.
     */
    fun containsActiveScan(): Boolean {

        return cacheManager.contains(
            ACTIVE_SCAN_KEY
        )
    }

    /**
     * Removes active scan information.
     */
    fun removeActiveScan(): Boolean {

        return cacheManager.remove(
            ACTIVE_SCAN_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Scan State
    // -------------------------------------------------------------------------

    /**
     * Stores scan state.
     *
     * Examples:
     *
     * - IDLE
     * - RUNNING
     * - PAUSED
     * - COMPLETED
     * - FAILED
     * - CANCELLED
     */
    fun putScanState(
        state: String,
        ttlMillis: Long = RESULT_TTL
    ) {

        if (state.isBlank()) {
            return
        }

        cacheManager.put(
            key = SCAN_STATE_KEY,
            value = state,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached scan state.
     */
    fun getScanState():
        String? {

        return cacheManager.get(
            SCAN_STATE_KEY
        )
    }

    /**
     * Removes cached scan state.
     */
    fun removeScanState(): Boolean {

        return cacheManager.remove(
            SCAN_STATE_KEY
        )
    }

    /**
     * Updates the active scan state.
     */
    fun refreshScanState(
        state: String,
        ttlMillis: Long = RESULT_TTL
    ) {

        if (state.isBlank()) {
            return
        }

        cacheManager.refresh(
            key = SCAN_STATE_KEY,
            value = state,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Scan Configuration
    // -------------------------------------------------------------------------

    /**
     * Stores the current scan configuration.
     */
    fun putConfiguration(
        configuration: ScanConfiguration,
        ttlMillis: Long = CONFIGURATION_TTL
    ) {

        cacheManager.put(
            key = SCAN_CONFIGURATION_KEY,
            value = configuration,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached scan configuration.
     */
    fun getConfiguration():
        ScanConfiguration? {

        return cacheManager.get(
            SCAN_CONFIGURATION_KEY
        )
    }

    /**
     * Checks whether scan configuration is cached.
     */
    fun containsConfiguration(): Boolean {

        return cacheManager.contains(
            SCAN_CONFIGURATION_KEY
        )
    }

    /**
     * Removes scan configuration.
     */
    fun removeConfiguration(): Boolean {

        return cacheManager.remove(
            SCAN_CONFIGURATION_KEY
        )
    }

    /**
     * Refreshes scan configuration.
     */
    fun refreshConfiguration(
        configuration: ScanConfiguration,
        ttlMillis: Long = CONFIGURATION_TTL
    ) {

        cacheManager.refresh(
            key = SCAN_CONFIGURATION_KEY,
            value = configuration,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Recent Scan Results
    // -------------------------------------------------------------------------

    /**
     * Stores recently completed scan results.
     */
    fun putRecentResults(
        results: List<ScanResult>,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.put(
            key = RECENT_RESULTS_KEY,
            value = results,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves recent scan results.
     */
    fun getRecentResults():
        List<ScanResult>? {

        return cacheManager.get(
            RECENT_RESULTS_KEY
        )
    }

    /**
     * Checks whether recent results are cached.
     */
    fun containsRecentResults(): Boolean {

        return cacheManager.contains(
            RECENT_RESULTS_KEY
        )
    }

    /**
     * Removes recent scan results.
     */
    fun removeRecentResults(): Boolean {

        return cacheManager.remove(
            RECENT_RESULTS_KEY
        )
    }

    /**
     * Refreshes recent scan results.
     */
    fun refreshRecentResults(
        results: List<ScanResult>,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.refresh(
            key = RECENT_RESULTS_KEY,
            value = results,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads recent scan results using cache-aside.
     */
    suspend fun getRecentResultsOrLoad(
        ttlMillis: Long = HISTORY_TTL,
        loader: suspend () -> List<ScanResult>
    ): List<ScanResult> {

        return cacheManager.getOrPut(
            key = RECENT_RESULTS_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Scan Statistics
    // -------------------------------------------------------------------------

    /**
     * Stores scan statistics.
     *
     * The statistics object is generic so SentriX can use a
     * dedicated ScanStatistics model without coupling this
     * cache to a future implementation.
     */
    fun <T : Any> putStatistics(
        statistics: T,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.put(
            key = STATISTICS_KEY,
            value = statistics,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached scan statistics.
     */
    inline fun <reified T : Any> getStatistics():
        T? {

        return cacheManager.get(
            STATISTICS_KEY
        )
    }

    /**
     * Removes scan statistics.
     */
    fun removeStatistics(): Boolean {

        return cacheManager.remove(
            STATISTICS_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Scan Optimization
    // -------------------------------------------------------------------------

    /**
     * Stores scan optimization information.
     *
     * This could contain previously calculated optimization
     * information such as:
     *
     * - Recommended scan mode.
     * - Last scan duration.
     * - Resource usage.
     * - Scan scheduling hints.
     *
     * The actual optimization calculation belongs to the
     * Domain/application layer.
     */
    fun <T : Any> putOptimization(
        optimization: T,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.put(
            key = OPTIMIZATION_KEY,
            value = optimization,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached scan optimization information.
     */
    inline fun <reified T : Any> getOptimization():
        T? {

        return cacheManager.get(
            OPTIMIZATION_KEY
        )
    }

    /**
     * Removes cached optimization information.
     */
    fun removeOptimization(): Boolean {

        return cacheManager.remove(
            OPTIMIZATION_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Time-Range Scan Results
    // -------------------------------------------------------------------------

    /**
     * Generates a time-range cache key.
     */
    private fun rangeKey(
        startTime: Long,
        endTime: Long
    ): String {

        return RANGE_PREFIX +
            "$startTime:$endTime"
    }

    /**
     * Stores scan results for a specific period.
     */
    fun putRangeResults(
        startTime: Long,
        endTime: Long,
        results: List<ScanResult>,
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
            value = results,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves scan results for a time range.
     */
    fun getRangeResults(
        startTime: Long,
        endTime: Long
    ): List<ScanResult>? {

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
     * Removes time-range scan results.
     */
    fun removeRangeResults(
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
     * Loads range results using cache-aside behavior.
     */
    suspend fun getRangeResultsOrLoad(
        startTime: Long,
        endTime: Long,
        ttlMillis: Long = HISTORY_TTL,
        loader: suspend () -> List<ScanResult>
    ): List<ScanResult> {

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
    // Cache Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates the complete ScanCache namespace.
     *
     * This does not affect:
     *
     * - ThreatCache.
     * - VPNCache.
     * - PrivacyCache.
     * - UserCache.
     * - AnalyticsCache.
     */
    suspend fun invalidateAll() {

        cacheManager.invalidatePrefix(
            PREFIX
        )
    }

    /**
     * Invalidates all current/live scan information.
     */
    suspend fun invalidateCurrentScanData() {

        cacheManager.remove(
            LATEST_RESULT_KEY
        )

        cacheManager.remove(
            QUICK_SCAN_RESULT_KEY
        )

        cacheManager.remove(
            SMART_SCAN_RESULT_KEY
        )

        cacheManager.remove(
            ACTIVE_SCAN_KEY
        )

        cacheManager.remove(
            SCAN_STATE_KEY
        )
    }

    /**
     * Invalidates all scan result caches.
     */
    suspend fun invalidateResults() {

        cacheManager.remove(
            LATEST_RESULT_KEY
        )

        cacheManager.remove(
            QUICK_SCAN_RESULT_KEY
        )

        cacheManager.remove(
            SMART_SCAN_RESULT_KEY
        )

        cacheManager.remove(
            RECENT_RESULTS_KEY
        )

        cacheManager.invalidatePrefix(
            RESULT_PREFIX
        )

        cacheManager.invalidatePrefix(
            PACKAGE_PREFIX
        )

        cacheManager.invalidatePrefix(
            RANGE_PREFIX
        )
    }

    /**
     * Invalidates application-specific scan results.
     */
    suspend fun invalidatePackageResults() {

        cacheManager.invalidatePrefix(
            PACKAGE_PREFIX
        )
    }

    /**
     * Invalidates scan history caches.
     */
    suspend fun invalidateHistory() {

        cacheManager.remove(
            RECENT_RESULTS_KEY
        )

        cacheManager.remove(
            STATISTICS_KEY
        )

        cacheManager.invalidatePrefix(
            RANGE_PREFIX
        )
    }

    /**
     * Invalidates scan optimization data.
     */
    suspend fun invalidateOptimization() {

        cacheManager.remove(
            OPTIMIZATION_KEY
        )
    }

    /**
     * Invalidates scan configuration.
     */
    suspend fun invalidateConfiguration() {

        cacheManager.remove(
            SCAN_CONFIGURATION_KEY
        )
    }

    /**
     * Invalidates all cached data associated with one scan.
     */
    suspend fun invalidateScan(
        scanId: String
    ) {

        if (scanId.isBlank()) {
            return
        }

        cacheManager.remove(
            resultKey(scanId)
        )

        /**
         * Aggregate results can now be stale.
         */
        cacheManager.remove(
            LATEST_RESULT_KEY
        )

        cacheManager.remove(
            RECENT_RESULTS_KEY
        )

        cacheManager.remove(
            STATISTICS_KEY
        )
    }

    /**
     * Invalidates all cached data associated with an
     * application package.
     */
    suspend fun invalidatePackage(
        packageName: String
    ) {

        if (packageName.isBlank()) {
            return
        }

        cacheManager.remove(
            packageResultKey(packageName)
        )

        /**
         * Recent/history aggregates may now be stale.
         */
        cacheManager.remove(
            RECENT_RESULTS_KEY
        )

        cacheManager.remove(
            STATISTICS_KEY
        )
    }

    /**
     * Removes expired scan cache entries.
     */
    suspend fun removeExpiredEntries(): Int {

        return cacheManager.removeExpiredEntries()
    }

    /**
     * Returns cache statistics.
     */
    fun getStatistics():
        CacheStatistics {

        return cacheManager.getStatistics()
    }
}
