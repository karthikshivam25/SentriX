package com.sentrix.data.cache

import com.sentrix.domain.models.SecurityReport
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Security Report Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Feature-specific cache for SentriX security reports.
 *
 * SecurityReportCache provides a strongly typed abstraction
 * over CacheManager for caching security-report information.
 *
 * Cached information includes:
 *
 * - Latest security report.
 * - Individual security reports.
 * - Security report lists.
 * - Recent reports.
 * - Report history.
 * - Application-specific reports.
 * - Time-range reports.
 * - Report summaries.
 * - Report generation status.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This class does NOT:
 *
 * - Generate security reports.
 * - Analyze threats.
 * - Calculate security scores.
 * - Determine risk levels.
 * - Make security decisions.
 * - Export PDF files.
 * - Upload reports.
 *
 * Report generation and analysis belong to the appropriate
 * Domain/Application services.
 *
 * This class only manages cached report DATA.
 *
 * Clean Architecture:
 *
 * SecurityReportRepositoryImpl
 *            │
 *            ▼
 *    SecurityReportCache
 *            │
 *            ▼
 *       CacheManager
 *            │
 *            ▼
 *      In-Memory Cache
 */
@Singleton
class SecurityReportCache @Inject constructor(
    private val cacheManager: CacheManager
) {

    // -------------------------------------------------------------------------
    // Cache Namespace
    // -------------------------------------------------------------------------

    private companion object {

        /**
         * Dedicated namespace for security reports.
         */
        const val PREFIX =
            "security_report:"

        const val LATEST_REPORT_KEY =
            "${PREFIX}latest"

        const val REPORT_LIST_KEY =
            "${PREFIX}list"

        const val RECENT_REPORTS_KEY =
            "${PREFIX}recent"

        const val REPORT_HISTORY_KEY =
            "${PREFIX}history"

        const val GENERATION_STATUS_KEY =
            "${PREFIX}generation_status"

        const val SUMMARY_KEY =
            "${PREFIX}summary"

        const val REPORT_PREFIX =
            "${PREFIX}report:"

        const val PACKAGE_PREFIX =
            "${PREFIX}package:"

        const val RANGE_PREFIX =
            "${PREFIX}range:"

        /**
         * Reports can remain cached slightly longer than
         * live security events.
         */
        const val REPORT_TTL =
            CacheManager.MEDIUM_TTL_MILLIS

        /**
         * Report lists may change when a new report is generated.
         */
        const val LIST_TTL =
            CacheManager.SHORT_TTL_MILLIS

        /**
         * Historical reports are relatively stable.
         */
        const val HISTORY_TTL =
            CacheManager.LONG_TTL_MILLIS
    }

    // -------------------------------------------------------------------------
    // Latest Security Report
    // -------------------------------------------------------------------------

    /**
     * Stores the latest generated security report.
     */
    fun putLatestReport(
        report: SecurityReport,
        ttlMillis: Long = REPORT_TTL
    ) {

        cacheManager.put(
            key = LATEST_REPORT_KEY,
            value = report,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the latest security report.
     */
    fun getLatestReport():
        SecurityReport? {

        return cacheManager.get(
            LATEST_REPORT_KEY
        )
    }

    /**
     * Checks whether a latest report is cached.
     */
    fun containsLatestReport(): Boolean {

        return cacheManager.contains(
            LATEST_REPORT_KEY
        )
    }

    /**
     * Removes the latest security report.
     */
    fun removeLatestReport(): Boolean {

        return cacheManager.remove(
            LATEST_REPORT_KEY
        )
    }

    /**
     * Refreshes the latest security report.
     */
    fun refreshLatestReport(
        report: SecurityReport,
        ttlMillis: Long = REPORT_TTL
    ) {

        cacheManager.refresh(
            key = LATEST_REPORT_KEY,
            value = report,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads the latest report using cache-aside behavior.
     */
    suspend fun getLatestReportOrLoad(
        ttlMillis: Long = REPORT_TTL,
        loader: suspend () -> SecurityReport
    ): SecurityReport {

        return cacheManager.getOrPut(
            key = LATEST_REPORT_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Report by ID
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for an individual report.
     */
    private fun reportKey(
        reportId: String
    ): String {

        return REPORT_PREFIX +
            reportId.trim()
    }

    /**
     * Stores an individual security report.
     */
    fun putReport(
        report: SecurityReport,
        ttlMillis: Long = REPORT_TTL
    ) {

        if (report.reportId.isBlank()) {
            return
        }

        cacheManager.put(
            key = reportKey(
                report.reportId
            ),
            value = report,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves an individual report by ID.
     */
    fun getReport(
        reportId: String
    ): SecurityReport? {

        if (reportId.isBlank()) {
            return null
        }

        return cacheManager.get(
            reportKey(
                reportId
            )
        )
    }

    /**
     * Checks whether a report is cached.
     */
    fun containsReport(
        reportId: String
    ): Boolean {

        if (reportId.isBlank()) {
            return false
        }

        return cacheManager.contains(
            reportKey(
                reportId
            )
        )
    }

    /**
     * Removes an individual report.
     */
    fun removeReport(
        reportId: String
    ): Boolean {

        if (reportId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            reportKey(
                reportId
            )
        )
    }

    /**
     * Refreshes an individual report.
     */
    fun refreshReport(
        report: SecurityReport,
        ttlMillis: Long = REPORT_TTL
    ) {

        if (report.reportId.isBlank()) {
            return
        }

        cacheManager.refresh(
            key = reportKey(
                report.reportId
            ),
            value = report,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads a report using cache-aside behavior.
     */
    suspend fun getReportOrLoad(
        reportId: String,
        ttlMillis: Long = REPORT_TTL,
        loader: suspend () -> SecurityReport
    ): SecurityReport {

        require(reportId.isNotBlank()) {
            "Report ID cannot be blank."
        }

        return cacheManager.getOrPut(
            key = reportKey(
                reportId
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Report List
    // -------------------------------------------------------------------------

    /**
     * Stores a list of security reports.
     *
     * Individual reports are also populated into the cache.
     */
    fun putReportList(
        reports: List<SecurityReport>,
        ttlMillis: Long = LIST_TTL
    ) {

        cacheManager.put(
            key = REPORT_LIST_KEY,
            value = reports,
            ttlMillis = ttlMillis
        )

        reports.forEach { report ->

            putReport(
                report = report,
                ttlMillis = ttlMillis
            )
        }
    }

    /**
     * Retrieves the cached report list.
     */
    fun getReportList():
        List<SecurityReport>? {

        return cacheManager.get(
            REPORT_LIST_KEY
        )
    }

    /**
     * Checks whether the report list exists.
     */
    fun containsReportList(): Boolean {

        return cacheManager.contains(
            REPORT_LIST_KEY
        )
    }

    /**
     * Removes the report list.
     */
    fun removeReportList(): Boolean {

        return cacheManager.remove(
            REPORT_LIST_KEY
        )
    }

    /**
     * Refreshes the report list.
     */
    fun refreshReportList(
        reports: List<SecurityReport>,
        ttlMillis: Long = LIST_TTL
    ) {

        cacheManager.refresh(
            key = REPORT_LIST_KEY,
            value = reports,
            ttlMillis = ttlMillis
        )

        reports.forEach { report ->

            putReport(
                report = report,
                ttlMillis = ttlMillis
            )
        }
    }

    /**
     * Loads the report list using cache-aside behavior.
     */
    suspend fun getReportListOrLoad(
        ttlMillis: Long = LIST_TTL,
        loader: suspend () -> List<SecurityReport>
    ): List<SecurityReport> {

        return cacheManager.getOrPut(
            key = REPORT_LIST_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Recent Reports
    // -------------------------------------------------------------------------

    /**
     * Stores recently generated reports.
     */
    fun putRecentReports(
        reports: List<SecurityReport>,
        ttlMillis: Long = LIST_TTL
    ) {

        cacheManager.put(
            key = RECENT_REPORTS_KEY,
            value = reports,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves recent reports.
     */
    fun getRecentReports():
        List<SecurityReport>? {

        return cacheManager.get(
            RECENT_REPORTS_KEY
        )
    }

    /**
     * Checks whether recent reports are cached.
     */
    fun containsRecentReports(): Boolean {

        return cacheManager.contains(
            RECENT_REPORTS_KEY
        )
    }

    /**
     * Removes recent reports.
     */
    fun removeRecentReports(): Boolean {

        return cacheManager.remove(
            RECENT_REPORTS_KEY
        )
    }

    /**
     * Refreshes recent reports.
     */
    fun refreshRecentReports(
        reports: List<SecurityReport>,
        ttlMillis: Long = LIST_TTL
    ) {

        cacheManager.refresh(
            key = RECENT_REPORTS_KEY,
            value = reports,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads recent reports using cache-aside behavior.
     */
    suspend fun getRecentReportsOrLoad(
        ttlMillis: Long = LIST_TTL,
        loader: suspend () -> List<SecurityReport>
    ): List<SecurityReport> {

        return cacheManager.getOrPut(
            key = RECENT_REPORTS_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Report History
    // -------------------------------------------------------------------------

    /**
     * Stores historical reports.
     */
    fun putReportHistory(
        reports: List<SecurityReport>,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.put(
            key = REPORT_HISTORY_KEY,
            value = reports,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached report history.
     */
    fun getReportHistory():
        List<SecurityReport>? {

        return cacheManager.get(
            REPORT_HISTORY_KEY
        )
    }

    /**
     * Checks whether report history is cached.
     */
    fun containsReportHistory(): Boolean {

        return cacheManager.contains(
            REPORT_HISTORY_KEY
        )
    }

    /**
     * Removes report history.
     */
    fun removeReportHistory(): Boolean {

        return cacheManager.remove(
            REPORT_HISTORY_KEY
        )
    }

    /**
     * Refreshes report history.
     */
    fun refreshReportHistory(
        reports: List<SecurityReport>,
        ttlMillis: Long = HISTORY_TTL
    ) {

        cacheManager.refresh(
            key = REPORT_HISTORY_KEY,
            value = reports,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads report history using cache-aside behavior.
     */
    suspend fun getReportHistoryOrLoad(
        ttlMillis: Long = HISTORY_TTL,
        loader: suspend () -> List<SecurityReport>
    ): List<SecurityReport> {

        return cacheManager.getOrPut(
            key = REPORT_HISTORY_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Application-Specific Reports
    // -------------------------------------------------------------------------

    /**
     * Generates an application-specific report cache key.
     */
    private fun packageReportKey(
        packageName: String
    ): String {

        return PACKAGE_PREFIX +
            packageName.trim().lowercase()
    }

    /**
     * Stores the latest security report for an application.
     */
    fun putPackageReport(
        packageName: String,
        report: SecurityReport,
        ttlMillis: Long = REPORT_TTL
    ) {

        if (packageName.isBlank()) {
            return
        }

        cacheManager.put(
            key = packageReportKey(
                packageName
            ),
            value = report,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the latest security report for an application.
     */
    fun getPackageReport(
        packageName: String
    ): SecurityReport? {

        if (packageName.isBlank()) {
            return null
        }

        return cacheManager.get(
            packageReportKey(
                packageName
            )
        )
    }

    /**
     * Checks whether an application report is cached.
     */
    fun containsPackageReport(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.contains(
            packageReportKey(
                packageName
            )
        )
    }

    /**
     * Removes an application-specific report.
     */
    fun removePackageReport(
        packageName: String
    ): Boolean {

        if (packageName.isBlank()) {
            return false
        }

        return cacheManager.remove(
            packageReportKey(
                packageName
            )
        )
    }

    /**
     * Loads an application report using cache-aside behavior.
     */
    suspend fun getPackageReportOrLoad(
        packageName: String,
        ttlMillis: Long = REPORT_TTL,
        loader: suspend () -> SecurityReport
    ): SecurityReport {

        require(packageName.isNotBlank()) {
            "Package name cannot be blank."
        }

        return cacheManager.getOrPut(
            key = packageReportKey(
                packageName
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // Time-Range Reports
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for a time-range report query.
     */
    private fun rangeKey(
        startTime: Long,
        endTime: Long
    ): String {

        return RANGE_PREFIX +
            "$startTime:$endTime"
    }

    /**
     * Stores reports for a specific time range.
     */
    fun putRangeReports(
        startTime: Long,
        endTime: Long,
        reports: List<SecurityReport>,
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
            value = reports,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves reports for a time range.
     */
    fun getRangeReports(
        startTime: Long,
        endTime: Long
    ): List<SecurityReport>? {

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
     * Removes a time-range report cache.
     */
    fun removeRangeReports(
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
     * Loads reports for a time range using cache-aside behavior.
     */
    suspend fun getRangeReportsOrLoad(
        startTime: Long,
        endTime: Long,
        ttlMillis: Long = HISTORY_TTL,
        loader: suspend () -> List<SecurityReport>
    ): List<SecurityReport> {

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
    // Report Summary
    // -------------------------------------------------------------------------

    /**
     * Stores a precomputed report summary.
     *
     * The summary is produced outside this cache. This class
     * only stores the result.
     */
    fun <T : Any> putSummary(
        summary: T,
        ttlMillis: Long = LIST_TTL
    ) {

        cacheManager.put(
            key = SUMMARY_KEY,
            value = summary,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves a cached report summary.
     */
    inline fun <reified T : Any> getSummary():
        T? {

        return cacheManager.get(
            SUMMARY_KEY
        )
    }

    /**
     * Checks whether a report summary exists.
     */
    fun containsSummary(): Boolean {

        return cacheManager.contains(
            SUMMARY_KEY
        )
    }

    /**
     * Removes the cached summary.
     */
    fun removeSummary(): Boolean {

        return cacheManager.remove(
            SUMMARY_KEY
        )
    }

    // -------------------------------------------------------------------------
    // Report Generation Status
    // -------------------------------------------------------------------------

    /**
     * Stores report-generation status.
     *
     * Examples:
     *
     * - IDLE
     * - GENERATING
     * - COMPLETED
     * - FAILED
     * - CANCELLED
     */
    fun putGenerationStatus(
        status: String,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        if (status.isBlank()) {
            return
        }

        cacheManager.put(
            key = GENERATION_STATUS_KEY,
            value = status,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves report-generation status.
     */
    fun getGenerationStatus():
        String? {

        return cacheManager.get(
            GENERATION_STATUS_KEY
        )
    }

    /**
     * Removes generation status.
     */
    fun removeGenerationStatus(): Boolean {

        return cacheManager.remove(
            GENERATION_STATUS_KEY
        )
    }

    /**
     * Updates generation status.
     */
    fun refreshGenerationStatus(
        status: String,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        if (status.isBlank()) {
            return
        }

        cacheManager.refresh(
            key = GENERATION_STATUS_KEY,
            value = status,
            ttlMillis = ttlMillis
        )
    }

    // -------------------------------------------------------------------------
    // Cache Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates the complete security-report cache.
     */
    suspend fun invalidateAll() {

        cacheManager.invalidatePrefix(
            PREFIX
        )
    }

    /**
     * Invalidates current report information.
     *
     * Used after generating a new report.
     */
    suspend fun invalidateCurrentReports() {

        cacheManager.remove(
            LATEST_REPORT_KEY
        )

        cacheManager.remove(
            REPORT_LIST_KEY
        )

        cacheManager.remove(
            RECENT_REPORTS_KEY
        )

        cacheManager.remove(
            SUMMARY_KEY
        )
    }

    /**
     * Invalidates individual report caches.
     */
    suspend fun invalidateReports() {

        cacheManager.invalidatePrefix(
            REPORT_PREFIX
        )
    }

    /**
     * Invalidates historical report data.
     */
    suspend fun invalidateHistory() {

        cacheManager.remove(
            REPORT_HISTORY_KEY
        )

        cacheManager.invalidatePrefix(
            RANGE_PREFIX
        )
    }

    /**
     * Invalidates application-specific reports.
     */
    suspend fun invalidatePackageReports() {

        cacheManager.invalidatePrefix(
            PACKAGE_PREFIX
        )
    }

    /**
     * Invalidates everything related to one report.
     */
    suspend fun invalidateReport(
        reportId: String
    ) {

        if (reportId.isBlank()) {
            return
        }

        cacheManager.remove(
            reportKey(
                reportId
            )
        )

        /**
         * Aggregated report collections may now be stale.
         */
        cacheManager.remove(
            LATEST_REPORT_KEY
        )

        cacheManager.remove(
            REPORT_LIST_KEY
        )

        cacheManager.remove(
            RECENT_REPORTS_KEY
        )

        cacheManager.remove(
            REPORT_HISTORY_KEY
        )

        cacheManager.remove(
            SUMMARY_KEY
        )
    }

    /**
     * Invalidates all reports belonging to one application.
     */
    suspend fun invalidatePackage(
        packageName: String
    ) {

        if (packageName.isBlank()) {
            return
        }

        cacheManager.remove(
            packageReportKey(
                packageName
            )
        )

        /**
         * Aggregate report collections may now be stale.
         */
        cacheManager.remove(
            REPORT_LIST_KEY
        )

        cacheManager.remove(
            RECENT_REPORTS_KEY
        )

        cacheManager.remove(
            REPORT_HISTORY_KEY
        )

        cacheManager.remove(
            SUMMARY_KEY
        )
    }

    /**
     * Invalidates report-generation state.
     */
    suspend fun invalidateGenerationState() {

        cacheManager.remove(
            GENERATION_STATUS_KEY
        )
    }

    /**
     * Removes expired security-report cache entries.
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
