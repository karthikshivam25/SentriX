package com.sentrix.data.repository.analytics

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.AnalyticsDao
import com.sentrix.data.local.dao.ScanHistoryDao
import com.sentrix.data.local.dao.SecurityReportDao
import com.sentrix.data.local.dao.SecurityMetricsDao
import com.sentrix.data.local.dao.ThreatDao
import com.sentrix.data.local.entities.AnalyticsEntity
import com.sentrix.data.local.entities.ScanHistoryEntity
import com.sentrix.data.local.entities.SecurityMetricsEntity
import com.sentrix.data.local.entities.SecurityReportEntity
import com.sentrix.data.local.entities.ThreatEntity
import com.sentrix.data.remote.api.AnalyticsApiService
import com.sentrix.data.remote.dto.DashboardDto
import com.sentrix.domain.models.Dashboard
import com.sentrix.domain.models.ScanResult
import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.SecurityReport
import com.sentrix.domain.models.Threat
import com.sentrix.domain.repository.DashboardRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Dashboard Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.analytics
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Central Data-layer repository for the SentriX security
 * dashboard.
 *
 * The dashboard needs information from multiple security
 * subsystems:
 *
 * - Security Metrics.
 * - Analytics.
 * - Scan History.
 * - Threats.
 * - Security Reports.
 *
 * This repository provides a single Data-layer entry point
 * for obtaining that dashboard information.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT:
 *
 * - Calculate risk.
 * - Determine whether a threat is malicious.
 * - Generate recommendations.
 * - Decide the security score.
 * - Decide threat severity.
 * - Apply security policies.
 *
 * Those responsibilities belong to the Domain layer.
 *
 * This repository is responsible for:
 *
 * - Reading dashboard data from local storage.
 * - Retrieving dashboard snapshots from the backend.
 * - Synchronizing dashboard information.
 * - Persisting dashboard snapshots.
 * - Combining Data-layer sources.
 * - DTO -> Domain conversion.
 * - Entity -> Domain conversion.
 * - Domain -> Entity conversion.
 * - Exception translation.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * DashboardRepository
 *    │
 *    ▼
 * DashboardRepositoryImpl
 *    │
 *    ├──► SecurityMetricsDao
 *    ├──► AnalyticsDao
 *    ├──► ScanHistoryDao
 *    ├──► ThreatDao
 *    ├──► SecurityReportDao
 *    │
 *    └──► AnalyticsApiService
 */
@Singleton
class DashboardRepositoryImpl @Inject constructor(
    private val securityMetricsDao: SecurityMetricsDao,
    private val analyticsDao: AnalyticsDao,
    private val scanHistoryDao: ScanHistoryDao,
    private val threatDao: ThreatDao,
    private val securityReportDao: SecurityReportDao,
    private val analyticsApiService: AnalyticsApiService
) : DashboardRepository {

    /**
     * Retrieves the latest dashboard state.
     *
     * Local data is preferred because the dashboard should
     * remain available even when the device is offline.
     */
    override suspend fun getDashboard():
        Result<Dashboard> {

        return try {

            val dashboard =
                buildDashboardFromLocalData()

            Result.success(
                dashboard
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves a dashboard snapshot from the backend.
     *
     * The remote result is cached locally so it can be
     * displayed later when the device is offline.
     */
    override suspend fun refreshDashboard():
        Result<Dashboard> {

        return try {

            val response =
                analyticsApiService.getDashboard()

            /**
             * Cache all dashboard components returned by the
             * backend.
             */
            cacheDashboard(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves dashboard information for a specific period.
     *
     * This is useful for historical dashboard views.
     */
    override suspend fun getDashboardBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<Dashboard>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val responses =
                analyticsApiService.getDashboardHistory(
                    startTime = startTime,
                    endTime = endTime
                )

            /**
             * Cache the returned snapshots.
             */
            responses.forEach {
                cacheDashboard(it)
            }

            Result.success(
                responses.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves recent dashboard snapshots.
     */
    override suspend fun getDashboardHistory(
        limit: Int
    ): Result<List<Dashboard>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Dashboard history limit must be greater than zero."
                    )
                )
            }

            val responses =
                analyticsApiService.getDashboardHistory(
                    limit = limit
                )

            responses.forEach {
                cacheDashboard(it)
            }

            Result.success(
                responses.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            /**
             * If the network is unavailable, fall back to the
             * locally aggregated dashboard history.
             */
            if (exception is IOException) {

                return try {

                    val dashboards =
                        buildLocalDashboardHistory(limit)

                    Result.success(
                        dashboards
                    )

                } catch (localException: Exception) {

                    Result.failure(
                        mapDashboardException(localException)
                    )
                }
            }

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves the latest security score for the dashboard.
     */
    override suspend fun getDashboardSecurityScore():
        Result<Double> {

        return try {

            val metrics =
                securityMetricsDao.getLatestMetrics()

            Result.success(
                metrics?.securityScore ?: 0.0
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves the latest risk score.
     */
    override suspend fun getDashboardRiskScore():
        Result<Double> {

        return try {

            val metrics =
                securityMetricsDao.getLatestMetrics()

            Result.success(
                metrics?.averageRiskScore ?: 0.0
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves the number of threats currently visible to
     * the dashboard.
     */
    override suspend fun getDashboardThreatCount():
        Result<Int> {

        return try {

            val count =
                threatDao.getActiveThreatCount()

            Result.success(
                count
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves the number of critical threats.
     */
    override suspend fun getCriticalThreatCount():
        Result<Int> {

        return try {

            val count =
                threatDao.getCriticalThreatCount()

            Result.success(
                count
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves recent threats for dashboard cards.
     */
    override suspend fun getRecentThreats(
        limit: Int
    ): Result<List<Threat>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Threat limit must be greater than zero."
                    )
                )
            }

            val entities =
                threatDao.getRecentThreats(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves recent scans displayed on the dashboard.
     */
    override suspend fun getRecentScans(
        limit: Int
    ): Result<List<ScanResult>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Scan limit must be greater than zero."
                    )
                )
            }

            val entities =
                scanHistoryDao.getRecentScans(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves the latest security report.
     */
    override suspend fun getLatestSecurityReport():
        Result<SecurityReport?> {

        return try {

            val entity =
                securityReportDao.getLatestReport()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves recent security reports for dashboard display.
     */
    override suspend fun getRecentSecurityReports(
        limit: Int
    ): Result<List<SecurityReport>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security report limit must be greater than zero."
                    )
                )
            }

            val entities =
                securityReportDao.getRecentReports(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves the latest security metrics.
     */
    override suspend fun getLatestSecurityMetrics():
        Result<SecurityMetrics?> {

        return try {

            val entity =
                securityMetricsDao.getLatestMetrics()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Retrieves recent analytics records used by dashboard
     * charts.
     */
    override suspend fun getRecentAnalytics(
        limit: Int
    ): Result<List<SecurityMetrics>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Analytics limit must be greater than zero."
                    )
                )
            }

            val entities =
                analyticsDao.getRecentAnalytics(limit)

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Saves a dashboard snapshot locally.
     *
     * This allows dashboard state to be retained for offline
     * access and historical analysis.
     */
    override suspend fun saveDashboard(
        dashboard: Dashboard
    ): Result<Unit> {

        return try {

            cacheDashboard(
                dashboard
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Synchronizes dashboard information with the backend.
     */
    override suspend fun synchronizeDashboard():
        Result<Unit> {

        return try {

            val response =
                analyticsApiService.getDashboard()

            cacheDashboard(response)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Deletes dashboard snapshots older than a timestamp.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            analyticsDao.deleteOlderThan(timestamp)

            securityMetricsDao.deleteOlderThan(timestamp)

            scanHistoryDao.deleteScansOlderThan(timestamp)

            securityReportDao.deleteOlderThan(timestamp)

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Clears dashboard-related cached data.
     *
     * This should normally be triggered only by an explicit
     * data-reset/privacy operation.
     */
    override suspend fun clearDashboardCache():
        Result<Unit> {

        return try {

            analyticsDao.deleteAll()

            securityMetricsDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapDashboardException(exception)
            )
        }
    }

    /**
     * Builds the dashboard from locally stored sources.
     *
     * This is the primary offline dashboard strategy.
     */
    private suspend fun buildDashboardFromLocalData():
        Dashboard {

        val metrics =
            securityMetricsDao.getLatestMetrics()

        val analytics =
            analyticsDao.getLatestAnalytics()

        val recentScans =
            scanHistoryDao.getRecentScans(
                DASHBOARD_SCAN_LIMIT
            )

        val recentThreats =
            threatDao.getRecentThreats(
                DASHBOARD_THREAT_LIMIT
            )

        val latestReport =
            securityReportDao.getLatestReport()

        return Dashboard(
            timestamp =
                metrics?.timestamp
                    ?: System.currentTimeMillis(),

            securityScore =
                metrics?.securityScore
                    ?: 0.0,

            riskScore =
                metrics?.averageRiskScore
                    ?: 0.0,

            totalScans =
                metrics?.totalScans
                    ?: analytics?.totalScans
                    ?: 0,

            threatsDetected =
                metrics?.threatsDetected
                    ?: analytics?.threatsDetected
                    ?: 0,

            criticalThreats =
                metrics?.criticalThreats
                    ?: analytics?.criticalThreats
                    ?: 0,

            highThreats =
                metrics?.highThreats
                    ?: analytics?.highThreats
                    ?: 0,

            mediumThreats =
                metrics?.mediumThreats
                    ?: analytics?.mediumThreats
                    ?: 0,

            lowThreats =
                metrics?.lowThreats
                    ?: analytics?.lowThreats
                    ?: 0,

            malwareDetections =
                metrics?.malwareDetections
                    ?: analytics?.malwareDetections
                    ?: 0,

            phishingDetections =
                metrics?.phishingDetections
                    ?: analytics?.phishingDetections
                    ?: 0,

            scamDetections =
                metrics?.scamDetections
                    ?: analytics?.scamDetections
                    ?: 0,

            blockedThreats =
                metrics?.blockedThreats
                    ?: analytics?.blockedThreats
                    ?: 0,

            networkThreats =
                metrics?.networkThreats
                    ?: analytics?.networkThreats
                    ?: 0,

            privacyEvents =
                metrics?.privacyEvents
                    ?: analytics?.privacyEvents
                    ?: 0,

            recentScans =
                recentScans.map {
                    it.toDomain()
                },

            recentThreats =
                recentThreats.map {
                    it.toDomain()
                },

            latestReport =
                latestReport?.toDomain()
        )
    }

    /**
     * Builds multiple dashboard snapshots from local data.
     *
     * Each analytics/security-metrics snapshot is converted
     * into a lightweight Dashboard object.
     */
    private suspend fun buildLocalDashboardHistory(
        limit: Int
    ): List<Dashboard> {

        val metrics =
            securityMetricsDao.getRecentMetrics(limit)

        return metrics.map { metric ->

            Dashboard(
                timestamp =
                    metric.timestamp,

                securityScore =
                    metric.securityScore,

                riskScore =
                    metric.averageRiskScore,

                totalScans =
                    metric.totalScans,

                threatsDetected =
                    metric.threatsDetected,

                criticalThreats =
                    metric.criticalThreats,

                highThreats =
                    metric.highThreats,

                mediumThreats =
                    metric.mediumThreats,

                lowThreats =
                    metric.lowThreats,

                malwareDetections =
                    metric.malwareDetections,

                phishingDetections =
                    metric.phishingDetections,

                scamDetections =
                    metric.scamDetections,

                blockedThreats =
                    metric.blockedThreats,

                networkThreats =
                    metric.networkThreats,

                privacyEvents =
                    metric.privacyEvents,

                recentScans =
                    emptyList(),

                recentThreats =
                    emptyList(),

                latestReport =
                    null
            )
        }
    }

    /**
     * Caches a remote dashboard response.
     *
     * The dashboard response is decomposed into its individual
     * persistence models.
     */
    private suspend fun cacheDashboard(
        dashboard: DashboardDto
    ) {

        dashboard.securityMetrics?.let {
            securityMetricsDao.insertOrUpdate(
                it.toEntity()
            )
        }

        dashboard.analytics?.let {
            analyticsDao.insertOrUpdate(
                it.toEntity()
            )
        }

        dashboard.recentScans
            .takeIf {
                it.isNotEmpty()
            }
            ?.let { scans ->

                scanHistoryDao.insertOrUpdateAll(
                    scans.map {
                        it.toEntity()
                    }
                )
            }

        dashboard.recentThreats
            .takeIf {
                it.isNotEmpty()
            }
            ?.let { threats ->

                threatDao.insertOrUpdateAll(
                    threats.map {
                        it.toEntity()
                    }
                )
            }

        dashboard.latestReport?.let {
            securityReportDao.insertOrUpdate(
                it.toEntity()
            )
        }
    }

    /**
     * Converts DashboardDto into Domain Dashboard.
     */
    private fun DashboardDto.toDomain():
        Dashboard {

        return Dashboard(
            timestamp = timestamp,
            securityScore = securityScore,
            riskScore = riskScore,
            totalScans = totalScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            blockedThreats = blockedThreats,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,

            recentScans =
                recentScans.map {
                    it.toDomain()
                },

            recentThreats =
                recentThreats.map {
                    it.toDomain()
                },

            latestReport =
                latestReport?.toDomain()
        )
    }

    /**
     * Saves a Domain Dashboard into the local repositories.
     */
    private suspend fun cacheDashboard(
        dashboard: Dashboard
    ) {

        dashboard.recentScans
            .map {
                it.toEntity()
            }
            .takeIf {
                it.isNotEmpty()
            }
            ?.let {
                scanHistoryDao.insertOrUpdateAll(it)
            }

        dashboard.recentThreats
            .map {
                it.toEntity()
            }
            .takeIf {
                it.isNotEmpty()
            }
            ?.let {
                threatDao.insertOrUpdateAll(it)
            }

        dashboard.latestReport?.let {
            securityReportDao.insertOrUpdate(
                it.toEntity()
            )
        }
    }

    /**
     * Converts AnalyticsEntity into Domain SecurityMetrics.
     */
    private fun AnalyticsEntity.toDomain():
        SecurityMetrics {

        return SecurityMetrics(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Converts SecurityMetricsEntity into Domain model.
     */
    private fun SecurityMetricsEntity.toDomain():
        SecurityMetrics {

        return SecurityMetrics(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Converts ScanHistoryEntity into Domain ScanResult.
     */
    private fun ScanHistoryEntity.toDomain():
        ScanResult {

        return ScanResult(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            threatsFound = threatsFound,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            riskScore = riskScore
        )
    }

    /**
     * Converts ThreatEntity into Domain Threat.
     *
     * The exact fields should remain aligned with the
     * previously defined SentriX ThreatEntity and Threat model.
     */
    private fun ThreatEntity.toDomain():
        Threat {

        return Threat(
            threatId = threatId,
            name = name,
            type = type,
            severity = severity,
            description = description,
            detectedAt = detectedAt,
            status = status
        )
    }

    /**
     * Converts SecurityReportEntity into Domain SecurityReport.
     */
    private fun SecurityReportEntity.toDomain():
        SecurityReport {

        return SecurityReport(
            reportId = reportId,
            reportType = reportType,
            status = status,
            generatedAt = generatedAt,
            periodStart = periodStart,
            periodEnd = periodEnd,
            securityScore = securityScore,
            riskScore = riskScore,
            totalScans = totalScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            privacyEvents = privacyEvents,
            networkThreats = networkThreats,
            blockedThreats = blockedThreats,
            recommendations = recommendations
        )
    }

    /**
     * Converts Domain ScanResult into local entity.
     */
    private fun ScanResult.toEntity():
        ScanHistoryEntity {

        return ScanHistoryEntity(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            threatsFound = threatsFound,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            riskScore = riskScore
        )
    }

    /**
     * Converts Domain Threat into local entity.
     *
     * Keep this mapping synchronized with ThreatEntity.
     */
    private fun Threat.toEntity():
        ThreatEntity {

        return ThreatEntity(
            threatId = threatId,
            name = name,
            type = type,
            severity = severity,
            description = description,
            detectedAt = detectedAt,
            status = status
        )
    }

    /**
     * Converts Domain SecurityReport into local entity.
     */
    private fun SecurityReport.toEntity():
        SecurityReportEntity {

        return SecurityReportEntity(
            reportId = reportId,
            reportType = reportType,
            status = status,
            generatedAt = generatedAt,
            periodStart = periodStart,
            periodEnd = periodEnd,
            securityScore = securityScore,
            riskScore = riskScore,
            totalScans = totalScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            privacyEvents = privacyEvents,
            networkThreats = networkThreats,
            blockedThreats = blockedThreats,
            recommendations = recommendations
        )
    }

    /**
     * Converts SecurityMetricsDto into local entity.
     */
    private fun com.sentrix.data.remote.dto.SecurityMetricsDto.toEntity():
        SecurityMetricsEntity {

        return SecurityMetricsEntity(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Converts AnalyticsDto into local entity.
     */
    private fun com.sentrix.data.remote.dto.AnalyticsDto.toEntity():
        AnalyticsEntity {

        return AnalyticsEntity(
            id = id,
            timestamp = timestamp,
            totalScans = totalScans,
            completedScans = completedScans,
            failedScans = failedScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            networkThreats = networkThreats,
            privacyEvents = privacyEvents,
            blockedThreats = blockedThreats,
            averageRiskScore = averageRiskScore,
            securityScore = securityScore,
            totalScanDurationMs = totalScanDurationMs
        )
    }

    /**
     * Converts remote ScanResult-like DTO into local entity.
     *
     * Used by DashboardDto.recentScans.
     */
    private fun com.sentrix.data.remote.dto.ScanResultDto.toEntity():
        ScanHistoryEntity {

        return ScanHistoryEntity(
            scanId = scanId,
            scanType = scanType,
            status = status,
            startedAt = startedAt,
            completedAt = completedAt,
            scannedItems = scannedItems,
            threatsFound = threatsFound,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            riskScore = riskScore
        )
    }

    /**
     * Converts remote ThreatDto into local entity.
     *
     * Used by DashboardDto.recentThreats.
     */
    private fun com.sentrix.data.remote.dto.ThreatDto.toEntity():
        ThreatEntity {

        return ThreatEntity(
            threatId = threatId,
            name = name,
            type = type,
            severity = severity,
            description = description,
            detectedAt = detectedAt,
            status = status
        )
    }

    /**
     * Converts remote SecurityReportDto into local entity.
     */
    private fun com.sentrix.data.remote.dto.SecurityReportDto.toEntity():
        SecurityReportEntity {

        return SecurityReportEntity(
            reportId = reportId,
            reportType = reportType,
            status = status,
            generatedAt = generatedAt,
            periodStart = periodStart,
            periodEnd = periodEnd,
            securityScore = securityScore,
            riskScore = riskScore,
            totalScans = totalScans,
            threatsDetected = threatsDetected,
            criticalThreats = criticalThreats,
            highThreats = highThreats,
            mediumThreats = mediumThreats,
            lowThreats = lowThreats,
            malwareDetections = malwareDetections,
            phishingDetections = phishingDetections,
            scamDetections = scamDetections,
            privacyEvents = privacyEvents,
            networkThreats = networkThreats,
            blockedThreats = blockedThreats,
            recommendations = recommendations
        )
    }

    /**
     * Converts infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapDashboardException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Connectivity-related failures.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX dashboard service.",
                    cause = exception
                )
            }

            /**
             * Backend HTTP failures.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The dashboard request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access the SentriX dashboard."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested dashboard data was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Dashboard synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Dashboard request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX dashboard service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Dashboard request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve previously translated exceptions.
             */
            is NetworkException,
            is ServerException -> {
                exception
            }

            /**
             * Unexpected database or infrastructure failure.
             */
            else -> {
                UnknownException(
                    message = "An unexpected dashboard repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * Number of scan records shown in the dashboard's
         * recent-scans section.
         */
        private const val DASHBOARD_SCAN_LIMIT = 5

        /**
         * Number of threat records shown in the dashboard's
         * recent-threats section.
         */
        private const val DASHBOARD_THREAT_LIMIT = 5
    }
}
