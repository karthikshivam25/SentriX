package com.sentrix.data.repository.analytics

import com.sentrix.core.exceptions.NetworkException
import com.sentrix.core.exceptions.ServerException
import com.sentrix.core.exceptions.UnknownException
import com.sentrix.data.local.dao.SecurityReportDao
import com.sentrix.data.local.entities.SecurityReportEntity
import com.sentrix.data.remote.api.ReportApiService
import com.sentrix.data.remote.dto.SecurityReportDto
import com.sentrix.domain.models.SecurityReport
import com.sentrix.domain.repository.SecurityReportRepository
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - Security Report Repository Implementation
 *
 * Package:
 * com.sentrix.data.repository.analytics
 *
 * Responsibility:
 * ------------------------------------------------------------
 * Concrete Data-layer implementation of
 * SecurityReportRepository.
 *
 * This repository manages SentriX security reports generated
 * from security events, scan results, threat intelligence,
 * privacy activity and security metrics.
 *
 * Reports may contain:
 *
 * - Security score.
 * - Overall risk level.
 * - Scan statistics.
 * - Threat statistics.
 * - Malware detections.
 * - Phishing detections.
 * - Scam detections.
 * - Privacy events.
 * - Network threats.
 * - Blocked threats.
 * - Security recommendations.
 * - Report period.
 * - Report generation timestamp.
 * - Report status.
 *
 * Typical report types:
 *
 * - DAILY
 * - WEEKLY
 * - MONTHLY
 * - INCIDENT
 * - SECURITY_HEALTH
 * - THREAT_SUMMARY
 * - PRIVACY
 * - COMPLIANCE
 * - DEVICE_SECURITY
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This repository does NOT generate or interpret reports.
 *
 * Report generation belongs to:
 *
 * - SecurityReportingService
 * - SecurityReportService
 * - RiskScoringService
 * - AnalyticsService
 * - SecurityRecommendationService
 *
 * This repository is responsible only for DATA operations:
 *
 * - Save reports.
 * - Retrieve reports.
 * - Query report history.
 * - Filter reports.
 * - Update report status.
 * - Delete reports.
 * - Synchronize reports.
 * - Convert DTOs to Domain models.
 * - Convert Domain models to database entities.
 * - Convert database entities back to Domain models.
 * - Translate infrastructure exceptions.
 *
 * Clean Architecture:
 *
 * Domain
 *    │
 *    ▼
 * SecurityReportRepository
 *    │
 *    ▼
 * SecurityReportRepositoryImpl
 *    │
 *    ├──────────────► SecurityReportDao
 *    │                     │
 *    │                     ▼
 *    │              SecurityReportEntity
 *    │
 *    └──────────────► ReportApiService
 *                          │
 *                          ▼
 *                    SecurityReportDto
 */
@Singleton
class SecurityReportRepositoryImpl @Inject constructor(
    private val securityReportDao: SecurityReportDao,
    private val reportApiService: ReportApiService
) : SecurityReportRepository {

    /**
     * Retrieves the latest security report.
     *
     * Local storage is preferred so previously generated
     * security reports remain available offline.
     */
    override suspend fun getLatestReport():
        Result<SecurityReport?> {

        return try {

            val entity =
                securityReportDao.getLatestReport()

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves a security report by its unique ID.
     */
    override suspend fun getReportById(
        reportId: String
    ): Result<SecurityReport?> {

        return try {

            if (reportId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security report ID cannot be blank."
                    )
                )
            }

            val entity =
                securityReportDao.getById(reportId)

            Result.success(
                entity?.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves recent security reports.
     *
     * Useful for the Security Reports screen.
     */
    override suspend fun getRecentReports(
        limit: Int
    ): Result<List<SecurityReport>> {

        return try {

            if (limit <= 0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Report history limit must be greater than zero."
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
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves all locally stored security reports.
     */
    override suspend fun getAllReports():
        Result<List<SecurityReport>> {

        return try {

            val entities =
                securityReportDao.getAllReports()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports by report type.
     *
     * Examples:
     *
     * DAILY
     * WEEKLY
     * MONTHLY
     * INCIDENT
     * SECURITY_HEALTH
     * THREAT_SUMMARY
     * PRIVACY
     */
    override suspend fun getReportsByType(
        reportType: String
    ): Result<List<SecurityReport>> {

        return try {

            if (reportType.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Report type cannot be blank."
                    )
                )
            }

            val entities =
                securityReportDao.getReportsByType(
                    reportType
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports by report status.
     *
     * Examples:
     *
     * GENERATED
     * PROCESSING
     * FAILED
     * EXPIRED
     * ARCHIVED
     */
    override suspend fun getReportsByStatus(
        status: String
    ): Result<List<SecurityReport>> {

        return try {

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Report status cannot be blank."
                    )
                )
            }

            val entities =
                securityReportDao.getReportsByStatus(
                    status
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports within a specified time range.
     *
     * Timestamps are expected to be epoch milliseconds.
     */
    override suspend fun getReportsBetween(
        startTime: Long,
        endTime: Long
    ): Result<List<SecurityReport>> {

        return try {

            if (startTime > endTime) {
                return Result.failure(
                    IllegalArgumentException(
                        "Start time cannot be after end time."
                    )
                )
            }

            val entities =
                securityReportDao.getReportsBetween(
                    startTime = startTime,
                    endTime = endTime
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports whose security score is below the
     * supplied threshold.
     *
     * This is useful when displaying reports that indicate
     * deteriorating security posture.
     */
    override suspend fun getReportsBelowSecurityScore(
        maximumScore: Double
    ): Result<List<SecurityReport>> {

        return try {

            if (maximumScore !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security score must be between 0 and 100."
                    )
                )
            }

            val entities =
                securityReportDao.getReportsBelowSecurityScore(
                    maximumScore
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports with a risk score at or above the
     * specified threshold.
     */
    override suspend fun getReportsAboveRiskScore(
        minimumRiskScore: Double
    ): Result<List<SecurityReport>> {

        return try {

            if (minimumRiskScore !in 0.0..100.0) {
                return Result.failure(
                    IllegalArgumentException(
                        "Risk score must be between 0 and 100."
                    )
                )
            }

            val entities =
                securityReportDao.getReportsAboveRiskScore(
                    minimumRiskScore
                )

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports containing critical threats.
     */
    override suspend fun getCriticalThreatReports():
        Result<List<SecurityReport>> {

        return try {

            val entities =
                securityReportDao.getReportsWithCriticalThreats()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports containing malware detections.
     */
    override suspend fun getMalwareReports():
        Result<List<SecurityReport>> {

        return try {

            val entities =
                securityReportDao.getReportsWithMalware()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports containing phishing detections.
     */
    override suspend fun getPhishingReports():
        Result<List<SecurityReport>> {

        return try {

            val entities =
                securityReportDao.getReportsWithPhishing()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports containing privacy events.
     */
    override suspend fun getPrivacyReports():
        Result<List<SecurityReport>> {

        return try {

            val entities =
                securityReportDao.getReportsWithPrivacyEvents()

            Result.success(
                entities.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Saves one security report locally.
     *
     * Used after SecurityReportingService generates a report.
     */
    override suspend fun saveReport(
        report: SecurityReport
    ): Result<Unit> {

        return try {

            securityReportDao.insertOrUpdate(
                report.toEntity()
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Saves multiple reports in a single operation.
     *
     * Useful for backend synchronization.
     */
    override suspend fun saveReports(
        reports: List<SecurityReport>
    ): Result<Unit> {

        return try {

            if (reports.isEmpty()) {
                return Result.success(Unit)
            }

            securityReportDao.insertOrUpdateAll(
                reports.map {
                    it.toEntity()
                }
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Updates the status of an existing report.
     */
    override suspend fun updateReportStatus(
        reportId: String,
        status: String
    ): Result<Unit> {

        return try {

            if (reportId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security report ID cannot be blank."
                    )
                )
            }

            if (status.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Report status cannot be blank."
                    )
                )
            }

            securityReportDao.updateStatus(
                reportId = reportId,
                status = status
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Marks a report as archived.
     */
    override suspend fun archiveReport(
        reportId: String
    ): Result<Unit> {

        return try {

            if (reportId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security report ID cannot be blank."
                    )
                )
            }

            securityReportDao.updateStatus(
                reportId = reportId,
                status = REPORT_STATUS_ARCHIVED
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Refreshes the latest security report from the backend.
     */
    override suspend fun refreshLatestReport():
        Result<SecurityReport> {

        return try {

            val response =
                reportApiService.getLatestSecurityReport()

            cacheReport(response)

            Result.success(
                response.toDomain()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves remote security-report history and merges
     * it into the local database.
     */
    override suspend fun synchronizeReports():
        Result<Unit> {

        return try {

            val response =
                reportApiService.getSecurityReportHistory()

            if (response.isNotEmpty()) {

                securityReportDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Retrieves reports updated after the supplied timestamp.
     *
     * This enables incremental synchronization.
     */
    override suspend fun getReportsSince(
        timestamp: Long
    ): Result<List<SecurityReport>> {

        return try {

            val response =
                reportApiService.getSecurityReportsSince(
                    timestamp
                )

            if (response.isNotEmpty()) {

                securityReportDao.insertOrUpdateAll(
                    response.map {
                        it.toEntity()
                    }
                )
            }

            Result.success(
                response.map {
                    it.toDomain()
                }
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Deletes one local report.
     */
    override suspend fun deleteReport(
        reportId: String
    ): Result<Unit> {

        return try {

            if (reportId.isBlank()) {
                return Result.failure(
                    IllegalArgumentException(
                        "Security report ID cannot be blank."
                    )
                )
            }

            securityReportDao.deleteById(
                reportId
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Deletes reports older than a specified timestamp.
     *
     * This supports SentriX data-retention policies.
     */
    override suspend fun deleteOlderThan(
        timestamp: Long
    ): Result<Unit> {

        return try {

            securityReportDao.deleteOlderThan(
                timestamp
            )

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Clears all locally stored reports.
     *
     * This should normally be used only during an explicit
     * user-requested data reset/privacy operation.
     */
    override suspend fun clearReports():
        Result<Unit> {

        return try {

            securityReportDao.deleteAll()

            Result.success(Unit)

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Returns the number of locally stored reports.
     */
    override suspend fun getReportCount():
        Result<Int> {

        return try {

            Result.success(
                securityReportDao.getCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Returns the number of reports containing critical
     * security findings.
     */
    override suspend fun getCriticalReportCount():
        Result<Int> {

        return try {

            Result.success(
                securityReportDao.getCriticalReportCount()
            )

        } catch (exception: Exception) {

            Result.failure(
                mapSecurityReportException(exception)
            )
        }
    }

    /**
     * Converts remote SecurityReportDto into Domain model.
     *
     * DTO -> Domain
     */
    private fun SecurityReportDto.toDomain():
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
     * Converts remote DTO into Room entity.
     *
     * DTO -> Entity
     */
    private fun SecurityReportDto.toEntity():
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
     * Converts Domain SecurityReport into Room entity.
     *
     * Domain -> Entity
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
     * Converts Room entity into Domain SecurityReport.
     *
     * Entity -> Domain
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
     * Stores one remote security report locally.
     */
    private suspend fun cacheReport(
        report: SecurityReportDto
    ) {

        securityReportDao.insertOrUpdate(
            report.toEntity()
        )
    }

    /**
     * Maps infrastructure exceptions into SentriX
     * application-level exceptions.
     */
    private fun mapSecurityReportException(
        exception: Exception
    ): Exception {

        return when (exception) {

            /**
             * Network connectivity failure.
             */
            is IOException -> {
                NetworkException(
                    message = "Unable to communicate with the SentriX security-report service.",
                    cause = exception
                )
            }

            /**
             * Backend HTTP failure.
             */
            is HttpException -> {

                when (exception.code()) {

                    400 -> {
                        ServerException(
                            "The security-report request was invalid."
                        )
                    }

                    401 -> {
                        ServerException(
                            "The SentriX session is no longer authorized."
                        )
                    }

                    403 -> {
                        ServerException(
                            "You do not have permission to access security reports."
                        )
                    }

                    404 -> {
                        ServerException(
                            "The requested security report was not found."
                        )
                    }

                    409 -> {
                        ServerException(
                            "Security-report synchronization conflict occurred."
                        )
                    }

                    429 -> {
                        ServerException(
                            "Security-report request limit exceeded."
                        )
                    }

                    in 500..599 -> {
                        ServerException(
                            "SentriX security-report service is temporarily unavailable."
                        )
                    }

                    else -> {
                        ServerException(
                            "Security-report request failed with HTTP ${exception.code()}."
                        )
                    }
                }
            }

            /**
             * Preserve already translated exceptions.
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
                    message = "An unexpected security-report repository error occurred.",
                    cause = exception
                )
            }
        }
    }

    companion object {

        /**
         * Local report status used when a report has been
         * archived.
         */
        private const val REPORT_STATUS_ARCHIVED = "ARCHIVED"
    }
}
