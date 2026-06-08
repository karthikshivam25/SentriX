package com.sentrix.domain.repositories

import com.sentrix.domain.models.ScanConfiguration
import com.sentrix.domain.models.ScanResult
import com.sentrix.domain.models.ScanType

/**
 * ScanRepository
 *
 * Repository responsible for
 * managing security scan
 * operations within the
 * SentriX cybersecurity platform.
 *
 * Used by:
 * - QuickScanUseCase
 * - DeepScanUseCase
 * - SmartScanUseCase
 * - MalwareDetectionEngine
 * - SecurityDashboard
 *
 * Responsibilities:
 * - Start security scans
 * - Store scan results
 * - Retrieve scan history
 * - Manage scan configurations
 * - Provide scan analytics
 */
interface ScanRepository {

    /**
     * Starts a security scan.
     *
     * @param scanType Type of scan.
     * @param configuration Scan configuration.
     *
     * @return Scan result.
     */
    suspend fun startScan(
        scanType: ScanType,
        configuration: ScanConfiguration
    ): ScanResult

    /**
     * Retrieves scan result
     * by identifier.
     *
     * @param scanId Scan ID.
     *
     * @return Scan result.
     */
    suspend fun getScanResult(
        scanId: String
    ): ScanResult?

    /**
     * Retrieves all scan results.
     *
     * @return Scan result list.
     */
    suspend fun getScanHistory():
        List<ScanResult>

    /**
     * Saves scan result.
     *
     * @param result Scan result.
     */
    suspend fun saveScanResult(
        result: ScanResult
    )

    /**
     * Deletes scan result.
     *
     * @param scanId Scan ID.
     */
    suspend fun deleteScanResult(
        scanId: String
    )

    /**
     * Retrieves the latest scan.
     *
     * @return Latest scan result.
     */
    suspend fun getLatestScan():
        ScanResult?

    /**
     * Retrieves scans by type.
     *
     * @param scanType Scan type.
     *
     * @return Scan result list.
     */
    suspend fun getScansByType(
        scanType: ScanType
    ): List<ScanResult>

    /**
     * Retrieves total scan count.
     *
     * @return Number of scans.
     */
    suspend fun getScanCount():
        Int
}

/**
 * ScanResult
 *
 * Represents the outcome
 * of a security scan.
 */
data class ScanResult(

    /**
     * Scan identifier.
     */
    val scanId: String,

    /**
     * Scan type.
     */
    val scanType:
        ScanType,

    /**
     * Scan start time.
     */
    val startedAt: Long,

    /**
     * Scan completion time.
     */
    val completedAt: Long,

    /**
     * Number of files scanned.
     */
    val scannedFiles: Int,

    /**
     * Threats detected.
     */
    val threatsDetected: Int,

    /**
     * Scan status.
     */
    val scanStatus:
        ScanStatus,

    /**
     * Scan summary.
     */
    val summary: String
)

/**
 * ScanConfiguration
 *
 * Represents scan settings.
 */
data class ScanConfiguration(

    /**
     * Scan archives.
     */
    val scanArchives: Boolean,

    /**
     * Scan applications.
     */
    val scanApplications: Boolean,

    /**
     * Scan downloads folder.
     */
    val scanDownloads: Boolean,

    /**
     * Scan external storage.
     */
    val scanExternalStorage: Boolean
)

/**
 * Scan types.
 */
enum class ScanType {

    /**
     * Quick scan.
     */
    QUICK,

    /**
     * Deep scan.
     */
    DEEP,

    /**
     * Smart scan.
     */
    SMART,

    /**
     * Custom scan.
     */
    CUSTOM
}

/**
 * Scan status.
 */
enum class ScanStatus {

    /**
     * Scan running.
     */
    IN_PROGRESS,

    /**
     * Scan completed.
     */
    COMPLETED,

    /**
     * Scan failed.
     */
    FAILED,

    /**
     * Scan cancelled.
     */
    CANCELLED
}
