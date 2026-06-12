package com.sentrix.data.local.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * ScanHistoryEntity
 *
 * Represents a security scan
 * execution record within the
 * SentriX platform.
 *
 * Responsibilities:
 * - Store scan history
 * - Track scan performance
 * - Monitor threat detections
 * - Support analytics
 * - Generate security reports
 */
@Entity(
    tableName = "scan_history"
)
data class ScanHistoryEntity(

    /**
     * Unique scan identifier.
     */
    @PrimaryKey
    val scanId: String,

    /**
     * Scan name.
     */
    val scanName: String,

    /**
     * Scan type.
     *
     * QUICK_SCAN
     * DEEP_SCAN
     * SMART_SCAN
     * CUSTOM_SCAN
     */
    val scanType: String,

    /**
     * Scan status.
     *
     * PENDING
     * RUNNING
     * COMPLETED
     * FAILED
     * CANCELLED
     */
    val scanStatus: String,

    /**
     * Scan target path.
     */
    val targetPath: String?,

    /**
     * Number of files scanned.
     */
    val filesScanned: Int,

    /**
     * Number of threats detected.
     */
    val threatsDetected: Int,

    /**
     * Number of critical threats.
     */
    val criticalThreats: Int,

    /**
     * Number of high threats.
     */
    val highThreats: Int,

    /**
     * Number of medium threats.
     */
    val mediumThreats: Int,

    /**
     * Number of low threats.
     */
    val lowThreats: Int,

    /**
     * Number of files quarantined.
     */
    val quarantinedFiles: Int,

    /**
     * Number of files cleaned.
     */
    val cleanedFiles: Int,

    /**
     * Scan duration in milliseconds.
     */
    val scanDuration: Long,

    /**
     * CPU usage percentage.
     */
    val cpuUsage: Double,

    /**
     * Memory usage in MB.
     */
    val memoryUsage: Long,

    /**
     * Scan start timestamp.
     */
    val scanStartedAt: Long,

    /**
     * Scan completion timestamp.
     */
    val scanCompletedAt: Long?,

    /**
     * Scan result summary.
     */
    val summary: String,

    /**
     * Indicates whether
     * the scan completed successfully.
     */
    val isSuccessful: Boolean,

    /**
     * Record creation timestamp.
     */
    val createdAt: Long,

    /**
     * Last update timestamp.
     */
    val updatedAt: Long?
)
