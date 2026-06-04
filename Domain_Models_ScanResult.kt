package com.sentrix.domain.models

/**
 * ScanResult
 *
 * Represents the outcome of a security scan
 * performed by the SentriX platform.
 *
 * Used by:
 * - Malware Scanner
 * - File Scanner
 * - APK Analyzer
 * - Threat Detection Engine
 * - Security Dashboard
 * - AI Analysis Engine
 */
data class ScanResult(

    /**
     * Unique scan identifier.
     */
    val scanId: String,

    /**
     * Scan type.
     */
    val scanType: ScanType,

    /**
     * Scan status.
     */
    val status: ScanStatus,

    /**
     * Scan start timestamp.
     */
    val startedAt: Long,

    /**
     * Scan completion timestamp.
     */
    val completedAt: Long,

    /**
     * Scan duration in milliseconds.
     */
    val duration: Long,

    /**
     * Overall security score.
     */
    val securityScore: Int,

    /**
     * Number of items scanned.
     */
    val scannedItems: Int,

    /**
     * Number of threats found.
     */
    val threatsFound: Int,

    /**
     * Number of malware detections.
     */
    val malwareFound: Int,

    /**
     * Number of warnings.
     */
    val warningsFound: Int,

    /**
     * Scan summary.
     */
    val summary: String,

    /**
     * Detected threats.
     */
    val threats: List<Threat> = emptyList(),

    /**
     * Detected malware.
     */
    val malware: List<Malware> = emptyList(),

    /**
     * Recommendations.
     */
    val recommendations: List<String> = emptyList(),

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Types of security scans.
 */
enum class ScanType {
    QUICK_SCAN,
    FULL_SCAN,
    FILE_SCAN,
    APK_SCAN,
    MALWARE_SCAN,
    NETWORK_SCAN,
    DEVICE_INTEGRITY_SCAN,
    CLOUD_SCAN,
    CUSTOM_SCAN
}

/**
 * Scan execution status.
 */
enum class ScanStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
}
