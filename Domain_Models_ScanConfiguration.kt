package com.sentrix.domain.models

/**
 * ScanConfiguration
 *
 * Represents the configuration settings
 * used to execute security scans within
 * the SentriX platform.
 *
 * Used by:
 * - ScanManager
 * - Malware Scanner
 * - File Scanner
 * - APK Analyzer
 * - Threat Detection Engine
 * - Scheduled Scan Service
 */
data class ScanConfiguration(

    /**
     * Unique configuration identifier.
     */
    val configurationId: String,

    /**
     * Scan profile name.
     */
    val profileName: String,

    /**
     * Scan type.
     */
    val scanType: ScanType,

    /**
     * Whether malware detection
     * is enabled.
     */
    val malwareDetectionEnabled: Boolean = true,

    /**
     * Whether file scanning
     * is enabled.
     */
    val fileScanningEnabled: Boolean = true,

    /**
     * Whether APK scanning
     * is enabled.
     */
    val apkScanningEnabled: Boolean = true,

    /**
     * Whether network analysis
     * is enabled.
     */
    val networkAnalysisEnabled: Boolean = true,

    /**
     * Whether device integrity
     * checks are enabled.
     */
    val deviceIntegrityEnabled: Boolean = true,

    /**
     * Whether AI threat analysis
     * is enabled.
     */
    val aiAnalysisEnabled: Boolean = true,

    /**
     * Maximum scan duration
     * in milliseconds.
     */
    val maxScanDuration: Long,

    /**
     * Maximum file size allowed
     * for scanning (bytes).
     */
    val maxFileSize: Long,

    /**
     * Directories included
     * in the scan.
     */
    val includedPaths: List<String> = emptyList(),

    /**
     * Directories excluded
     * from the scan.
     */
    val excludedPaths: List<String> = emptyList(),

    /**
     * Threat severity threshold.
     */
    val severityThreshold: ThreatSeverity = ThreatSeverity.LOW,

    /**
     * Whether cloud-assisted
     * scanning is enabled.
     */
    val cloudScanEnabled: Boolean = false,

    /**
     * Whether automatic threat
     * remediation is enabled.
     */
    val autoRemediationEnabled: Boolean = false,

    /**
     * Additional configuration
     * metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)
