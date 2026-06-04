package com.sentrix.core.exceptions

/**
 * ScanException
 *
 * Base exception for all scan-related failures
 * in the SentriX security platform.
 */
open class ScanException : Exception {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Generic scan failure.
 */
class ScanFailedException(
    message: String = "Scan operation failed."
) : ScanException(message)

/**
 * Scan cancelled by user.
 */
class ScanCancelledException(
    message: String = "Scan was cancelled."
) : ScanException(message)

/**
 * Scan timed out.
 */
class ScanTimeoutException(
    message: String = "Scan operation timed out."
) : ScanException(message)

/**
 * Unsupported scan type.
 */
class UnsupportedScanTypeException(
    message: String = "Unsupported scan type."
) : ScanException(message)

/**
 * Invalid scan configuration.
 */
class InvalidScanConfigurationException(
    message: String = "Invalid scan configuration."
) : ScanException(message)

/**
 * Scan engine initialization failure.
 */
class ScanInitializationException(
    message: String = "Failed to initialize scan engine.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Scan engine unavailable.
 */
class ScanEngineUnavailableException(
    message: String = "Scan engine unavailable."
) : ScanException(message)

/**
 * Malware scan failure.
 */
class MalwareScanException(
    message: String = "Malware scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * APK scan failure.
 */
class ApkScanException(
    message: String = "APK scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * File scan failure.
 */
class FileScanException(
    message: String = "File scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Directory scan failure.
 */
class DirectoryScanException(
    message: String = "Directory scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Network scan failure.
 */
class NetworkScanException(
    message: String = "Network scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * URL scan failure.
 */
class UrlScanException(
    message: String = "URL scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Permission scan failure.
 */
class PermissionScanException(
    message: String = "Permission scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Privacy scan failure.
 */
class PrivacyScanException(
    message: String = "Privacy scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Device health scan failure.
 */
class DeviceHealthScanException(
    message: String = "Device health scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Real-time protection scan failure.
 */
class RealtimeScanException(
    message: String = "Real-time scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Threat analysis failure.
 */
class ThreatAnalysisScanException(
    message: String = "Threat analysis scan failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Corrupted file encountered during scan.
 */
class CorruptedFileException(
    message: String = "Corrupted file detected."
) : ScanException(message)

/**
 * File access denied.
 */
class FileAccessDeniedException(
    message: String = "Unable to access file."
) : ScanException(message)

/**
 * Storage unavailable.
 */
class StorageUnavailableException(
    message: String = "Storage is unavailable."
) : ScanException(message)

/**
 * Scan permission denied.
 */
class ScanPermissionDeniedException(
    message: String = "Required permission denied for scan."
) : ScanException(message)

/**
 * Malware detected during scan.
 */
class ThreatDetectedException(
    message: String = "Threat detected during scan."
) : ScanException(message)

/**
 * Critical threat detected.
 */
class CriticalThreatDetectedException(
    message: String = "Critical threat detected."
) : ScanException(message)

/**
 * Scan result processing failure.
 */
class ScanResultProcessingException(
    message: String = "Failed to process scan results.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Scan database failure.
 */
class ScanDatabaseException(
    message: String = "Scan database operation failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * Signature database unavailable.
 */
class SignatureDatabaseException(
    message: String = "Signature database unavailable."
) : ScanException(message)

/**
 * Heuristic analysis failure.
 */
class HeuristicAnalysisException(
    message: String = "Heuristic analysis failed.",
    cause: Throwable? = null
) : ScanException(message, cause)

/**
 * AI scan analysis failure.
 */
class AIScanException(
    message: String = "AI scan analysis failed.",
    cause: Throwable? = null
) : ScanException(message, cause)
