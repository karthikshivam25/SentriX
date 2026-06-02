package com.sentrix.core.enums

/**
 * Represents the current status of a scan process
 */
enum class ScanStatus(
    val displayName: String,
    val description: String
) {

    IDLE(
        displayName = "Idle",
        description = "Scanner is inactive"
    ),

    INITIALIZING(
        displayName = "Initializing",
        description = "Preparing scan engine and resources"
    ),

    STARTING(
        displayName = "Starting",
        description = "Scan process is starting"
    ),

    SCANNING(
        displayName = "Scanning",
        description = "Scanning is currently in progress"
    ),

    ANALYZING(
        displayName = "Analyzing",
        description = "Analyzing detected files and threats"
    ),

    DETECTING_THREATS(
        displayName = "Detecting Threats",
        description = "Searching for suspicious activities and malware"
    ),

    CLEANING(
        displayName = "Cleaning",
        description = "Removing or isolating detected threats"
    ),

    QUARANTINING(
        displayName = "Quarantining",
        description = "Moving infected items into quarantine"
    ),

    OPTIMIZING(
        displayName = "Optimizing",
        description = "Improving system performance and security"
    ),

    PAUSED(
        displayName = "Paused",
        description = "Scan process is temporarily paused"
    ),

    RESUMING(
        displayName = "Resuming",
        description = "Resuming paused scan operation"
    ),

    COMPLETED(
        displayName = "Completed",
        description = "Scan finished successfully"
    ),

    COMPLETED_WITH_WARNINGS(
        displayName = "Completed With Warnings",
        description = "Scan completed but issues were detected"
    ),

    CANCELLED(
        displayName = "Cancelled",
        description = "Scan was cancelled by the user"
    ),

    FAILED(
        displayName = "Failed",
        description = "Scan failed due to an error"
    ),

    TIMEOUT(
        displayName = "Timeout",
        description = "Scan exceeded the allowed execution time"
    ),

    ERROR(
        displayName = "Error",
        description = "Unexpected scan engine error occurred"
    );

    /**
     * Returns true if scan is actively running
     */
    fun isActive(): Boolean {
        return this == INITIALIZING ||
               this == STARTING ||
               this == SCANNING ||
               this == ANALYZING ||
               this == DETECTING_THREATS ||
               this == CLEANING ||
               this == QUARANTINING ||
               this == OPTIMIZING ||
               this == RESUMING
    }

    /**
     * Returns true if scan has finished
     */
    fun isFinished(): Boolean {
        return this == COMPLETED ||
               this == COMPLETED_WITH_WARNINGS ||
               this == CANCELLED ||
               this == FAILED ||
               this == TIMEOUT ||
               this == ERROR
    }

    /**
     * Returns true if scan encountered issues
     */
    fun hasErrors(): Boolean {
        return this == FAILED ||
               this == ERROR ||
               this == TIMEOUT
    }

    /**
     * Returns true if scan can be resumed
     */
    fun canResume(): Boolean {
        return this == PAUSED
    }
}
