package com.sentrix.core.wrappers

import com.sentrix.core.enums.ScanStatus
import com.sentrix.core.enums.ScanType

/**
 * Wrapper representing the result of a security scan.
 */
data class ScanResultWrapper(
    val scanId: String,
    val scanType: ScanType,
    val status: ScanStatus,
    val threatsDetected: Int = 0,
    val filesScanned: Int = 0,
    val durationMillis: Long = 0L,
    val riskScore: Int = 0,
    val summary: String = "",
    val recommendations: List<String> = emptyList(),
    val detectedThreats: List<String> = emptyList(),
    val startedAt: Long = System.currentTimeMillis(),
    val completedAt: Long? = null
) {

    /**
     * Returns true if the scan completed successfully.
     */
    fun isCompleted(): Boolean =
        status == ScanStatus.COMPLETED

    /**
     * Returns true if threats were found.
     */
    fun hasThreats(): Boolean =
        threatsDetected > 0

    /**
     * Returns true if scan is currently running.
     */
    fun isRunning(): Boolean =
        status == ScanStatus.RUNNING

    /**
     * Returns scan duration in seconds.
     */
    fun getDurationSeconds(): Long =
        durationMillis / 1000

    /**
     * Returns risk level description.
     */
    fun getRiskLevel(): String {
        return when (riskScore) {
            in 0..20 -> "Low"
            in 21..50 -> "Moderate"
            in 51..80 -> "High"
            else -> "Critical"
        }
    }

    companion object {

        fun empty(
            scanType: ScanType
        ): ScanResultWrapper {
            return ScanResultWrapper(
                scanId = "",
                scanType = scanType,
                status = ScanStatus.IDLE
            )
        }
    }
}
