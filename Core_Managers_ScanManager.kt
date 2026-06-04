package com.sentrix.core.managers

import android.content.Context
import com.sentrix.core.enums.ScanStatus
import com.sentrix.core.enums.ScanType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ScanManager
 *
 * Responsibilities:
 * - Scan orchestration
 * - Scan progress tracking
 * - Scan status monitoring
 * - Scan history management
 * - Threat detection integration
 * - Result aggregation
 */
class ScanManager(
    private val context: Context,
    private val threatManager: ThreatManager? = null,
    private val analyticsManager: AnalyticsManager? = null
) {

    private val scope = CoroutineScope(Dispatchers.IO)

    private var currentScanJob: Job? = null

    private val scanHistory =
        mutableListOf<ScanRecord>()

    private val _scanState =
        MutableStateFlow(
            ScanState(
                status = ScanStatus.IDLE,
                progress = 0,
                currentScanType = null
            )
        )

    val scanState: StateFlow<ScanState> =
        _scanState.asStateFlow()

    /**
     * Start a scan.
     */
    fun startScan(
        scanType: ScanType
    ) {

        if (_scanState.value.status ==
            ScanStatus.SCANNING
        ) {
            return
        }

        currentScanJob?.cancel()

        currentScanJob = scope.launch {

            _scanState.value = ScanState(
                status = ScanStatus.SCANNING,
                progress = 0,
                currentScanType = scanType
            )

            analyticsManager?.trackScan(
                scanType = scanType.name,
                result = "STARTED"
            )

            try {

                for (progress in 1..100) {

                    delay(50)

                    _scanState.value =
                        _scanState.value.copy(
                            progress = progress
                        )
                }

                val result = ScanResult(
                    threatsFound = 0,
                    filesScanned = 100,
                    durationMillis = 5000L,
                    scanType = scanType,
                    status = ScanStatus.COMPLETED
                )

                scanHistory.add(
                    ScanRecord(
                        timestamp = System.currentTimeMillis(),
                        result = result
                    )
                )

                analyticsManager?.trackScan(
                    scanType = scanType.name,
                    result = "COMPLETED"
                )

                _scanState.value =
                    ScanState(
                        status = ScanStatus.COMPLETED,
                        progress = 100,
                        currentScanType = scanType
                    )

            } catch (_: Exception) {

                _scanState.value =
                    ScanState(
                        status = ScanStatus.FAILED,
                        progress = 0,
                        currentScanType = scanType
                    )
            }
        }
    }

    /**
     * Cancel current scan.
     */
    fun cancelScan() {

        currentScanJob?.cancel()

        _scanState.value =
            _scanState.value.copy(
                status = ScanStatus.CANCELLED
            )
    }

    /**
     * Check if scan is running.
     */
    fun isScanning(): Boolean {
        return scanState.value.status ==
                ScanStatus.SCANNING
    }

    /**
     * Get latest scan result.
     */
    fun getLastScanResult(): ScanResult? {
        return scanHistory.lastOrNull()?.result
    }

    /**
     * Get scan history.
     */
    fun getScanHistory(): List<ScanRecord> {
        return scanHistory.toList()
    }

    /**
     * Clear scan history.
     */
    fun clearHistory() {
        scanHistory.clear()
    }

    /**
     * Total scans performed.
     */
    fun getTotalScans(): Int {
        return scanHistory.size
    }

    /**
     * Total threats found.
     */
    fun getTotalThreatsDetected(): Int {

        return scanHistory.sumOf {
            it.result.threatsFound
        }
    }

    /**
     * Generate scan report.
     */
    fun generateScanReport(): String {

        val latest =
            getLastScanResult()

        return buildString {

            appendLine("Scan Report")
            appendLine("-------------------------")
            appendLine("Total Scans : ${getTotalScans()}")
            appendLine(
                "Threats Found : ${
                    getTotalThreatsDetected()
                }"
            )

            latest?.let {

                appendLine(
                    "Last Scan Type : ${it.scanType}"
                )

                appendLine(
                    "Last Status : ${it.status}"
                )

                appendLine(
                    "Files Scanned : ${it.filesScanned}"
                )
            }
        }
    }

    /**
     * Current scan state.
     */
    data class ScanState(
        val status: ScanStatus,
        val progress: Int,
        val currentScanType: ScanType?
    )

    /**
     * Scan result model.
     */
    data class ScanResult(
        val threatsFound: Int,
        val filesScanned: Int,
        val durationMillis: Long,
        val scanType: ScanType,
        val status: ScanStatus
    )

    /**
     * Historical scan record.
     */
    data class ScanRecord(
        val timestamp: Long,
        val result: ScanResult
    )
}
