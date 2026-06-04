package com.sentrix.core.managers

import android.content.Context
import com.sentrix.core.extensions.calculateSecurityScore
import com.sentrix.core.extensions.securityStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SecurityManager
 *
 * Central Security Orchestrator for SentriX
 *
 * Responsibilities:
 * - Security Score Management
 * - Device Security State
 * - Threat Counters
 * - Security Monitoring Status
 * - Global Security Events
 * - Security Dashboard Data Provider
 */
class SecurityManager private constructor(
    private val context: Context
) {

    companion object {

        @Volatile
        private var INSTANCE: SecurityManager? = null

        fun getInstance(
            context: Context
        ): SecurityManager {

            return INSTANCE ?: synchronized(this) {

                INSTANCE ?: SecurityManager(
                    context.applicationContext
                ).also {
                    INSTANCE = it
                }
            }
        }
    }

    /* ---------------------------------------------------------------------
     * Security State
     * --------------------------------------------------------------------- */

    private val monitoringEnabled =
        AtomicBoolean(false)

    private val _securityScore =
        MutableStateFlow(DEFAULT_SECURITY_SCORE)

    val securityScore: StateFlow<Int> =
        _securityScore.asStateFlow()

    private val _securityStatus =
        MutableStateFlow("Protected")

    val securityStatus: StateFlow<String> =
        _securityStatus.asStateFlow()

    private val _activeThreatCount =
        MutableStateFlow(0)

    val activeThreatCount: StateFlow<Int> =
        _activeThreatCount.asStateFlow()

    private val _criticalThreatCount =
        MutableStateFlow(0)

    val criticalThreatCount: StateFlow<Int> =
        _criticalThreatCount.asStateFlow()

    private val _lastScanTimestamp =
        MutableStateFlow(0L)

    val lastScanTimestamp: StateFlow<Long> =
        _lastScanTimestamp.asStateFlow()

    private val _securityEvents =
        MutableStateFlow<List<SecurityEvent>>(emptyList())

    val securityEvents: StateFlow<List<SecurityEvent>> =
        _securityEvents.asStateFlow()

    /* ---------------------------------------------------------------------
     * Monitoring Control
     * --------------------------------------------------------------------- */

    fun startMonitoring() {
        monitoringEnabled.set(true)
    }

    fun stopMonitoring() {
        monitoringEnabled.set(false)
    }

    fun isMonitoringEnabled(): Boolean {
        return monitoringEnabled.get()
    }

    /* ---------------------------------------------------------------------
     * Security Score Management
     * --------------------------------------------------------------------- */

    fun updateSecurityScore(
        permissionsRisk: Int,
        malwareRisk: Int,
        networkRisk: Int,
        rootRisk: Int
    ) {

        val score = calculateSecurityScore(
            permissionsRisk = permissionsRisk,
            malwareRisk = malwareRisk,
            networkRisk = networkRisk,
            rootRisk = rootRisk
        )

        _securityScore.value = score
        _securityStatus.value = score.securityStatus()
    }

    fun setSecurityScore(
        score: Int
    ) {

        _securityScore.value =
            score.coerceIn(0, 100)

        _securityStatus.value =
            score.securityStatus()
    }

    /* ---------------------------------------------------------------------
     * Threat Management
     * --------------------------------------------------------------------- */

    fun reportThreat(
        threatName: String,
        severity: ThreatSeverity,
        description: String
    ) {

        when (severity) {

            ThreatSeverity.CRITICAL -> {
                _criticalThreatCount.value += 1
            }

            else -> Unit
        }

        _activeThreatCount.value += 1

        addEvent(
            SecurityEvent(
                title = threatName,
                description = description,
                severity = severity
            )
        )
    }

    fun resolveThreat() {

        if (_activeThreatCount.value > 0) {
            _activeThreatCount.value--
        }
    }

    fun clearThreats() {

        _activeThreatCount.value = 0
        _criticalThreatCount.value = 0
    }

    /* ---------------------------------------------------------------------
     * Scan Tracking
     * --------------------------------------------------------------------- */

    fun updateLastScanTime(
        timestamp: Long = System.currentTimeMillis()
    ) {
        _lastScanTimestamp.value = timestamp
    }

    /* ---------------------------------------------------------------------
     * Security Events
     * --------------------------------------------------------------------- */

    fun addEvent(
        event: SecurityEvent
    ) {

        _securityEvents.value =
            listOf(event) + _securityEvents.value
    }

    fun clearEvents() {
        _securityEvents.value = emptyList()
    }

    fun getLatestEvent(): SecurityEvent? {
        return _securityEvents.value.firstOrNull()
    }

    /* ---------------------------------------------------------------------
     * Dashboard Helpers
     * --------------------------------------------------------------------- */

    fun getSecuritySummary(): SecuritySummary {

        return SecuritySummary(
            score = _securityScore.value,
            status = _securityStatus.value,
            activeThreats = _activeThreatCount.value,
            criticalThreats = _criticalThreatCount.value,
            lastScanTimestamp = _lastScanTimestamp.value
        )
    }

    fun hasThreats(): Boolean {
        return _activeThreatCount.value > 0
    }

    fun hasCriticalThreats(): Boolean {
        return _criticalThreatCount.value > 0
    }

    /* ---------------------------------------------------------------------
     * Reset
     * --------------------------------------------------------------------- */

    fun reset() {

        _securityScore.value =
            DEFAULT_SECURITY_SCORE

        _securityStatus.value =
            DEFAULT_SECURITY_STATUS

        _activeThreatCount.value = 0

        _criticalThreatCount.value = 0

        _lastScanTimestamp.value = 0L

        _securityEvents.value = emptyList()

        monitoringEnabled.set(false)
    }

    /* ---------------------------------------------------------------------
     * Constants
     * --------------------------------------------------------------------- */

    private companion object {

        const val DEFAULT_SECURITY_SCORE = 100

        const val DEFAULT_SECURITY_STATUS =
            "Protected"
    }
}

/* =========================================================================
 * Models
 * ========================================================================= */

data class SecuritySummary(
    val score: Int,
    val status: String,
    val activeThreats: Int,
    val criticalThreats: Int,
    val lastScanTimestamp: Long
)

data class SecurityEvent(
    val title: String,
    val description: String,
    val severity: ThreatSeverity,
    val timestamp: Long = System.currentTimeMillis()
)

enum class ThreatSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
