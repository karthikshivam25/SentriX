package com.sentrix.domain.services

import com.sentrix.domain.models.SecurityAlert
import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for generating security reports.
 *
 * This service creates dashboard summaries,
 * threat reports, audit reports, and executive reports
 * for the SentriX security platform.
 */
class SecurityReportingService {

    /**
     * Generates a threat report.
     */
    suspend fun generateThreatReport(
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        val criticalCount = indicators.count {
            it.severity.equals("CRITICAL", true)
        }

        val highCount = indicators.count {
            it.severity.equals("HIGH", true)
        }

        val mediumCount = indicators.count {
            it.severity.equals("MEDIUM", true)
        }

        val lowCount = indicators.count {
            it.severity.equals("LOW", true)
        }

        buildString {
            appendLine("SentriX Threat Report")
            appendLine("====================")
            appendLine("Total Threats: ${indicators.size}")
            appendLine("Critical Threats: $criticalCount")
            appendLine("High Threats: $highCount")
            appendLine("Medium Threats: $mediumCount")
            appendLine("Low Threats: $lowCount")
        }
    }

    /**
     * Generates security metrics report.
     */
    suspend fun generateMetricsReport(
        metrics: SecurityMetrics
    ): String = withContext(Dispatchers.Default) {

        buildString {
            appendLine("SentriX Security Metrics Report")
            appendLine("==============================")
            appendLine("Total Scans: ${metrics.totalScans}")
            appendLine("Threats Detected: ${metrics.threatsDetected}")
            appendLine("Compromised Devices: ${metrics.compromisedDevices}")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Last Updated: ${metrics.lastUpdated}")
        }
    }

    /**
     * Generates security alert report.
     */
    suspend fun generateAlertReport(
        alerts: List<SecurityAlert>
    ): String = withContext(Dispatchers.Default) {

        val unreadAlerts = alerts.count {
            !it.isRead
        }

        buildString {
            appendLine("SentriX Alert Report")
            appendLine("===================")
            appendLine("Total Alerts: ${alerts.size}")
            appendLine("Unread Alerts: $unreadAlerts")
        }
    }

    /**
     * Generates executive security report.
     */
    suspend fun generateExecutiveReport(
        metrics: SecurityMetrics,
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        buildString {
            appendLine("SentriX Executive Security Report")
            appendLine("=================================")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Threat Count: ${indicators.size}")
            appendLine("Compromised Devices: ${metrics.compromisedDevices}")
            appendLine(
                if (metrics.riskScore >= 60)
                    "Status: Attention Required"
                else
                    "Status: Secure"
            )
        }
    }

    /**
     * Generates audit report.
     */
    suspend fun generateAuditReport(
        metrics: SecurityMetrics,
        indicators: List<ThreatIndicator>,
        alerts: List<SecurityAlert>
    ): String = withContext(Dispatchers.Default) {

        buildString {

            appendLine("SentriX Security Audit Report")
            appendLine("================================")
            appendLine("Total Scans: ${metrics.totalScans}")
            appendLine("Threats Detected: ${metrics.threatsDetected}")
            appendLine("Total Alerts: ${alerts.size}")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Threat Indicators: ${indicators.size}")
            appendLine("Compromised Devices: ${metrics.compromisedDevices}")
        }
    }

    /**
     * Generates dashboard summary.
     */
    suspend fun generateDashboardSummary(
        metrics: SecurityMetrics,
        indicators: List<ThreatIndicator>
    ): String = withContext(Dispatchers.Default) {

        buildString {
            appendLine("Dashboard Summary")
            appendLine("-----------------")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Threats: ${indicators.size}")
            appendLine("Compromised Devices: ${metrics.compromisedDevices}")
        }
    }

    /**
     * Returns only unread alerts.
     */
    suspend fun getUnreadAlerts(
        alerts: List<SecurityAlert>
    ): List<SecurityAlert> = withContext(Dispatchers.Default) {

        alerts.filter {
            !it.isRead
        }
    }

    /**
     * Returns critical threats.
     */
    suspend fun getCriticalThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", true)
        }
    }

    /**
     * Returns high priority threats.
     */
    suspend fun getHighPriorityThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", true)
        }
    }

    /**
     * Generates a complete security report.
     */
    suspend fun generateCompleteReport(
        metrics: SecurityMetrics,
        indicators: List<ThreatIndicator>,
        alerts: List<SecurityAlert>
    ): String = withContext(Dispatchers.Default) {

        val unreadAlerts = getUnreadAlerts(alerts).size

        buildString {

            appendLine("SentriX Complete Security Report")
            appendLine("================================")
            appendLine("Total Scans: ${metrics.totalScans}")
            appendLine("Threats Detected: ${metrics.threatsDetected}")
            appendLine("Threat Indicators: ${indicators.size}")
            appendLine("Total Alerts: ${alerts.size}")
            appendLine("Unread Alerts: $unreadAlerts")
            appendLine("Compromised Devices: ${metrics.compromisedDevices}")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine()

            appendLine(
                if (metrics.riskScore >= 60)
                    "Overall Status: HIGH RISK"
                else
                    "Overall Status: SECURE"
            )
        }
    }

    /**
     * Determines whether reporting data exists.
     */
    suspend fun hasReportableData(
        metrics: SecurityMetrics,
        indicators: List<ThreatIndicator>,
        alerts: List<SecurityAlert>
    ): Boolean = withContext(Dispatchers.Default) {

        metrics.totalScans > 0 ||
        indicators.isNotEmpty() ||
        alerts.isNotEmpty()
    }
}
