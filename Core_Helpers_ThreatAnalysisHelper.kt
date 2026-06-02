package com.sentrix.core.helpers

import android.content.Context
import android.content.pm.ApplicationInfo
import com.sentrix.core.enums.MalwareType
import com.sentrix.core.enums.SecurityStatus
import com.sentrix.core.enums.ThreatSource

object ThreatAnalysisHelper {

    /**
     * Analyze application threat level
     */
    fun analyzeApplicationThreat(
        context: Context,
        packageName: String
    ): ThreatReport {

        val threatScore =
            MalwareDetectionHelper.calculateThreatScore(
                context,
                packageName
            )

        val malwareType =
            MalwareDetectionHelper.detectMalwareType(
                context,
                packageName
            )

        val securityStatus =
            determineSecurityStatus(threatScore)

        val threatSources =
            detectThreatSources(
                context,
                packageName
            )

        val suspiciousPermissions =
            MalwareDetectionHelper.getSuspiciousPermissions(
                context,
                packageName
            )

        return ThreatReport(
            packageName = packageName,
            threatScore = threatScore,
            malwareType = malwareType,
            securityStatus = securityStatus,
            threatSources = threatSources,
            suspiciousPermissions = suspiciousPermissions,
            recommendation = generateRecommendation(threatScore)
        )
    }

    /**
     * Analyze all installed applications
     */
    fun analyzeInstalledApplications(
        context: Context
    ): List<ThreatReport> {

        val applications =
            context.packageManager.getInstalledApplications(0)

        return applications.map {

            analyzeApplicationThreat(
                context,
                it.packageName
            )
        }
    }

    /**
     * Get only dangerous applications
     */
    fun getDangerousApplications(
        context: Context
    ): List<ThreatReport> {

        return analyzeInstalledApplications(context).filter {

            it.securityStatus == SecurityStatus.DANGEROUS ||
            it.securityStatus == SecurityStatus.CRITICAL
        }
    }

    /**
     * Determine security status from score
     */
    private fun determineSecurityStatus(
        threatScore: Int
    ): SecurityStatus {

        return when {

            threatScore >= 80 -> SecurityStatus.CRITICAL

            threatScore >= 60 -> SecurityStatus.DANGEROUS

            threatScore >= 40 -> SecurityStatus.WARNING

            threatScore >= 20 -> SecurityStatus.SAFE

            else -> SecurityStatus.SECURE
        }
    }

    /**
     * Detect threat sources
     */
    private fun detectThreatSources(
        context: Context,
        packageName: String
    ): List<ThreatSource> {

        val sources = mutableListOf<ThreatSource>()

        if (
            MalwareDetectionHelper.hasSuspiciousPermissions(
                context,
                packageName
            )
        ) {
            sources.add(ThreatSource.PERMISSIONS)
        }

        if (
            MalwareDetectionHelper.containsSuspiciousKeywords(
                packageName
            )
        ) {
            sources.add(ThreatSource.PACKAGE_NAME)
        }

        if (
            MalwareDetectionHelper.isUnknownInstaller(
                context,
                packageName
            )
        ) {
            sources.add(ThreatSource.UNKNOWN_SOURCE)
        }

        if (
            MalwareDetectionHelper.isDebuggableApp(
                context,
                packageName
            )
        ) {
            sources.add(ThreatSource.DEBUGGABLE_APP)
        }

        if (
            MalwareDetectionHelper.hasNativeExecutable(
                context,
                packageName
            )
        ) {
            sources.add(ThreatSource.NATIVE_CODE)
        }

        return sources
    }

    /**
     * Generate recommendation text
     */
    private fun generateRecommendation(
        threatScore: Int
    ): String {

        return when {

            threatScore >= 80 -> {
                "Immediate removal recommended. High-risk threat detected."
            }

            threatScore >= 60 -> {
                "App appears dangerous. Uninstall advised."
            }

            threatScore >= 40 -> {
                "Potential suspicious behavior detected. Review permissions."
            }

            threatScore >= 20 -> {
                "Low-level risk detected. Monitor application activity."
            }

            else -> {
                "Application appears secure."
            }
        }
    }

    /**
     * Calculate overall device risk score
     */
    fun calculateDeviceRiskScore(
        context: Context
    ): Int {

        val reports = analyzeInstalledApplications(context)

        if (reports.isEmpty()) return 0

        val totalScore = reports.sumOf {
            it.threatScore
        }

        return totalScore / reports.size
    }

    /**
     * Get malware statistics
     */
    fun getMalwareStatistics(
        context: Context
    ): Map<MalwareType, Int> {

        val reports = analyzeInstalledApplications(context)

        return reports.groupingBy {
            it.malwareType
        }.eachCount()
    }

    /**
     * Get security summary
     */
    fun getSecuritySummary(
        context: Context
    ): SecuritySummary {

        val reports = analyzeInstalledApplications(context)

        val criticalCount = reports.count {
            it.securityStatus == SecurityStatus.CRITICAL
        }

        val dangerousCount = reports.count {
            it.securityStatus == SecurityStatus.DANGEROUS
        }

        val warningCount = reports.count {
            it.securityStatus == SecurityStatus.WARNING
        }

        val safeCount = reports.count {
            it.securityStatus == SecurityStatus.SAFE ||
            it.securityStatus == SecurityStatus.SECURE
        }

        return SecuritySummary(
            totalApps = reports.size,
            criticalThreats = criticalCount,
            dangerousThreats = dangerousCount,
            warnings = warningCount,
            safeApps = safeCount,
            deviceRiskScore = calculateDeviceRiskScore(context)
        )
    }

    /**
     * Threat report data model
     */
    data class ThreatReport(
        val packageName: String,
        val threatScore: Int,
        val malwareType: MalwareType,
        val securityStatus: SecurityStatus,
        val threatSources: List<ThreatSource>,
        val suspiciousPermissions: List<String>,
        val recommendation: String
    )

    /**
     * Security summary model
     */
    data class SecuritySummary(
        val totalApps: Int,
        val criticalThreats: Int,
        val dangerousThreats: Int,
        val warnings: Int,
        val safeApps: Int,
        val deviceRiskScore: Int
    )
}
