package com.sentrix.security.integrity

import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * SentriX Integrity Report Generator
 *
 * Aggregates integrity-check results from different SentriX security
 * components and generates a unified integrity report.
 *
 * Responsibilities:
 *
 * - Aggregate application integrity results.
 * - Aggregate file integrity results.
 * - Aggregate database integrity results.
 * - Aggregate signature integrity results.
 * - Aggregate generic integrity findings.
 * - Calculate an overall integrity score.
 * - Determine overall integrity status.
 * - Generate human-readable summaries.
 * - Generate machine-readable structured reports.
 * - Identify critical findings.
 * - Identify modified/deleted resources.
 * - Provide report statistics.
 *
 * This class DOES NOT perform integrity checks itself.
 *
 * It is intentionally separated from:
 *
 * - IntegrityChecker
 * - FileIntegrityChecker
 * - DatabaseIntegrityChecker
 * - SignatureIntegrityChecker
 * - AppIntegrityChecker
 *
 * Architecture:
 *
 *        Integrity Checkers
 *               │
 *      ┌────────┼────────┐
 *      ▼        ▼        ▼
 *     App     File    Database
 *     Check   Check    Check
 *      │        │        │
 *      └────────┼────────┘
 *               ▼
 *        Signature Check
 *               │
 *               ▼
 *     IntegrityReportGenerator
 *               │
 *       ┌───────┼────────┐
 *       ▼       ▼        ▼
 *     Score   Findings  Summary
 *       │       │        │
 *       └───────┼────────┘
 *               ▼
 *        IntegrityReport
 */
class IntegrityReportGenerator {

    // =========================================================================
    // Main Report Generation
    // =========================================================================

    /**
     * Generates a unified integrity report from all available integrity
     * components.
     */
    fun generateReport(
        appIntegrity:
            AppIntegrityReport? = null,

        fileResults:
            List<FileIntegrityResult> = emptyList(),

        databaseReports:
            List<DatabaseIntegrityReport> = emptyList(),

        signatureIntegrity:
            SignatureIntegrityReport? = null,

        genericFindings:
            List<IntegrityReportFinding> = emptyList()
    ): IntegrityReport {

        val generatedAt =
            System.currentTimeMillis()

        val findings =
            mutableListOf<IntegrityReportFinding>()

        // ---------------------------------------------------------------------
        // Application integrity
        // ---------------------------------------------------------------------

        if (
            appIntegrity != null
        ) {

            findings +=
                convertAppIntegrityFindings(
                    appIntegrity
                )
        }

        // ---------------------------------------------------------------------
        // File integrity
        // ---------------------------------------------------------------------

        findings +=
            convertFileIntegrityFindings(
                fileResults
            )

        // ---------------------------------------------------------------------
        // Database integrity
        // ---------------------------------------------------------------------

        findings +=
            convertDatabaseIntegrityFindings(
                databaseReports
            )

        // ---------------------------------------------------------------------
        // Signature integrity
        // ---------------------------------------------------------------------

        if (
            signatureIntegrity != null
        ) {

            findings +=
                convertSignatureIntegrityFindings(
                    signatureIntegrity
                )
        }

        // ---------------------------------------------------------------------
        // Generic integrity findings
        // ---------------------------------------------------------------------

        findings +=
            genericFindings

        val normalizedFindings =
            normalizeFindings(
                findings
            )

        val severity =
            determineSeverity(
                normalizedFindings
            )

        val status =
            determineStatus(
                normalizedFindings
            )

        val score =
            calculateIntegrityScore(
                normalizedFindings
            )

        val statistics =
            calculateStatistics(
                normalizedFindings
            )

        val summary =
            generateSummary(
                status =
                    status,
                score =
                    score,
                statistics =
                    statistics
            )

        return IntegrityReport(

            reportId =
                createReportId(
                    generatedAt
                ),

            generatedAtMillis =
                generatedAt,

            generatedAtFormatted =
                formatTimestamp(
                    generatedAt
                ),

            applicationIntegrity =
                appIntegrity,

            fileResults =
                fileResults,

            databaseReports =
                databaseReports,

            signatureIntegrity =
                signatureIntegrity,

            findings =
                normalizedFindings,

            severity =
                severity,

            status =
                status,

            score =
                score,

            statistics =
                statistics,

            summary =
                summary
        )
    }

    // =========================================================================
    // Application Findings
    // =========================================================================

    /**
     * Converts application integrity results into common report findings.
     */
    private fun convertAppIntegrityFindings(
        report:
            AppIntegrityReport
    ): List<IntegrityReportFinding> {

        return report.findings.map {
            finding ->

            IntegrityReportFinding(

                source =
                    IntegrityReportSource
                        .APPLICATION,

                category =
                    IntegrityReportCategory
                        .APPLICATION_INTEGRITY,

                severity =
                    mapAppSeverity(
                        finding.severity
                    ),

                type =
                    finding.type.name,

                message =
                    finding.message,

                resource =
                    report.packageName,

                detectedAtMillis =
                    System.currentTimeMillis()
            )
        }
    }

    /**
     * Maps AppIntegrity severity into the common report severity.
     */
    private fun mapAppSeverity(
        severity:
            AppIntegritySeverity
    ): IntegrityReportSeverity {

        return when (
            severity
        ) {

            AppIntegritySeverity.SAFE ->
                IntegrityReportSeverity.SAFE

            AppIntegritySeverity.LOW ->
                IntegrityReportSeverity.LOW

            AppIntegritySeverity.MEDIUM ->
                IntegrityReportSeverity.MEDIUM

            AppIntegritySeverity.HIGH ->
                IntegrityReportSeverity.HIGH

            AppIntegritySeverity.CRITICAL ->
                IntegrityReportSeverity.CRITICAL
        }
    }

    // =========================================================================
    // File Findings
    // =========================================================================

    /**
     * Converts file integrity results into common report findings.
     */
    private fun convertFileIntegrityFindings(
        results:
            List<FileIntegrityResult>
    ): List<IntegrityReportFinding> {

        val findings =
            mutableListOf<IntegrityReportFinding>()

        results.forEach {
            result ->

            when (
                result
            ) {

                is FileIntegrityResult.Checked -> {

                    when (
                        result.status
                    ) {

                        FileIntegrityStatus.INTACT -> {
                            // No finding required for healthy files.
                        }

                        FileIntegrityStatus.MODIFIED -> {

                            findings +=
                                IntegrityReportFinding(

                                    source =
                                        IntegrityReportSource
                                            .FILE,

                                    category =
                                        IntegrityReportCategory
                                            .FILE_INTEGRITY,

                                    severity =
                                        IntegrityReportSeverity
                                            .HIGH,

                                    type =
                                        "FILE_MODIFIED",

                                    message =
                                        "File contents differ from the trusted integrity baseline.",

                                    resource =
                                        result.path,

                                    detectedAtMillis =
                                        result.checkedAtMillis
                                )
                        }

                        FileIntegrityStatus.DELETED -> {

                            findings +=
                                IntegrityReportFinding(

                                    source =
                                        IntegrityReportSource
                                            .FILE,

                                    category =
                                        IntegrityReportCategory
                                            .FILE_INTEGRITY,

                                    severity =
                                        IntegrityReportSeverity
                                            .CRITICAL,

                                    type =
                                        "FILE_DELETED",

                                    message =
                                        "A protected file has been deleted.",

                                    resource =
                                        result.path,

                                    detectedAtMillis =
                                        result.checkedAtMillis
                                )
                        }

                        FileIntegrityStatus.INVALID -> {

                            findings +=
                                IntegrityReportFinding(

                                    source =
                                        IntegrityReportSource
                                            .FILE,

                                    category =
                                        IntegrityReportCategory
                                            .FILE_INTEGRITY,

                                    severity =
                                        IntegrityReportSeverity
                                            .HIGH,

                                    type =
                                        "INVALID_FILE",

                                    message =
                                        "Protected path is not a valid regular file.",

                                    resource =
                                        result.path,

                                    detectedAtMillis =
                                        result.checkedAtMillis
                                )
                        }

                        FileIntegrityStatus.UNVERIFIABLE -> {

                            findings +=
                                IntegrityReportFinding(

                                    source =
                                        IntegrityReportSource
                                            .FILE,

                                    category =
                                        IntegrityReportCategory
                                            .FILE_INTEGRITY,

                                    severity =
                                        IntegrityReportSeverity
                                            .HIGH,

                                    type =
                                        "FILE_UNVERIFIABLE",

                                    message =
                                        "Protected file could not be cryptographically verified.",

                                    resource =
                                        result.path,

                                    detectedAtMillis =
                                        result.checkedAtMillis
                                )
                        }

                        FileIntegrityStatus.NO_BASELINE -> {

                            findings +=
                                IntegrityReportFinding(

                                    source =
                                        IntegrityReportSource
                                            .FILE,

                                    category =
                                        IntegrityReportCategory
                                            .FILE_INTEGRITY,

                                    severity =
                                        IntegrityReportSeverity
                                            .LOW,

                                    type =
                                        "FILE_BASELINE_MISSING",

                                    message =
                                        "No trusted integrity baseline exists for the file.",

                                    resource =
                                        result.path,

                                    detectedAtMillis =
                                        result.checkedAtMillis
                                )
                        }
                    }
                }

                is FileIntegrityResult.Failed -> {

                    findings +=
                        IntegrityReportFinding(

                            source =
                                IntegrityReportSource
                                    .FILE,

                            category =
                                IntegrityReportCategory
                                    .FILE_INTEGRITY,

                            severity =
                                IntegrityReportSeverity
                                    .HIGH,

                            type =
                                "FILE_CHECK_FAILED",

                            message =
                                result.reason,

                            resource =
                                result.path,

                            detectedAtMillis =
                                System.currentTimeMillis()
                        )
                }
            }
        }

        return findings
    }

    // =========================================================================
    // Database Findings
    // =========================================================================

    /**
     * Converts database integrity reports into common report findings.
     */
    private fun convertDatabaseIntegrityFindings(
        reports:
            List<DatabaseIntegrityReport>
    ): List<IntegrityReportFinding> {

        val findings =
            mutableListOf<IntegrityReportFinding>()

        reports.forEach {
            report ->

            report.findings.forEach {
                finding ->

                findings +=
                    IntegrityReportFinding(

                        source =
                            IntegrityReportSource
                                .DATABASE,

                        category =
                            IntegrityReportCategory
                                .DATABASE_INTEGRITY,

                        severity =
                            mapDatabaseSeverity(
                                finding.severity
                            ),

                        type =
                            finding.type.name,

                        message =
                            finding.message,

                        resource =
                            report.databasePath,

                        detectedAtMillis =
                            report.checkedAtMillis
                    )
            }
        }

        return findings
    }

    /**
     * Maps database severity to report severity.
     */
    private fun mapDatabaseSeverity(
        severity:
            DatabaseIntegritySeverity
    ): IntegrityReportSeverity {

        return when (
            severity
        ) {

            DatabaseIntegritySeverity.SAFE ->
                IntegrityReportSeverity.SAFE

            DatabaseIntegritySeverity.LOW ->
                IntegrityReportSeverity.LOW

            DatabaseIntegritySeverity.MEDIUM ->
                IntegrityReportSeverity.MEDIUM

            DatabaseIntegritySeverity.HIGH ->
                IntegrityReportSeverity.HIGH

            DatabaseIntegritySeverity.CRITICAL ->
                IntegrityReportSeverity.CRITICAL
        }
    }

    // =========================================================================
    // Signature Findings
    // =========================================================================

    /**
     * Converts signature integrity findings into common report findings.
     */
    private fun convertSignatureIntegrityFindings(
        report:
            SignatureIntegrityReport
    ): List<IntegrityReportFinding> {

        return report.findings.map {
            finding ->

            IntegrityReportFinding(

                source =
                    IntegrityReportSource
                        .SIGNATURE,

                category =
                    IntegrityReportCategory
                        .SIGNATURE_INTEGRITY,

                severity =
                    mapSignatureSeverity(
                        finding.severity
                    ),

                type =
                    finding.type.name,

                message =
                    finding.message,

                resource =
                    report.packageName,

                detectedAtMillis =
                    System.currentTimeMillis()
            )
        }
    }

    /**
     * Maps signature severity to common report severity.
     */
    private fun mapSignatureSeverity(
        severity:
            SignatureIntegritySeverity
    ): IntegrityReportSeverity {

        return when (
            severity
        ) {

            SignatureIntegritySeverity.SAFE ->
                IntegrityReportSeverity.SAFE

            SignatureIntegritySeverity.LOW ->
                IntegrityReportSeverity.LOW

            SignatureIntegritySeverity.MEDIUM ->
                IntegrityReportSeverity.MEDIUM

            SignatureIntegritySeverity.HIGH ->
                IntegrityReportSeverity.HIGH

            SignatureIntegritySeverity.CRITICAL ->
                IntegrityReportSeverity.CRITICAL
        }
    }

    // =========================================================================
    // Finding Normalization
    // =========================================================================

    /**
     * Removes exact duplicate findings and orders findings by severity.
     */
    private fun normalizeFindings(
        findings:
            List<IntegrityReportFinding>
    ): List<IntegrityReportFinding> {

        return findings
            .distinctBy {
                FindingIdentity(

                    source =
                        it.source,

                    category =
                        it.category,

                    type =
                        it.type,

                    resource =
                        it.resource,

                    message =
                        it.message
                )
            }
            .sortedByDescending {
                it.severity.priority
            }
    }

    // =========================================================================
    // Severity
    // =========================================================================

    /**
     * Determines the highest severity represented in the report.
     */
    private fun determineSeverity(
        findings:
            List<IntegrityReportFinding>
    ): IntegrityReportSeverity {

        return findings
            .maxByOrNull {
                it.severity.priority
            }
            ?.severity
            ?: IntegrityReportSeverity
                .SAFE
    }

    // =========================================================================
    // Status
    // =========================================================================

    /**
     * Determines overall integrity status.
     */
    private fun determineStatus(
        findings:
            List<IntegrityReportFinding>
    ): IntegrityReportStatus {

        if (
            findings.any {
                it.severity ==
                        IntegrityReportSeverity
                            .CRITICAL
            }
        ) {

            return IntegrityReportStatus
                .COMPROMISED
        }

        if (
            findings.any {
                it.severity ==
                        IntegrityReportSeverity
                            .HIGH
            }
        ) {

            return IntegrityReportStatus
                .SUSPICIOUS
        }

        if (
            findings.any {
                it.severity ==
                        IntegrityReportSeverity
                            .MEDIUM
            }
        ) {

            return IntegrityReportStatus
                .WARNING
        }

        if (
            findings.any {
                it.severity ==
                        IntegrityReportSeverity
                            .LOW
            }
        ) {

            return IntegrityReportStatus
                .DEGRADED
        }

        return IntegrityReportStatus
            .INTACT
    }

    // =========================================================================
    // Score
    // =========================================================================

    /**
     * Calculates an overall integrity score.
     *
     * Score range:
     *
     *     0   = severely compromised
     *     100 = healthy
     *
     * Penalties:
     *
     * CRITICAL = -40
     * HIGH     = -25
     * MEDIUM   = -12
     * LOW      = -5
     *
     * Multiple identical findings are removed before scoring.
     */
    fun calculateIntegrityScore(
        findings:
            List<IntegrityReportFinding>
    ): Int {

        if (
            findings.isEmpty()
        ) {

            return 100
        }

        val penalty =
            findings.sumOf {
                finding ->

                when (
                    finding.severity
                ) {

                    IntegrityReportSeverity.SAFE ->
                        0

                    IntegrityReportSeverity.LOW ->
                        5

                    IntegrityReportSeverity.MEDIUM ->
                        12

                    IntegrityReportSeverity.HIGH ->
                        25

                    IntegrityReportSeverity.CRITICAL ->
                        40
                }
            }

        return (
            100 - penalty
            )
            .coerceIn(
                minimumValue = 0,
                maximumValue = 100
            )
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * Calculates report statistics.
     */
    private fun calculateStatistics(
        findings:
            List<IntegrityReportFinding>
    ): IntegrityReportStatistics {

        val bySeverity =
            findings.groupingBy {
                it.severity
            }
                .eachCount()

        val byCategory =
            findings.groupingBy {
                it.category
            }
                .eachCount()

        val criticalCount =
            bySeverity[
                IntegrityReportSeverity
                    .CRITICAL
            ] ?: 0

        val highCount =
            bySeverity[
                IntegrityReportSeverity
                    .HIGH
            ] ?: 0

        val mediumCount =
            bySeverity[
                IntegrityReportSeverity
                    .MEDIUM
            ] ?: 0

        val lowCount =
            bySeverity[
                IntegrityReportSeverity
                    .LOW
            ] ?: 0

        return IntegrityReportStatistics(

            totalFindings =
                findings.size,

            criticalFindings =
                criticalCount,

            highFindings =
                highCount,

            mediumFindings =
                mediumCount,

            lowFindings =
                lowCount,

            safeFindings =
                bySeverity[
                    IntegrityReportSeverity
                        .SAFE
                ] ?: 0,

            applicationFindings =
                byCategory[
                    IntegrityReportCategory
                        .APPLICATION_INTEGRITY
                ] ?: 0,

            fileFindings =
                byCategory[
                    IntegrityReportCategory
                        .FILE_INTEGRITY
                ] ?: 0,

            databaseFindings =
                byCategory[
                    IntegrityReportCategory
                        .DATABASE_INTEGRITY
                ] ?: 0,

            signatureFindings =
                byCategory[
                    IntegrityReportCategory
                        .SIGNATURE_INTEGRITY
                ] ?: 0,

            runtimeFindings =
                byCategory[
                    IntegrityReportCategory
                        .RUNTIME_INTEGRITY
                ] ?: 0,

            genericFindings =
                byCategory[
                    IntegrityReportCategory
                        .GENERAL
                ] ?: 0
        )
    }

    // =========================================================================
    // Summary
    // =========================================================================

    /**
     * Generates a concise human-readable report summary.
     */
    private fun generateSummary(
        status:
            IntegrityReportStatus,

        score: Int,

        statistics:
            IntegrityReportStatistics
    ): String {

        return when (
            status
        ) {

            IntegrityReportStatus.INTACT ->

                "SentriX integrity verification completed successfully. " +
                        "No integrity violations were detected. " +
                        "Integrity score: $score/100."

            IntegrityReportStatus.DEGRADED ->

                "SentriX integrity verification completed with minor " +
                        "integrity observations. " +
                        "${statistics.lowFindings} low-severity finding(s) " +
                        "were detected. Integrity score: $score/100."

            IntegrityReportStatus.WARNING ->

                "SentriX integrity verification detected warning-level " +
                        "conditions. " +
                        "${statistics.mediumFindings} medium-severity finding(s) " +
                        "were detected. Integrity score: $score/100."

            IntegrityReportStatus.SUSPICIOUS ->

                "SentriX integrity verification detected suspicious " +
                        "integrity conditions. " +
                        "${statistics.highFindings} high-severity finding(s) " +
                        "require investigation. Integrity score: $score/100."

            IntegrityReportStatus.COMPROMISED ->

                "SentriX integrity verification detected critical integrity " +
                        "violations. " +
                        "${statistics.criticalFindings} critical finding(s) " +
                        "require immediate security handling. " +
                        "Integrity score: $score/100."
        }
    }

    // =========================================================================
    // Critical Findings
    // =========================================================================

    /**
     * Returns only critical findings.
     */
    fun getCriticalFindings(
        report:
            IntegrityReport
    ): List<IntegrityReportFinding> {

        return report.findings.filter {
            it.severity ==
                    IntegrityReportSeverity
                        .CRITICAL
        }
    }

    /**
     * Returns high or critical findings.
     */
    fun getHighRiskFindings(
        report:
            IntegrityReport
    ): List<IntegrityReportFinding> {

        return report.findings.filter {
            it.severity ==
                    IntegrityReportSeverity
                        .HIGH ||
                    it.severity ==
                    IntegrityReportSeverity
                        .CRITICAL
        }
    }

    /**
     * Determines whether immediate security action should be considered.
     */
    fun requiresImmediateAction(
        report:
            IntegrityReport
    ): Boolean {

        return report.status ==
                IntegrityReportStatus
                    .COMPROMISED
    }

    /**
     * Determines whether the report contains any suspicious condition.
     */
    fun isSuspicious(
        report:
            IntegrityReport
    ): Boolean {

        return report.status ==
                IntegrityReportStatus
                    .SUSPICIOUS ||
                report.status ==
                IntegrityReportStatus
                    .COMPROMISED
    }

    // =========================================================================
    // Category Filtering
    // =========================================================================

    /**
     * Returns findings belonging to a specific category.
     */
    fun getFindingsByCategory(
        report:
            IntegrityReport,
        category:
            IntegrityReportCategory
    ): List<IntegrityReportFinding> {

        return report.findings.filter {
            it.category ==
                    category
        }
    }

    /**
     * Returns findings belonging to a specific source.
     */
    fun getFindingsBySource(
        report:
            IntegrityReport,
        source:
            IntegrityReportSource
    ): List<IntegrityReportFinding> {

        return report.findings.filter {
            it.source ==
                    source
        }
    }

    // =========================================================================
    // Text Report
    // =========================================================================

    /**
     * Generates a human-readable text representation.
     */
    fun generateTextReport(
        report:
            IntegrityReport
    ): String {

        val builder =
            StringBuilder()

        builder.appendLine(
            "========================================"
        )

        builder.appendLine(
            "           SENTRIX INTEGRITY REPORT"
        )

        builder.appendLine(
            "========================================"
        )

        builder.appendLine(
            "Report ID : ${report.reportId}"
        )

        builder.appendLine(
            "Generated : ${report.generatedAtFormatted}"
        )

        builder.appendLine(
            "Status    : ${report.status}"
        )

        builder.appendLine(
            "Severity  : ${report.severity}"
        )

        builder.appendLine(
            "Score     : ${report.score}/100"
        )

        builder.appendLine()

        builder.appendLine(
            "SUMMARY"
        )

        builder.appendLine(
            report.summary
        )

        builder.appendLine()

        builder.appendLine(
            "STATISTICS"
        )

        builder.appendLine(
            "Total Findings    : " +
                    report.statistics.totalFindings
        )

        builder.appendLine(
            "Critical Findings : " +
                    report.statistics.criticalFindings
        )

        builder.appendLine(
            "High Findings     : " +
                    report.statistics.highFindings
        )

        builder.appendLine(
            "Medium Findings   : " +
                    report.statistics.mediumFindings
        )

        builder.appendLine(
            "Low Findings      : " +
                    report.statistics.lowFindings
        )

        builder.appendLine()

        builder.appendLine(
            "FINDINGS"
        )

        if (
            report.findings.isEmpty()
        ) {

            builder.appendLine(
                "No integrity findings detected."
            )

        } else {

            report.findings.forEachIndexed {
                index,
                finding ->

                builder.appendLine(
                    "${index + 1}. " +
                            "[${finding.severity}] " +
                            "${finding.type}"
                )

                builder.appendLine(
                    "   Source   : ${finding.source}"
                )

                builder.appendLine(
                    "   Category : ${finding.category}"
                )

                if (
                    !finding.resource.isNullOrBlank()
                ) {

                    builder.appendLine(
                        "   Resource : ${finding.resource}"
                    )
                }

                builder.appendLine(
                    "   Message  : ${finding.message}"
                )

                builder.appendLine()
            }
        }

        builder.appendLine(
            "========================================"
        )

        return builder.toString()
    }

    // =========================================================================
    // Machine-Readable Report
    // =========================================================================

    /**
     * Generates a lightweight JSON-like representation without requiring a
     * JSON library.
     *
     * For production API serialization, SentriX should use kotlinx.serialization
     * or another dedicated JSON serializer.
     */
    fun generateStructuredSummary(
        report:
            IntegrityReport
    ): Map<String, Any> {

        return mapOf(

            "reportId" to
                    report.reportId,

            "generatedAtMillis" to
                    report.generatedAtMillis,

            "status" to
                    report.status.name,

            "severity" to
                    report.severity.name,

            "score" to
                    report.score,

            "summary" to
                    report.summary,

            "totalFindings" to
                    report.statistics.totalFindings,

            "criticalFindings" to
                    report.statistics.criticalFindings,

            "highFindings" to
                    report.statistics.highFindings,

            "mediumFindings" to
                    report.statistics.mediumFindings,

            "lowFindings" to
                    report.statistics.lowFindings
        )
    }

    // =========================================================================
    // Report ID
    // =========================================================================

    /**
     * Creates a deterministic human-readable report identifier.
     */
    private fun createReportId(
        timestamp: Long
    ): String {

        return "SENTRIX-INTEGRITY-$timestamp"
    }

    /**
     * Formats a timestamp for human-readable reports.
     */
    private fun formatTimestamp(
        timestamp: Long
    ): String {

        return try {

            SimpleDateFormat(
                "yyyy-MM-dd HH:mm:ss.SSS",
                Locale.US
            )
                .format(
                    Date(
                        timestamp
                    )
                )

        } catch (
            _: Exception
        ) {

            timestamp.toString()
        }
    }
}

// =============================================================================
// Integrity Report
// =============================================================================

/**
 * Unified SentriX integrity report.
 */
data class IntegrityReport(

    val reportId: String,

    val generatedAtMillis: Long,

    val generatedAtFormatted: String,

    val applicationIntegrity:
        AppIntegrityReport?,

    val fileResults:
        List<FileIntegrityResult>,

    val databaseReports:
        List<DatabaseIntegrityReport>,

    val signatureIntegrity:
        SignatureIntegrityReport?,

    val findings:
        List<IntegrityReportFinding>,

    val severity:
        IntegrityReportSeverity,

    val status:
        IntegrityReportStatus,

    val score: Int,

    val statistics:
        IntegrityReportStatistics,

    val summary: String
)

// =============================================================================
// Report Finding
// =============================================================================

/**
 * Common integrity finding used by the unified report.
 */
data class IntegrityReportFinding(

    val source:
        IntegrityReportSource,

    val category:
        IntegrityReportCategory,

    val severity:
        IntegrityReportSeverity,

    val type: String,

    val message: String,

    val resource: String?,

    val detectedAtMillis: Long
)

/**
 * Lightweight identity used for duplicate removal.
 */
private data class FindingIdentity(

    val source:
        IntegrityReportSource,

    val category:
        IntegrityReportCategory,

    val type: String,

    val resource: String?,

    val message: String
)

// =============================================================================
// Report Source
// =============================================================================

/**
 * Component that produced an integrity observation.
 */
enum class IntegrityReportSource {

    APPLICATION,

    FILE,

    DATABASE,

    SIGNATURE,

    RUNTIME,

    GENERAL
}

// =============================================================================
// Report Category
// =============================================================================

/**
 * Security category represented in the integrity report.
 */
enum class IntegrityReportCategory {

    APPLICATION_INTEGRITY,

    FILE_INTEGRITY,

    DATABASE_INTEGRITY,

    SIGNATURE_INTEGRITY,

    RUNTIME_INTEGRITY,

    GENERAL
}

// =============================================================================
// Report Severity
// =============================================================================

/**
 * Unified integrity severity.
 */
enum class IntegrityReportSeverity(
    val priority: Int
) {

    SAFE(
        priority = 0
    ),

    LOW(
        priority = 1
    ),

    MEDIUM(
        priority = 2
    ),

    HIGH(
        priority = 3
    ),

    CRITICAL(
        priority = 4
    )
}

// =============================================================================
// Report Status
// =============================================================================

/**
 * Overall integrity state.
 */
enum class IntegrityReportStatus {

    /**
     * All checked components passed integrity verification.
     */
    INTACT,

    /**
     * Minor integrity observations exist.
     */
    DEGRADED,

    /**
     * Medium-risk integrity conditions exist.
     */
    WARNING,

    /**
     * High-risk integrity conditions exist.
     */
    SUSPICIOUS,

    /**
     * Critical integrity violations were detected.
     */
    COMPROMISED
}

// =============================================================================
// Statistics
// =============================================================================

/**
 * Aggregated integrity report statistics.
 */
data class IntegrityReportStatistics(

    val totalFindings: Int,

    val criticalFindings: Int,

    val highFindings: Int,

    val mediumFindings: Int,

    val lowFindings: Int,

    val safeFindings: Int,

    val applicationFindings: Int,

    val fileFindings: Int,

    val databaseFindings: Int,

    val signatureFindings: Int,

    val runtimeFindings: Int,

    val genericFindings: Int
)
