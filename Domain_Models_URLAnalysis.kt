package com.sentrix.domain.models

/**
 * URLAnalysis
 *
 * Represents the result of a URL security
 * analysis performed by the SentriX platform.
 *
 * Used by:
 * - URLScannerHelper
 * - Phishing Detection Engine
 * - Threat Analysis Engine
 * - Browser Protection Module
 * - Security Dashboard
 * - AI Security Analysis
 */
data class URLAnalysis(

    /**
     * Unique analysis identifier.
     */
    val analysisId: String,

    /**
     * Original URL submitted
     * for analysis.
     */
    val url: String,

    /**
     * Final resolved URL.
     */
    val resolvedUrl: String? = null,

    /**
     * Domain name.
     */
    val domain: String,

    /**
     * Analysis result.
     */
    val verdict: URLVerdict,

    /**
     * Risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Threat severity.
     */
    val severity: ThreatSeverity,

    /**
     * Whether phishing indicators
     * were detected.
     */
    val phishingDetected: Boolean,

    /**
     * Whether malware indicators
     * were detected.
     */
    val malwareDetected: Boolean,

    /**
     * Whether the URL uses HTTPS.
     */
    val isSecureConnection: Boolean,

    /**
     * Reputation score (0 - 100).
     */
    val reputationScore: Int,

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Security findings.
     */
    val findings: List<URLFinding> = emptyList(),

    /**
     * Recommended actions.
     */
    val recommendations: List<String> = emptyList(),

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> = emptyMap()
)

/**
 * URL analysis verdict.
 */
enum class URLVerdict {
    SAFE,
    SUSPICIOUS,
    MALICIOUS,
    PHISHING,
    BLOCKED,
    UNKNOWN
}

/**
 * URL security finding.
 */
data class URLFinding(

    /**
     * Finding title.
     */
    val title: String,

    /**
     * Finding description.
     */
    val description: String,

    /**
     * Severity level.
     */
    val severity: ThreatSeverity
)
