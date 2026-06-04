package com.sentrix.domain.models

/**
 * ScamAnalysis
 *
 * Represents the result of scam detection
 * and fraud analysis performed by the
 * SentriX platform.
 *
 * Used by:
 * - Scam Detection Engine
 * - AI Fraud Analyzer
 * - SMS Protection Module
 * - Email Security Module
 * - URL Analysis Engine
 * - Security Dashboard
 */
data class ScamAnalysis(

    /**
     * Unique analysis identifier.
     */
    val analysisId: String,

    /**
     * Content source.
     */
    val sourceType: ScamSourceType,

    /**
     * Original content analyzed.
     */
    val content: String,

    /**
     * Analysis verdict.
     */
    val verdict: ScamVerdict,

    /**
     * Scam probability score (0 - 100).
     */
    val probabilityScore: Int,

    /**
     * Risk score (0 - 100).
     */
    val riskScore: Int,

    /**
     * Threat severity.
     */
    val severity: ThreatSeverity,

    /**
     * AI confidence score (0 - 100).
     */
    val confidenceScore: Int,

    /**
     * Detected scam category.
     */
    val category: ScamCategory,

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Security findings.
     */
    val findings: List<ScamFinding> = emptyList(),

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
 * Scam content source.
 */
enum class ScamSourceType {
    SMS,
    EMAIL,
    URL,
    PHONE_CALL,
    SOCIAL_MEDIA,
    MESSAGING_APP,
    DOCUMENT,
    UNKNOWN
}

/**
 * Scam analysis verdict.
 */
enum class ScamVerdict {
    SAFE,
    SUSPICIOUS,
    SCAM,
    HIGH_RISK_SCAM,
    UNKNOWN
}

/**
 * Scam categories.
 */
enum class ScamCategory {
    PHISHING,
    BANKING_FRAUD,
    INVESTMENT_SCAM,
    CRYPTO_SCAM,
    LOTTERY_SCAM,
    TECH_SUPPORT_SCAM,
    ROMANCE_SCAM,
    IMPERSONATION_SCAM,
    DELIVERY_SCAM,
    JOB_SCAM,
    UNKNOWN
}

/**
 * Scam detection finding.
 */
data class ScamFinding(

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
