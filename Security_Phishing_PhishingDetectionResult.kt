package com.sentrix.security.phishing

import java.time.Instant

/**
 * PhishingDetectionResult
 *
 * Central result model for the SentriX phishing detection pipeline.
 *
 * This class represents the final output of a phishing assessment.
 *
 * It is intentionally designed as an aggregation model rather than
 * an analyzer-specific result.
 *
 * The result can contain evidence from:
 *
 * - PhishingAnalyzer
 * - PhishingURLAnalyzer
 * - PhishingDomainAnalyzer
 * - PhishingContentAnalyzer
 * - PhishingPatternDetector
 * - PhishingIndicatorDetector
 * - PhishingRiskEvaluator
 * - External threat intelligence
 *
 * Typical flow:
 *
 *     Input
 *       |
 *       v
 * PhishingDetectionService
 *       |
 *       +---- URL Analysis
 *       |
 *       +---- Domain Analysis
 *       |
 *       +---- Content Analysis
 *       |
 *       +---- Pattern Detection
 *       |
 *       +---- Indicator Detection
 *       |
 *       v
 * PhishingRiskEvaluator
 *       |
 *       v
 * PhishingDetectionResult
 *
 * This model should remain immutable.
 */
data class PhishingDetectionResult(

    /**
     * Unique identifier for this detection operation.
     *
     * This can be used to correlate:
     *
     * - security logs
     * - analytics
     * - telemetry
     * - user reports
     * - threat events
     */
    val detectionId: String,

    /**
     * Timestamp at which the analysis was completed.
     */
    val analyzedAt: Instant = Instant.now(),

    /**
     * Overall phishing risk score.
     *
     * Range:
     *
     * 0.0 -> minimal risk
     * 1.0 -> maximum risk
     */
    val riskScore: Float,

    /**
     * Overall phishing classification.
     */
    val classification: PhishingRiskClassification,

    /**
     * Confidence in the final assessment.
     *
     * Range:
     *
     * 0.0 -> no confidence
     * 1.0 -> very high confidence
     */
    val confidence: Float,

    /**
     * Recommended security action.
     */
    val decision: PhishingRiskDecision,

    /**
     * Whether the content should be considered suspicious.
     */
    val isSuspicious: Boolean,

    /**
     * Whether the content is considered malicious/high-risk.
     *
     * This is intentionally separate from isSuspicious.
     *
     * Example:
     *
     * LOW risk:
     *     suspicious = true
     *     malicious = false
     *
     * HIGH risk:
     *     suspicious = true
     *     malicious = true
     */
    val isMalicious: Boolean,

    /**
     * Original content that was analyzed.
     *
     * This should normally NOT be persisted directly when it can
     * contain sensitive user information.
     */
    val analyzedContent: String? = null,

    /**
     * Primary URL discovered during analysis.
     */
    val primaryUrl: String? = null,

    /**
     * Extracted URLs.
     */
    val detectedUrls: List<String> = emptyList(),

    /**
     * Extracted domains.
     */
    val detectedDomains: List<String> = emptyList(),

    /**
     * Extracted email addresses.
     *
     * Callers should redact these before persistent logging if
     * privacy requirements require it.
     */
    val detectedEmailAddresses: List<String> = emptyList(),

    /**
     * URL analysis result.
     */
    val urlAnalysis:
        PhishingURLAnalysis? = null,

    /**
     * Domain analysis result.
     */
    val domainAnalysis:
        PhishingDomainAnalysis? = null,

    /**
     * Content analysis result.
     */
    val contentAnalysis:
        PhishingContentAnalysis? = null,

    /**
     * Pattern detection result.
     */
    val patternAnalysis:
        PhishingPatternDetectionResult? = null,

    /**
     * Technical/contextual indicator result.
     */
    val indicatorAnalysis:
        PhishingIndicatorDetectionResult? = null,

    /**
     * Final risk evaluation.
     */
    val riskEvaluation:
        PhishingRiskEvaluation? = null,

    /**
     * External threat-intelligence evidence.
     */
    val externalSignals:
        List<PhishingExternalSignal> = emptyList(),

    /**
     * Human-readable primary reasons behind the result.
     */
    val riskReasons:
        List<String> = emptyList(),

    /**
     * Recommended security actions.
     */
    val recommendations:
        List<PhishingRiskRecommendation> = emptyList(),

    /**
     * Normalized evidence summary.
     */
    val evidence:
        List<PhishingRiskEvidence> = emptyList(),

    /**
     * Security metadata.
     */
    val metadata:
        PhishingDetectionMetadata =
            PhishingDetectionMetadata()
) {

    /**
     * Returns true if the result requires user attention.
     */
    fun requiresUserAttention(): Boolean {

        return when (classification) {

            PhishingRiskClassification.SAFE ->
                false

            PhishingRiskClassification.LOW ->
                false

            PhishingRiskClassification.MEDIUM,
            PhishingRiskClassification.HIGH ->
                true
        }
    }

    /**
     * Returns true if SentriX should prevent interaction.
     */
    fun shouldBlock(): Boolean {

        return decision ==
                PhishingRiskDecision.BLOCK
    }

    /**
     * Returns true if SentriX should display a warning.
     */
    fun shouldWarn(): Boolean {

        return decision ==
                PhishingRiskDecision.WARN
    }

    /**
     * Returns true if the result should only be monitored.
     */
    fun shouldMonitor(): Boolean {

        return decision ==
                PhishingRiskDecision.MONITOR
    }

    /**
     * Returns true if the result is safe to proceed.
     */
    fun isSafe(): Boolean {

        return classification ==
                PhishingRiskClassification.SAFE &&
                decision ==
                PhishingRiskDecision.ALLOW
    }

    /**
     * Returns true if critical evidence was detected.
     */
    fun hasCriticalEvidence(): Boolean {

        return evidence.any {
            it.severity ==
                    PhishingEvidenceSeverity.CRITICAL
        }
    }

    /**
     * Returns true if strong evidence exists.
     */
    fun hasStrongEvidence(): Boolean {

        return evidence.any {
            it.score >=
                    0.70f ||
                    it.severity ==
                    PhishingEvidenceSeverity.CRITICAL
        }
    }

    /**
     * Returns the strongest evidence items.
     */
    fun getTopEvidence(
        limit: Int = 5
    ): List<PhishingRiskEvidence> {

        require(limit > 0) {
            "Limit must be greater than zero."
        }

        return evidence
            .sortedByDescending {
                it.score * it.weight
            }
            .take(limit)
    }

    /**
     * Returns the highest-risk detected URL.
     */
    fun getHighestRiskUrl(): String? {

        return urlAnalysis
            ?.findings
            ?.maxByOrNull {
                it.score
            }
            ?.let {
                it.value
            }
            ?: primaryUrl
    }

    /**
     * Returns the highest-risk detected domain.
     */
    fun getHighestRiskDomain(): String? {

        return domainAnalysis
            ?.findings
            ?.maxByOrNull {
                it.score
            }
            ?.let {
                it.value
            }
            ?: detectedDomains.firstOrNull()
    }

    /**
     * Returns all detected phishing categories.
     */
    fun getDetectedCategories():
            Set<PhishingPatternCategory> {

        return patternAnalysis
            ?.findings
            ?.map {
                it.category
            }
            ?.toSet()
            ?: emptySet()
    }

    /**
     * Returns all indicator types detected.
     */
    fun getIndicatorTypes():
            Set<PhishingIndicatorType> {

        return indicatorAnalysis
            ?.indicators
            ?.map {
                it.type
            }
            ?.toSet()
            ?: emptySet()
    }

    /**
     * Returns whether sensitive authentication information
     * appears to be targeted.
     */
    fun targetsAuthenticationData(): Boolean {

        val patternTarget =
            patternAnalysis
                ?.findings
                ?.any {

                    it.category ==
                            PhishingPatternCategory.CREDENTIAL_HARVESTING ||

                            it.category ==
                            PhishingPatternCategory.OTP_HARVESTING ||

                            it.category ==
                            PhishingPatternCategory.PIN_HARVESTING
                }
                ?: false

        val indicatorTarget =
            indicatorAnalysis
                ?.indicators
                ?.any {

                    it.type ==
                            PhishingIndicatorType
                                .SENSITIVE_ACTION_LANGUAGE ||

                            it.type ==
                            PhishingIndicatorType
                                .SENSITIVE_QUERY_PARAMETER
                }
                ?: false

        return patternTarget ||
                indicatorTarget
    }

    /**
     * Returns whether financial information appears to be targeted.
     */
    fun targetsFinancialData(): Boolean {

        return patternAnalysis
            ?.findings
            ?.any {

                it.category ==
                        PhishingPatternCategory
                            .FINANCIAL_HARVESTING ||

                        it.category ==
                        PhishingPatternCategory
                            .PAYMENT_MANIPULATION ||

                        it.category ==
                        PhishingPatternCategory
                            .REFUND_SCAM
            }
            ?: false
    }

    /**
     * Returns a compact security summary.
     *
     * This is useful for:
     *
     * - dashboards
     * - notifications
     * - security cards
     * - audit records
     */
    fun getSecuritySummary(): String {

        return when (classification) {

            PhishingRiskClassification.SAFE ->
                "No significant phishing indicators detected."

            PhishingRiskClassification.LOW ->
                "Low-risk phishing indicators detected."

            PhishingRiskClassification.MEDIUM ->
                "Potential phishing activity detected. User caution is recommended."

            PhishingRiskClassification.HIGH ->
                "High-risk phishing activity detected. Interaction should be prevented."
        }
    }

    /**
     * Returns a user-safe summary without exposing raw content.
     */
    fun getUserSafeSummary(): PhishingUserSafeSummary {

        return PhishingUserSafeSummary(
            classification =
                classification,

            riskScore =
                riskScore,

            confidence =
                confidence,

            decision =
                decision,

            isSuspicious =
                isSuspicious,

            isMalicious =
                isMalicious,

            requiresUserAttention =
                requiresUserAttention(),

            shouldBlock =
                shouldBlock(),

            shouldWarn =
                shouldWarn(),

            primaryReasons =
                riskReasons
                    .take(5),

            recommendations =
                recommendations
                    .take(5)
        )
    }
}

/**
 * User-safe representation of a phishing result.
 *
 * This model deliberately excludes:
 *
 * - raw message content
 * - complete URLs
 * - email addresses
 * - internal detection metadata
 * - potentially sensitive telemetry
 *
 * It is suitable for UI presentation.
 */
data class PhishingUserSafeSummary(

    val classification:
        PhishingRiskClassification,

    val riskScore:
        Float,

    val confidence:
        Float,

    val decision:
        PhishingRiskDecision,

    val isSuspicious:
        Boolean,

    val isMalicious:
        Boolean,

    val requiresUserAttention:
        Boolean,

    val shouldBlock:
        Boolean,

    val shouldWarn:
        Boolean,

    val primaryReasons:
        List<String>,

    val recommendations:
        List<PhishingRiskRecommendation>
)

/**
 * Metadata associated with a phishing detection operation.
 *
 * This metadata is intended for internal SentriX telemetry and
 * diagnostics.
 */
data class PhishingDetectionMetadata(

    /**
     * Detection engine version.
     */
    val engineVersion:
        String = "1.0.0",

    /**
     * Ruleset version.
     */
    val rulesetVersion:
        String = "1.0.0",

    /**
     * Detection source.
     */
    val source:
        PhishingDetectionSource =
            PhishingDetectionSource.UNKNOWN,

    /**
     * Whether URL analysis was performed.
     */
    val urlAnalysisPerformed:
        Boolean = false,

    /**
     * Whether domain analysis was performed.
     */
    val domainAnalysisPerformed:
        Boolean = false,

    /**
     * Whether content analysis was performed.
     */
    val contentAnalysisPerformed:
        Boolean = false,

    /**
     * Whether pattern analysis was performed.
     */
    val patternAnalysisPerformed:
        Boolean = false,

    /**
     * Whether indicator analysis was performed.
     */
    val indicatorAnalysisPerformed:
        Boolean = false,

    /**
     * Whether external intelligence was consulted.
     */
    val externalIntelligenceUsed:
        Boolean = false,

    /**
     * Number of evidence sources.
     */
    val evidenceSourceCount:
        Int = 0,

    /**
     * Number of detected indicators.
     */
    val indicatorCount:
        Int = 0,

    /**
     * Number of detected patterns.
     */
    val patternCount:
        Int = 0,

    /**
     * Analysis duration in milliseconds.
     */
    val analysisDurationMs:
        Long = 0L,

    /**
     * Whether the analysis was completed successfully.
     */
    val analysisCompleted:
        Boolean = true,

    /**
     * Optional warning generated during analysis.
     */
    val analysisWarning:
        String? = null
)

/**
 * Source from which the phishing detection was initiated.
 */
enum class PhishingDetectionSource {

    /**
     * URL entered directly by the user.
     */
    URL_INPUT,

    /**
     * Browser/web protection event.
     */
    WEB_BROWSER,

    /**
     * SMS/message content.
     */
    SMS,

    /**
     * Email content.
     */
    EMAIL,

    /**
     * Notification content.
     */
    NOTIFICATION,

    /**
     * File/document containing a suspicious link.
     */
    FILE,

    /**
     * Application-generated content.
     */
    APPLICATION,

    /**
     * Background real-time protection.
     */
    REALTIME_PROTECTION,

    /**
     * Manual security scan.
     */
    MANUAL_SCAN,

    /**
     * Unknown source.
     */
    UNKNOWN
)

/**
 * Factory/helper responsible for creating a final result from
 * PhishingRiskEvaluation and individual analyzer results.
 *
 * Keeping construction logic here prevents the service layer from
 * becoming overloaded with result-building code.
 */
object PhishingDetectionResultFactory {

    /**
     * Creates a final PhishingDetectionResult.
     */
    fun create(
        detectionId: String,
        riskEvaluation: PhishingRiskEvaluation,
        urlAnalysis: PhishingURLAnalysis? = null,
        domainAnalysis: PhishingDomainAnalysis? = null,
        contentAnalysis: PhishingContentAnalysis? = null,
        patternAnalysis: PhishingPatternDetectionResult? = null,
        indicatorAnalysis: PhishingIndicatorDetectionResult? = null,
        analyzedContent: String? = null,
        primaryUrl: String? = null,
        source: PhishingDetectionSource =
            PhishingDetectionSource.UNKNOWN,
        externalSignals:
            List<PhishingExternalSignal> = emptyList(),
        analysisDurationMs: Long = 0L
    ): PhishingDetectionResult {

        val detectedUrls =
            buildDetectedUrls(
                primaryUrl = primaryUrl,
                indicatorAnalysis = indicatorAnalysis
            )

        val detectedDomains =
            buildDetectedDomains(
                domainAnalysis = domainAnalysis,
                indicatorAnalysis = indicatorAnalysis
            )

        val detectedEmails =
            indicatorAnalysis
                ?.extractedEmails
                ?: emptyList()

        val isMalicious =
            riskEvaluation.classification ==
                    PhishingRiskClassification.HIGH

        val metadata =
            PhishingDetectionMetadata(
                source =
                    source,

                urlAnalysisPerformed =
                    urlAnalysis != null,

                domainAnalysisPerformed =
                    domainAnalysis != null,

                contentAnalysisPerformed =
                    contentAnalysis != null,

                patternAnalysisPerformed =
                    patternAnalysis != null,

                indicatorAnalysisPerformed =
                    indicatorAnalysis != null,

                externalIntelligenceUsed =
                    externalSignals.isNotEmpty(),

                evidenceSourceCount =
                    riskEvaluation.evidence
                        .map {
                            it.source
                        }
                        .distinct()
                        .size,

                indicatorCount =
                    indicatorAnalysis
                        ?.indicators
                        ?.size
                        ?: 0,

                patternCount =
                    patternAnalysis
                        ?.findings
                        ?.size
                        ?: 0,

                analysisDurationMs =
                    analysisDurationMs
            )

        return PhishingDetectionResult(

            detectionId =
                detectionId,

            riskScore =
                riskEvaluation.riskScore,

            classification =
                riskEvaluation.classification,

            confidence =
                riskEvaluation.confidence,

            decision =
                riskEvaluation.decision,

            isSuspicious =
                riskEvaluation.classification !=
                        PhishingRiskClassification.SAFE,

            isMalicious =
                isMalicious,

            analyzedContent =
                analyzedContent,

            primaryUrl =
                primaryUrl,

            detectedUrls =
                detectedUrls,

            detectedDomains =
                detectedDomains,

            detectedEmailAddresses =
                detectedEmails,

            urlAnalysis =
                urlAnalysis,

            domainAnalysis =
                domainAnalysis,

            contentAnalysis =
                contentAnalysis,

            patternAnalysis =
                patternAnalysis,

            indicatorAnalysis =
                indicatorAnalysis,

            riskEvaluation =
                riskEvaluation,

            externalSignals =
                externalSignals,

            riskReasons =
                riskEvaluation
                    .primaryReasons,

            recommendations =
                riskEvaluation
                    .recommendations,

            evidence =
                riskEvaluation
                    .evidence,

            metadata =
                metadata
        )
    }

    /**
     * Builds a unique URL list.
     */
    private fun buildDetectedUrls(
        primaryUrl: String?,
        indicatorAnalysis:
            PhishingIndicatorDetectionResult?
    ): List<String> {

        val urls =
            mutableListOf<String>()

        if (
            !primaryUrl.isNullOrBlank()
        ) {

            urls.add(
                primaryUrl
            )
        }

        indicatorAnalysis
            ?.extractedUrls
            ?.forEach {
                if (
                    it.isNotBlank() &&
                    !urls.contains(it)
                ) {
                    urls.add(it)
                }
            }

        return urls
    }

    /**
     * Builds a unique domain list.
     */
    private fun buildDetectedDomains(
        domainAnalysis:
            PhishingDomainAnalysis?,
        indicatorAnalysis:
            PhishingIndicatorDetectionResult?
    ): List<String> {

        val domains =
            mutableListOf<String>()

        domainAnalysis
            ?.domain
            ?.takeIf {
                it.isNotBlank()
            }
            ?.let {
                domains.add(it)
            }

        indicatorAnalysis
            ?.extractedUrls
            ?.forEach { url ->

                try {

                    val host =
                        java.net.URI(url)
                            .host

                    if (
                        !host.isNullOrBlank() &&
                        !domains.contains(host)
                    ) {

                        domains.add(host)
                    }

                } catch (_: Exception) {
                    // Ignore malformed URL.
                }
            }

        return domains
    }
}
