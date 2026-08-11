package com.sentrix.security.phishing

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.max
import kotlin.math.min

/**
 * PhishingRiskEvaluator
 *
 * Central risk-scoring engine for the SentriX phishing subsystem.
 *
 * This component combines evidence produced by:
 *
 * - PhishingAnalyzer
 * - PhishingURLAnalyzer
 * - PhishingDomainAnalyzer
 * - PhishingContentAnalyzer
 * - PhishingPatternDetector
 * - PhishingIndicatorDetector
 *
 * Responsibilities:
 *
 * - Aggregate phishing evidence.
 * - Normalize individual risk scores.
 * - Apply configurable evidence weights.
 * - Detect strong indicator combinations.
 * - Apply confidence adjustments.
 * - Calculate a final phishing risk score.
 * - Classify the result.
 * - Recommend an appropriate security action.
 * - Generate human-readable risk explanations.
 *
 * This evaluator does NOT:
 *
 * - Perform network calls.
 * - Query threat-intelligence APIs.
 * - Modify device state.
 * - Block applications or URLs directly.
 *
 * It produces a decision recommendation.
 *
 * Architecture:
 *
 *                    ┌──────────────────────┐
 *                    │ PhishingAnalyzer     │
 *                    └──────────┬───────────┘
 *                               │
 *          ┌────────────────────┼────────────────────┐
 *          ▼                    ▼                    ▼
 *   URL Analyzer         Domain Analyzer      Content Analyzer
 *          │                    │                    │
 *          └────────────────────┼────────────────────┘
 *                               ▼
 *                  Pattern / Indicator Detectors
 *                               │
 *                               ▼
 *                    PhishingRiskEvaluator
 *                               │
 *                ┌──────────────┼──────────────┐
 *                ▼              ▼              ▼
 *             Score        Confidence       Decision
 *                │              │              │
 *                └──────────────┼──────────────┘
 *                               ▼
 *                     SentriX Security Layer
 */
class PhishingRiskEvaluator(
    private val configuration: PhishingRiskConfiguration =
        PhishingRiskConfiguration()
) {

    companion object {

        private const val TAG = "PhishingRiskEvaluator"

        private const val MAX_EVIDENCE_ITEMS = 250

        private const val SAFE_THRESHOLD = 0.25f
        private const val LOW_THRESHOLD = 0.45f
        private const val MEDIUM_THRESHOLD = 0.65f
        private const val HIGH_THRESHOLD = 0.85f

        /**
         * Maximum confidence.
         */
        private const val MAX_CONFIDENCE = 1.0f

        /**
         * Minimum confidence.
         */
        private const val MIN_CONFIDENCE = 0.0f
    }

    /**
     * Evaluates a complete phishing assessment.
     */
    suspend fun evaluate(
        input: PhishingRiskInput
    ): PhishingRiskEvaluation =
        withContext(Dispatchers.Default) {

            checkCancellation()

            Log.d(
                TAG,
                "Starting phishing risk evaluation."
            )

            val evidence =
                collectEvidence(input)

            checkCancellation()

            val weightedScore =
                calculateWeightedScore(
                    evidence
                )

            val combinationAdjustment =
                calculateCombinationAdjustment(
                    evidence
                )

            val severityAdjustment =
                calculateSeverityAdjustment(
                    evidence
                )

            val confidence =
                calculateConfidence(
                    evidence = evidence,
                    input = input
                )

            val finalScore =
                calculateFinalScore(
                    weightedScore = weightedScore,
                    combinationAdjustment = combinationAdjustment,
                    severityAdjustment = severityAdjustment,
                    confidence = confidence
                )

            val classification =
                classify(
                    score = finalScore
                )

            val decision =
                determineDecision(
                    classification = classification,
                    evidence = evidence,
                    input = input
                )

            val reasons =
                buildRiskReasons(
                    evidence = evidence,
                    classification = classification
                )

            val recommendations =
                buildRecommendations(
                    decision = decision,
                    classification = classification
                )

            val result =
                PhishingRiskEvaluation(
                    riskScore = finalScore,
                    classification = classification,
                    confidence = confidence,
                    decision = decision,
                    evidence = evidence,
                    primaryReasons = reasons,
                    recommendations = recommendations
                )

            Log.d(
                TAG,
                "Phishing risk evaluation completed. " +
                        "score=${result.riskScore}, " +
                        "classification=${result.classification}, " +
                        "confidence=${result.confidence}, " +
                        "decision=${result.decision}"
            )

            result
        }

    /**
     * Convenience evaluation using content analysis.
     */
    suspend fun evaluateContent(
        contentAnalysis: PhishingContentAnalysis,
        patternAnalysis: PhishingPatternDetectionResult? = null,
        indicatorAnalysis: PhishingIndicatorDetectionResult? = null
    ): PhishingRiskEvaluation {

        return evaluate(
            PhishingRiskInput(
                contentAnalysis = contentAnalysis,
                patternAnalysis = patternAnalysis,
                indicatorAnalysis = indicatorAnalysis
            )
        )
    }

    /**
     * Convenience evaluation using URL analysis.
     */
    suspend fun evaluateUrl(
        urlAnalysis: PhishingURLAnalysis
    ): PhishingRiskEvaluation {

        return evaluate(
            PhishingRiskInput(
                urlAnalysis = urlAnalysis
            )
        )
    }

    /**
     * Convenience evaluation using domain analysis.
     */
    suspend fun evaluateDomain(
        domainAnalysis: PhishingDomainAnalysis
    ): PhishingRiskEvaluation {

        return evaluate(
            PhishingRiskInput(
                domainAnalysis = domainAnalysis
            )
        )
    }

    /**
     * Evaluates an individual score using the configured thresholds.
     */
    fun classifyRisk(
        score: Float
    ): PhishingRiskClassification {

        return classify(
            score.coerceIn(
                0.0f,
                1.0f
            )
        )
    }

    /**
     * Returns the recommended action for a risk score.
     */
    fun recommendAction(
        score: Float
    ): PhishingRiskDecision {

        return when (
            classifyRisk(score)
        ) {

            PhishingRiskClassification.SAFE ->
                PhishingRiskDecision.ALLOW

            PhishingRiskClassification.LOW ->
                PhishingRiskDecision.MONITOR

            PhishingRiskClassification.MEDIUM ->
                PhishingRiskDecision.WARN

            PhishingRiskClassification.HIGH ->
                PhishingRiskDecision.BLOCK
        }
    }

    /**
     * Collects all available evidence.
     */
    private fun collectEvidence(
        input: PhishingRiskInput
    ): List<PhishingRiskEvidence> {

        val evidence =
            mutableListOf<PhishingRiskEvidence>()

        input.urlAnalysis?.let { analysis ->

            evidence.add(
                PhishingRiskEvidence(
                    source =
                        PhishingEvidenceSource.URL_ANALYZER,
                    score =
                        analysis.riskScore,
                    severity =
                        mapClassificationSeverity(
                            analysis.classification.name
                        ),
                    description =
                        "URL analysis produced a ${analysis.classification} risk assessment.",
                    weight =
                        configuration.urlWeight
                )
            )

            analysis.findings
                .take(MAX_EVIDENCE_ITEMS)
                .forEach { finding ->

                    evidence.add(
                        PhishingRiskEvidence(
                            source =
                                PhishingEvidenceSource.URL_ANALYZER,
                            score =
                                finding.score,
                            severity =
                                mapUrlSeverity(
                                    finding.severity
                                ),
                            description =
                                finding.description,
                            weight =
                                configuration.urlFindingWeight
                        )
                    )
                }
        }

        input.domainAnalysis?.let { analysis ->

            evidence.add(
                PhishingRiskEvidence(
                    source =
                        PhishingEvidenceSource.DOMAIN_ANALYZER,
                    score =
                        analysis.riskScore,
                    severity =
                        mapClassificationSeverity(
                            analysis.classification.name
                        ),
                    description =
                        "Domain analysis produced a ${analysis.classification} risk assessment.",
                    weight =
                        configuration.domainWeight
                )
            )

            analysis.findings
                .take(MAX_EVIDENCE_ITEMS)
                .forEach { finding ->

                    evidence.add(
                        PhishingRiskEvidence(
                            source =
                                PhishingEvidenceSource.DOMAIN_ANALYZER,
                            score =
                                finding.score,
                            severity =
                                mapDomainSeverity(
                                    finding.severity
                                ),
                            description =
                                finding.description,
                            weight =
                                configuration.domainFindingWeight
                        )
                    )
                }
        }

        input.contentAnalysis?.let { analysis ->

            evidence.add(
                PhishingRiskEvidence(
                    source =
                        PhishingEvidenceSource.CONTENT_ANALYZER,
                    score =
                        analysis.riskScore,
                    severity =
                        mapClassificationSeverity(
                            analysis.classification.name
                        ),
                    description =
                        "Content analysis produced a ${analysis.classification} risk assessment.",
                    weight =
                        configuration.contentWeight
                )
            )

            analysis.findings
                .take(MAX_EVIDENCE_ITEMS)
                .forEach { finding ->

                    evidence.add(
                        PhishingRiskEvidence(
                            source =
                                PhishingEvidenceSource.CONTENT_ANALYZER,
                            score =
                                finding.score,
                            severity =
                                mapContentSeverity(
                                    finding.severity
                                ),
                            description =
                                finding.description,
                            weight =
                                configuration.contentFindingWeight
                        )
                    )
                }
        }

        input.patternAnalysis?.let { analysis ->

            evidence.add(
                PhishingRiskEvidence(
                    source =
                        PhishingEvidenceSource.PATTERN_DETECTOR,
                    score =
                        analysis.riskScore,
                    severity =
                        mapClassificationSeverity(
                            analysis.classification.name
                        ),
                    description =
                        "Pattern analysis produced a ${analysis.classification} risk assessment.",
                    weight =
                        configuration.patternWeight
                )
            )

            analysis.findings
                .take(MAX_EVIDENCE_ITEMS)
                .forEach { finding ->

                    evidence.add(
                        PhishingRiskEvidence(
                            source =
                                PhishingEvidenceSource.PATTERN_DETECTOR,
                            score =
                                finding.score,
                            severity =
                                mapPatternSeverity(
                                    finding.severity
                                ),
                            description =
                                finding.description,
                            weight =
                                configuration.patternFindingWeight
                        )
                    )
                }
        }

        input.indicatorAnalysis?.let { analysis ->

            evidence.add(
                PhishingRiskEvidence(
                    source =
                        PhishingEvidenceSource.INDICATOR_DETECTOR,
                    score =
                        analysis.riskScore,
                    severity =
                        mapClassificationSeverity(
                            analysis.classification.name
                        ),
                    description =
                        "Indicator analysis produced a ${analysis.classification} risk assessment.",
                    weight =
                        configuration.indicatorWeight
                )
            )

            analysis.indicators
                .take(MAX_EVIDENCE_ITEMS)
                .forEach { finding ->

                    evidence.add(
                        PhishingRiskEvidence(
                            source =
                                PhishingEvidenceSource.INDICATOR_DETECTOR,
                            score =
                                finding.score,
                            severity =
                                mapIndicatorSeverity(
                                    finding.severity
                                ),
                            description =
                                finding.description,
                            weight =
                                configuration.indicatorFindingWeight
                        )
                    )
                }
        }

        input.externalSignals
            .take(MAX_EVIDENCE_ITEMS)
            .forEach { signal ->

                evidence.add(
                    PhishingRiskEvidence(
                        source =
                            PhishingEvidenceSource.EXTERNAL_SIGNAL,
                        score =
                            signal.score,
                        severity =
                            signal.severity,
                        description =
                            signal.description,
                        weight =
                            signal.weight
                    )
                )
            }

        return evidence
            .sortedByDescending {
                it.score * it.weight
            }
            .take(MAX_EVIDENCE_ITEMS)
    }

    /**
     * Calculates the weighted base score.
     *
     * A weighted average is used instead of simply adding all findings.
     * This prevents a large number of low-value findings from
     * automatically producing a HIGH classification.
     */
    private fun calculateWeightedScore(
        evidence: List<PhishingRiskEvidence>
    ): Float {

        if (evidence.isEmpty()) {
            return 0.0f
        }

        val weightedSum =
            evidence.sumOf {
                (
                    it.score *
                            it.weight
                    ).toDouble()
            }

        val totalWeight =
            evidence.sumOf {
                it.weight.toDouble()
            }

        if (totalWeight <= 0.0) {
            return 0.0f
        }

        return (
            weightedSum /
                    totalWeight
            )
            .toFloat()
            .coerceIn(
                0.0f,
                1.0f
            )
    }

    /**
     * Calculates additional score for corroborating evidence.
     *
     * Example:
     *
     * suspicious content
     * +
     * suspicious URL
     * +
     * suspicious domain
     *
     * is stronger than any individual signal.
     */
    private fun calculateCombinationAdjustment(
        evidence: List<PhishingRiskEvidence>
    ): Float {

        val sources =
            evidence
                .filter {
                    it.score >=
                            configuration
                                .strongEvidenceThreshold
                }
                .map {
                    it.source
                }
                .toSet()

        var adjustment =
            0.0f

        if (
            sources.contains(
                PhishingEvidenceSource.CONTENT_ANALYZER
            ) &&
            sources.contains(
                PhishingEvidenceSource.URL_ANALYZER
            )
        ) {

            adjustment +=
                configuration.contentUrlCombinationBonus
        }

        if (
            sources.contains(
                PhishingEvidenceSource.URL_ANALYZER
            ) &&
            sources.contains(
                PhishingEvidenceSource.DOMAIN_ANALYZER
            )
        ) {

            adjustment +=
                configuration.urlDomainCombinationBonus
        }

        if (
            sources.contains(
                PhishingEvidenceSource.PATTERN_DETECTOR
            ) &&
            sources.contains(
                PhishingEvidenceSource.INDICATOR_DETECTOR
            )
        ) {

            adjustment +=
                configuration.patternIndicatorCombinationBonus
        }

        if (
            sources.size >= 4
        ) {

            adjustment +=
                configuration.multiSourceBonus
        }

        return adjustment
    }

    /**
     * Calculates adjustment based on critical/high evidence.
     */
    private fun calculateSeverityAdjustment(
        evidence: List<PhishingRiskEvidence>
    ): Float {

        if (evidence.isEmpty()) {
            return 0.0f
        }

        val critical =
            evidence.count {
                it.severity ==
                        PhishingEvidenceSeverity.CRITICAL
            }

        val high =
            evidence.count {
                it.severity ==
                        PhishingEvidenceSeverity.HIGH
            }

        var adjustment =
            0.0f

        if (
            critical >= 1
        ) {

            adjustment +=
                configuration.criticalEvidenceBonus
        }

        if (
            critical >= 2
        ) {

            adjustment +=
                configuration.multipleCriticalBonus
        }

        if (
            high >= 3
        ) {

            adjustment +=
                configuration.multipleHighBonus
        }

        return adjustment
    }

    /**
     * Calculates confidence in the evaluation.
     */
    private fun calculateConfidence(
        evidence: List<PhishingRiskEvidence>,
        input: PhishingRiskInput
    ): Float {

        if (evidence.isEmpty()) {
            return MIN_CONFIDENCE
        }

        val sourceCount =
            evidence
                .map {
                    it.source
                }
                .distinct()
                .size

        val strongEvidenceCount =
            evidence.count {
                it.score >=
                        configuration
                            .strongEvidenceThreshold
            }

        val criticalEvidenceCount =
            evidence.count {
                it.severity ==
                        PhishingEvidenceSeverity.CRITICAL
            }

        var confidence =
            configuration.baseConfidence

        /*
         * More independent evidence sources increase confidence.
         */
        confidence +=
            sourceCount *
                    configuration
                        .sourceConfidenceIncrement

        confidence +=
            min(
                strongEvidenceCount *
                        configuration
                            .strongEvidenceConfidenceIncrement,
                0.20f
            )

        confidence +=
            min(
                criticalEvidenceCount *
                        configuration
                            .criticalEvidenceConfidenceIncrement,
                0.20f
            )

        /*
         * A complete analysis is more trustworthy than a partial
         * analysis.
         */
        if (
            input.urlAnalysis != null &&
            input.domainAnalysis != null
        ) {

            confidence +=
                configuration
                    .urlDomainCompletenessBonus
        }

        if (
            input.contentAnalysis != null &&
            input.patternAnalysis != null
        ) {

            confidence +=
                configuration
                    .contentPatternCompletenessBonus
        }

        return confidence.coerceIn(
            MIN_CONFIDENCE,
            MAX_CONFIDENCE
        )
    }

    /**
     * Produces the final risk score.
     *
     * Confidence prevents weak/partial evidence from reaching
     * maximum certainty.
     */
    private fun calculateFinalScore(
        weightedScore: Float,
        combinationAdjustment: Float,
        severityAdjustment: Float,
        confidence: Float
    ): Float {

        val adjusted =
            weightedScore +
                    combinationAdjustment +
                    severityAdjustment

        /*
         * Preserve a minimum amount of evidence-driven risk while
         * reducing confidence in incomplete analyses.
         */
        val confidenceFactor =
            0.50f +
                    (
                        confidence *
                                0.50f
                        )

        return (
            adjusted *
                    confidenceFactor
            ).coerceIn(
                0.0f,
                1.0f
            )
        )
    }

    /**
     * Converts final score to classification.
     */
    private fun classify(
        score: Float
    ): PhishingRiskClassification {

        return when {

            score >= HIGH_THRESHOLD ->
                PhishingRiskClassification.HIGH

            score >= MEDIUM_THRESHOLD ->
                PhishingRiskClassification.MEDIUM

            score >= LOW_THRESHOLD ->
                PhishingRiskClassification.LOW

            else ->
                PhishingRiskClassification.SAFE
        }
    }

    /**
     * Determines the recommended security action.
     */
    private fun determineDecision(
        classification: PhishingRiskClassification,
        evidence: List<PhishingRiskEvidence>,
        input: PhishingRiskInput
    ): PhishingRiskDecision {

        val hasCriticalEvidence =
            evidence.any {
                it.severity ==
                        PhishingEvidenceSeverity.CRITICAL
            }

        val hasStrongMultiSourceEvidence =
            evidence
                .filter {
                    it.score >=
                            configuration
                                .strongEvidenceThreshold
                }
                .map {
                    it.source
                }
                .distinct()
                .size >= 2

        return when {

            classification ==
                    PhishingRiskClassification.HIGH -> {

                if (
                    hasCriticalEvidence ||
                    hasStrongMultiSourceEvidence ||
                    configuration
                        .allowHighRiskBlocking
                ) {

                    PhishingRiskDecision.BLOCK

                } else {

                    PhishingRiskDecision.WARN
                }
            }

            classification ==
                    PhishingRiskClassification.MEDIUM -> {

                if (
                    hasCriticalEvidence &&
                    configuration
                        .allowMediumRiskBlocking
                ) {

                    PhishingRiskDecision.BLOCK

                } else {

                    PhishingRiskDecision.WARN
                }
            }

            classification ==
                    PhishingRiskClassification.LOW -> {

                PhishingRiskDecision.MONITOR
            }

            else -> {

                PhishingRiskDecision.ALLOW
            }
        }
    }

    /**
     * Generates primary risk explanations.
     */
    private fun buildRiskReasons(
        evidence: List<PhishingRiskEvidence>,
        classification: PhishingRiskClassification
    ): List<String> {

        if (
            evidence.isEmpty()
        ) {

            return listOf(
                "No significant phishing indicators were detected."
            )
        }

        val reasons =
            evidence
                .sortedByDescending {
                    it.score * it.weight
                }
                .take(
                    configuration
                        .maxRiskReasons
                )
                .map {
                    it.description
                }
                .distinct()

        if (
            reasons.isEmpty()
        ) {

            return listOf(
                "No significant phishing indicators were detected."
            )
        }

        return reasons
    }

    /**
     * Generates action recommendations.
     */
    private fun buildRecommendations(
        decision: PhishingRiskDecision,
        classification: PhishingRiskClassification
    ): List<PhishingRiskRecommendation> {

        return when (decision) {

            PhishingRiskDecision.ALLOW -> {

                listOf(
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.NO_ACTION,
                        message =
                            "No immediate phishing action is required."
                    )
                )
            }

            PhishingRiskDecision.MONITOR -> {

                listOf(
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.MONITOR,
                        message =
                            "Continue monitoring the content, sender, URL, or domain."
                    ),
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.AVOID_SENSITIVE_ACTIONS,
                        message =
                            "Avoid entering passwords, OTPs, PINs, or financial information until the source is verified."
                    )
                )
            }

            PhishingRiskDecision.WARN -> {

                listOf(
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.USER_WARNING,
                        message =
                            "Warn the user before opening the link or performing the requested action."
                    ),
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.VERIFY_SOURCE,
                        message =
                            "Verify the sender and organization through an independent trusted channel."
                    ),
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.AVOID_SENSITIVE_ACTIONS,
                        message =
                            "Do not provide passwords, OTPs, PINs, card details, or other sensitive information."
                    )
                )
            }

            PhishingRiskDecision.BLOCK -> {

                listOf(
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.BLOCK_CONTENT,
                        message =
                            "Prevent the suspicious content or link from being opened."
                    ),
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.ISOLATE_THREAT,
                        message =
                            "Isolate the suspicious resource from normal user interaction."
                    ),
                    PhishingRiskRecommendation(
                        type =
                            PhishingRecommendationType.REPORT_THREAT,
                        message =
                            "Record the event for SentriX security telemetry and threat intelligence."
                    )
                )
            }
        }
    }

    /**
     * Maps URL classification to common severity.
     */
    private fun mapUrlSeverity(
        severity: PhishingURLSeverity
    ): PhishingEvidenceSeverity {

        return when (severity) {

            PhishingURLSeverity.LOW ->
                PhishingEvidenceSeverity.LOW

            PhishingURLSeverity.MEDIUM ->
                PhishingEvidenceSeverity.MEDIUM

            PhishingURLSeverity.HIGH ->
                PhishingEvidenceSeverity.HIGH

            PhishingURLSeverity.CRITICAL ->
                PhishingEvidenceSeverity.CRITICAL
        }
    }

    /**
     * Maps domain classification severity.
     */
    private fun mapDomainSeverity(
        severity: PhishingDomainSeverity
    ): PhishingEvidenceSeverity {

        return when (severity) {

            PhishingDomainSeverity.LOW ->
                PhishingEvidenceSeverity.LOW

            PhishingDomainSeverity.MEDIUM ->
                PhishingEvidenceSeverity.MEDIUM

            PhishingDomainSeverity.HIGH ->
                PhishingEvidenceSeverity.HIGH

            PhishingDomainSeverity.CRITICAL ->
                PhishingEvidenceSeverity.CRITICAL
        }
    }

    /**
     * Maps content classification severity.
     */
    private fun mapContentSeverity(
        severity: PhishingContentSeverity
    ): PhishingEvidenceSeverity {

        return when (severity) {

            PhishingContentSeverity.LOW ->
                PhishingEvidenceSeverity.LOW

            PhishingContentSeverity.MEDIUM ->
                PhishingEvidenceSeverity.MEDIUM

            PhishingContentSeverity.HIGH ->
                PhishingEvidenceSeverity.HIGH

            PhishingContentSeverity.CRITICAL ->
                PhishingEvidenceSeverity.CRITICAL
        }
    }

    /**
     * Maps pattern classification severity.
     */
    private fun mapPatternSeverity(
        severity: PhishingPatternSeverity
    ): PhishingEvidenceSeverity {

        return when (severity) {

            PhishingPatternSeverity.LOW ->
                PhishingEvidenceSeverity.LOW

            PhishingPatternSeverity.MEDIUM ->
                PhishingEvidenceSeverity.MEDIUM

            PhishingPatternSeverity.HIGH ->
                PhishingEvidenceSeverity.HIGH

            PhishingPatternSeverity.CRITICAL ->
                PhishingEvidenceSeverity.CRITICAL
        }
    }

    /**
     * Maps indicator classification severity.
     */
    private fun mapIndicatorSeverity(
        severity: PhishingIndicatorSeverity
    ): PhishingEvidenceSeverity {

        return when (severity) {

            PhishingIndicatorSeverity.LOW ->
                PhishingEvidenceSeverity.LOW

            PhishingIndicatorSeverity.MEDIUM ->
                PhishingEvidenceSeverity.MEDIUM

            PhishingIndicatorSeverity.HIGH ->
                PhishingEvidenceSeverity.HIGH

            PhishingIndicatorSeverity.CRITICAL ->
                PhishingEvidenceSeverity.CRITICAL
        }
    }

    /**
     * Maps a generic classification name to evidence severity.
     *
     * This method keeps the evaluator resilient if the individual
     * analyzer classification enums remain separate.
     */
    private fun mapClassificationSeverity(
        classification: String
    ): PhishingEvidenceSeverity {

        return when (
            classification.uppercase()
        ) {

            "HIGH" ->
                PhishingEvidenceSeverity.HIGH

            "MEDIUM" ->
                PhishingEvidenceSeverity.MEDIUM

            "LOW" ->
                PhishingEvidenceSeverity.LOW

            else ->
                PhishingEvidenceSeverity.LOW
        }
    }

    /**
     * Coroutine cancellation support.
     */
    private suspend fun checkCancellation() {

        if (
            !kotlinx.coroutines
                .currentCoroutineContext()
                .isActive
        ) {

            throw CancellationException(
                "Phishing risk evaluation was cancelled."
            )
        }
    }
}

/**
 * Input supplied to PhishingRiskEvaluator.
 *
 * Any combination of analysis results may be supplied.
 */
data class PhishingRiskInput(

    val urlAnalysis:
        PhishingURLAnalysis? = null,

    val domainAnalysis:
        PhishingDomainAnalysis? = null,

    val contentAnalysis:
        PhishingContentAnalysis? = null,

    val patternAnalysis:
        PhishingPatternDetectionResult? = null,

    val indicatorAnalysis:
        PhishingIndicatorDetectionResult? = null,

    val externalSignals:
        List<PhishingExternalSignal> = emptyList()
)

/**
 * External threat/reputation signal.
 *
 * This allows future integration with:
 *
 * - SentriX Cloud Threat Intelligence
 * - Google Safe Browsing
 * - VirusTotal-like providers
 * - Enterprise threat feeds
 * - ML models
 * - Internal reputation services
 */
data class PhishingExternalSignal(

    val source:
        String,

    val score:
        Float,

    val severity:
        PhishingEvidenceSeverity,

    val weight:
        Float = 1.0f,

    val description:
        String
)

/**
 * Internal normalized evidence item.
 */
data class PhishingRiskEvidence(

    val source:
        PhishingEvidenceSource,

    val score:
        Float,

    val severity:
        PhishingEvidenceSeverity,

    val description:
        String,

    val weight:
        Float
)

/**
 * Final phishing risk evaluation.
 */
data class PhishingRiskEvaluation(

    /**
     * Final normalized risk score.
     *
     * 0.0 = minimal risk
     * 1.0 = maximum risk
     */
    val riskScore:
        Float,

    /**
     * Overall classification.
     */
    val classification:
        PhishingRiskClassification,

    /**
     * Confidence in the evaluation.
     */
    val confidence:
        Float,

    /**
     * Recommended security action.
     */
    val decision:
        PhishingRiskDecision,

    /**
     * Evidence used to reach the decision.
     */
    val evidence:
        List<PhishingRiskEvidence>,

    /**
     * Main human-readable reasons.
     */
    val primaryReasons:
        List<String>,

    /**
     * Recommended follow-up actions.
     */
    val recommendations:
        List<PhishingRiskRecommendation>
)

/**
 * Overall phishing risk classification.
 */
enum class PhishingRiskClassification {

    SAFE,

    LOW,

    MEDIUM,

    HIGH
}

/**
 * Recommended security action.
 */
enum class PhishingRiskDecision {

    /**
     * Resource is considered safe enough to proceed.
     */
    ALLOW,

    /**
     * Continue observation without interrupting the user.
     */
    MONITOR,

    /**
     * Require a warning/confirmation before proceeding.
     */
    WARN,

    /**
     * Prevent interaction with the suspicious resource.
     */
    BLOCK
}

/**
 * Evidence source.
 */
enum class PhishingEvidenceSource {

    URL_ANALYZER,

    DOMAIN_ANALYZER,

    CONTENT_ANALYZER,

    PATTERN_DETECTOR,

    INDICATOR_DETECTOR,

    EXTERNAL_SIGNAL
}

/**
 * Normalized evidence severity.
 */
enum class PhishingEvidenceSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Recommended user/security action.
 */
data class PhishingRiskRecommendation(

    val type:
        PhishingRecommendationType,

    val message:
        String
)

/**
 * Recommendation types.
 */
enum class PhishingRecommendationType {

    NO_ACTION,

    MONITOR,

    USER_WARNING,

    VERIFY_SOURCE,

    AVOID_SENSITIVE_ACTIONS,

    BLOCK_CONTENT,

    ISOLATE_THREAT,

    REPORT_THREAT
)

/**
 * Configuration for phishing risk evaluation.
 *
 * Keeping these values configurable is important because SentriX
 * should eventually be able to tune risk scoring per deployment.
 */
data class PhishingRiskConfiguration(

    /**
     * High-level analyzer weights.
     */
    val urlWeight:
        Float = 1.20f,

    val domainWeight:
        Float = 1.25f,

    val contentWeight:
        Float = 1.00f,

    val patternWeight:
        Float = 1.10f,

    val indicatorWeight:
        Float = 1.10f,

    /**
     * Individual finding weights.
     */
    val urlFindingWeight:
        Float = 0.80f,

    val domainFindingWeight:
        Float = 0.85f,

    val contentFindingWeight:
        Float = 0.80f,

    val patternFindingWeight:
        Float = 0.90f,

    val indicatorFindingWeight:
        Float = 0.90f,

    /**
     * External intelligence weighting.
     */
    val externalSignalWeight:
        Float = 1.50f,

    /**
     * Score required for evidence to be considered strong.
     */
    val strongEvidenceThreshold:
        Float = 0.20f,

    /**
     * Multi-source score bonuses.
     */
    val contentUrlCombinationBonus:
        Float = 0.10f,

    val urlDomainCombinationBonus:
        Float = 0.12f,

    val patternIndicatorCombinationBonus:
        Float = 0.10f,

    val multiSourceBonus:
        Float = 0.08f,

    /**
     * Severity bonuses.
     */
    val criticalEvidenceBonus:
        Float = 0.12f,

    val multipleCriticalBonus:
        Float = 0.10f,

    val multipleHighBonus:
        Float = 0.08f,

    /**
     * Confidence calculation.
     */
    val baseConfidence:
        Float = 0.35f,

    val sourceConfidenceIncrement:
        Float = 0.08f,

    val strongEvidenceConfidenceIncrement:
        Float = 0.04f,

    val criticalEvidenceConfidenceIncrement:
        Float = 0.05f,

    val urlDomainCompletenessBonus:
        Float = 0.08f,

    val contentPatternCompletenessBonus:
        Float = 0.06f,

    /**
     * Number of primary reasons exposed to callers.
     */
    val maxRiskReasons:
        Int = 5,

    /**
     * Whether high-risk content can be blocked.
     */
    val allowHighRiskBlocking:
        Boolean = true,

    /**
     * Whether medium-risk content can be blocked when a
     * critical signal exists.
     */
    val allowMediumRiskBlocking:
        Boolean = false
)
