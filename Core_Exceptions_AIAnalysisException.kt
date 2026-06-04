package com.sentrix.core.exceptions

/**
 * AIAnalysisException
 *
 * Base exception for all AI, machine learning,
 * recommendation engine, threat intelligence,
 * and predictive analysis failures within SentriX.
 *
 * Used by:
 * - AIManager
 * - ThreatAnalysisHelper
 * - AIRecommendationHelper
 * - MalwareManager
 * - AnalyticsManager
 * - Security Intelligence Engine
 */
open class AIAnalysisException : Exception {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Generic AI analysis failure.
 */
class AIProcessingException(
    message: String = "AI analysis failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * AI model unavailable.
 */
class AIModelUnavailableException(
    message: String = "AI model unavailable."
) : AIAnalysisException(message)

/**
 * AI model loading failure.
 */
class AIModelLoadingException(
    message: String = "Failed to load AI model.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * AI inference failure.
 */
class AIInferenceException(
    message: String = "AI inference failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * AI prediction failure.
 */
class AIPredictionException(
    message: String = "Failed to generate AI prediction.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * AI recommendation generation failure.
 */
class AIRecommendationException(
    message: String = "Failed to generate recommendations.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Threat classification failure.
 */
class ThreatClassificationException(
    message: String = "Threat classification failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Malware classification failure.
 */
class MalwareClassificationException(
    message: String = "Malware classification failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Risk assessment failure.
 */
class RiskAssessmentException(
    message: String = "Risk assessment failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Security score calculation failure.
 */
class SecurityScoreException(
    message: String = "Security score calculation failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Anomaly detection failure.
 */
class AnomalyDetectionException(
    message: String = "Anomaly detection failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Behavioral analysis failure.
 */
class AIBehaviorAnalysisException(
    message: String = "Behavioral analysis failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Pattern recognition failure.
 */
class PatternRecognitionException(
    message: String = "Pattern recognition failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Threat correlation failure.
 */
class ThreatCorrelationException(
    message: String = "Threat correlation failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Threat intelligence analysis failure.
 */
class ThreatIntelligenceAnalysisException(
    message: String = "Threat intelligence analysis failed.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * AI confidence score too low.
 */
class LowConfidenceException(
    message: String = "AI confidence score below acceptable threshold."
) : AIAnalysisException(message)

/**
 * Invalid AI input data.
 */
class InvalidAIInputException(
    message: String = "Invalid AI input data."
) : AIAnalysisException(message)

/**
 * AI training data unavailable.
 */
class TrainingDataException(
    message: String = "Training data unavailable."
) : AIAnalysisException(message)

/**
 * AI resource exhaustion.
 */
class AIResourceException(
    message: String = "AI processing resources exhausted."
) : AIAnalysisException(message)

/**
 * Remote AI service unavailable.
 */
class RemoteAIServiceException(
    message: String = "Remote AI service unavailable.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * AI API communication failure.
 */
class AIServiceCommunicationException(
    message: String = "Failed to communicate with AI service.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Prompt validation failure.
 */
class PromptValidationException(
    message: String = "AI prompt validation failed."
) : AIAnalysisException(message)

/**
 * AI response parsing failure.
 */
class AIResponseParsingException(
    message: String = "Failed to parse AI response.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * AI hallucination detection.
 */
class AIHallucinationException(
    message: String = "Potential AI hallucination detected."
) : AIAnalysisException(message)

/**
 * Explainability analysis failure.
 */
class AIExplainabilityException(
    message: String = "Failed to generate explainable AI results.",
    cause: Throwable? = null
) : AIAnalysisException(message, cause)

/**
 * Model integrity validation failure.
 */
class AIModelIntegrityException(
    message: String = "AI model integrity validation failed."
) : AIAnalysisException(message)

/**
 * Critical AI subsystem failure.
 */
class CriticalAIException(
    message: String = "Critical AI subsystem failure."
) : AIAnalysisException(message)
