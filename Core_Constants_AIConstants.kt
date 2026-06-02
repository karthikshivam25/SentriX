package com.sentrix.core.constants

object AIConstants {

    /* ============================================================
     * AI ENGINE CONFIGURATION
     * ============================================================ */

    const val AI_ENGINE_NAME = "SentriX AI Engine"

    const val AI_MODEL_VERSION = "1.0.0"

    const val AI_CONFIDENCE_THRESHOLD = 0.85f

    /* ============================================================
     * MACHINE LEARNING MODELS
     * ============================================================ */

    const val MODEL_MALWARE_DETECTION =
        "model_malware_detection"

    const val MODEL_PHISHING_DETECTION =
        "model_phishing_detection"

    const val MODEL_PERMISSION_ANALYSIS =
        "model_permission_analysis"

    const val MODEL_NETWORK_ANALYSIS =
        "model_network_analysis"

    const val MODEL_BEHAVIOR_ANALYSIS =
        "model_behavior_analysis"

    /* ============================================================
     * AI THREAT PREDICTION
     * ============================================================ */

    const val PREDICTION_SAFE = "SAFE"
    const val PREDICTION_SUSPICIOUS = "SUSPICIOUS"
    const val PREDICTION_DANGEROUS = "DANGEROUS"
    const val PREDICTION_CRITICAL = "CRITICAL"

    /* ============================================================
     * AI ANALYSIS TYPES
     * ============================================================ */

    const val ANALYSIS_STATIC = "STATIC_ANALYSIS"
    const val ANALYSIS_DYNAMIC = "DYNAMIC_ANALYSIS"
    const val ANALYSIS_BEHAVIORAL = "BEHAVIORAL_ANALYSIS"
    const val ANALYSIS_HEURISTIC = "HEURISTIC_ANALYSIS"

    /* ============================================================
     * AI RESPONSE STATUS
     * ============================================================ */

    const val STATUS_ANALYZING = "ANALYZING"
    const val STATUS_COMPLETED = "COMPLETED"
    const val STATUS_FAILED = "FAILED"
    const val STATUS_TIMEOUT = "TIMEOUT"

    /* ============================================================
     * THREAT CLASSIFICATION
     * ============================================================ */

    const val CLASSIFICATION_BENIGN = "BENIGN"
    const val CLASSIFICATION_RISKWARE = "RISKWARE"
    const val CLASSIFICATION_MALWARE = "MALWARE"
    const val CLASSIFICATION_SPYWARE = "SPYWARE"
    const val CLASSIFICATION_RANSOMWARE = "RANSOMWARE"

    /* ============================================================
     * AI SCORING
     * ============================================================ */

    const val SCORE_SAFE_MIN = 0
    const val SCORE_SAFE_MAX = 20

    const val SCORE_LOW_MIN = 21
    const val SCORE_LOW_MAX = 40

    const val SCORE_MEDIUM_MIN = 41
    const val SCORE_MEDIUM_MAX = 60

    const val SCORE_HIGH_MIN = 61
    const val SCORE_HIGH_MAX = 80

    const val SCORE_CRITICAL_MIN = 81
    const val SCORE_CRITICAL_MAX = 100

    /* ============================================================
     * AI PERFORMANCE
     * ============================================================ */

    const val MAX_ANALYSIS_TIME_MS = 30_000L

    const val MAX_BATCH_SIZE = 100

    const val CACHE_AI_RESULTS = true

    /* ============================================================
     * NATURAL LANGUAGE PROCESSING
     * ============================================================ */

    const val NLP_LANGUAGE_ENGLISH = "en"
    const val NLP_LANGUAGE_TAMIL = "ta"
    const val NLP_LANGUAGE_HINDI = "hi"

    /* ============================================================
     * AI EVENT TAGS
     * ============================================================ */

    const val EVENT_AI_SCAN_STARTED =
        "EVENT_AI_SCAN_STARTED"

    const val EVENT_AI_SCAN_COMPLETED =
        "EVENT_AI_SCAN_COMPLETED"

    const val EVENT_AI_THREAT_DETECTED =
        "EVENT_AI_THREAT_DETECTED"

    const val EVENT_AI_MODEL_UPDATED =
        "EVENT_AI_MODEL_UPDATED"

    /* ============================================================
     * CLOUD AI CONFIGURATION
     * ============================================================ */

    const val CLOUD_AI_ENABLED = true

    const val CLOUD_AI_TIMEOUT = 20_000L

    const val CLOUD_AI_RETRY_COUNT = 3

    /* ============================================================
     * AI DATASETS
     * ============================================================ */

    const val DATASET_MALWARE =
        "dataset_malware"

    const val DATASET_NETWORK_TRAFFIC =
        "dataset_network_traffic"

    const val DATASET_PERMISSION_BEHAVIOR =
        "dataset_permission_behavior"

    /* ============================================================
     * AI SECURITY
     * ============================================================ */

    const val ENABLE_MODEL_ENCRYPTION = true

    const val ENABLE_SECURE_INFERENCE = true

    const val ENABLE_ADVERSARIAL_PROTECTION = true

    /* ============================================================
     * LOGGING
     * ============================================================ */

    const val AI_LOG_TAG = "SENTRIX_AI"

}
