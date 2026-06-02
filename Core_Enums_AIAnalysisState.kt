package com.sentrix.core.enums

/**
 * Represents AI analysis lifecycle states in SentriX
 */
enum class AIAnalysisState(
    val displayName: String,
    val description: String
) {

    IDLE(
        displayName = "Idle",
        description = "AI engine is inactive"
    ),

    INITIALIZING(
        displayName = "Initializing",
        description = "Preparing AI models and analysis environment"
    ),

    COLLECTING_DATA(
        displayName = "Collecting Data",
        description = "Gathering telemetry and behavioral information"
    ),

    PREPROCESSING(
        displayName = "Preprocessing",
        description = "Cleaning and preparing data for AI analysis"
    ),

    ANALYZING(
        displayName = "Analyzing",
        description = "Running AI-powered threat and behavior analysis"
    ),

    DETECTING_ANOMALIES(
        displayName = "Detecting Anomalies",
        description = "Searching for abnormal or suspicious patterns"
    ),

    CLASSIFYING_THREATS(
        displayName = "Classifying Threats",
        description = "Categorizing detected threats using AI models"
    ),

    PREDICTING_RISK(
        displayName = "Predicting Risk",
        description = "Estimating potential security risks and impact"
    ),

    GENERATING_REPORT(
        displayName = "Generating Report",
        description = "Preparing AI insights and analysis summaries"
    ),

    OPTIMIZING_MODELS(
        displayName = "Optimizing Models",
        description = "Improving AI model accuracy and performance"
    ),

    COMPLETED(
        displayName = "Completed",
        description = "AI analysis finished successfully"
    ),

    COMPLETED_WITH_WARNINGS(
        displayName = "Completed With Warnings",
        description = "AI analysis completed with detected concerns"
    ),

    FAILED(
        displayName = "Failed",
        description = "AI analysis process failed"
    ),

    CANCELLED(
        displayName = "Cancelled",
        description = "AI analysis was cancelled"
    ),

    ERROR(
        displayName = "Error",
        description = "Unexpected AI engine error occurred"
    );

    /**
     * Returns true if AI engine is actively processing
     */
    fun isProcessing(): Boolean {
        return this == INITIALIZING ||
               this == COLLECTING_DATA ||
               this == PREPROCESSING ||
               this == ANALYZING ||
               this == DETECTING_ANOMALIES ||
               this == CLASSIFYING_THREATS ||
               this == PREDICTING_RISK ||
               this == GENERATING_REPORT ||
               this == OPTIMIZING_MODELS
    }

    /**
     * Returns true if analysis finished
     */
    fun isFinished(): Boolean {
        return this == COMPLETED ||
               this == COMPLETED_WITH_WARNINGS ||
               this == FAILED ||
               this == CANCELLED ||
               this == ERROR
    }

    /**
     * Returns true if issues occurred during analysis
     */
    fun hasErrors(): Boolean {
        return this == FAILED ||
               this == ERROR
    }

    /**
     * Returns true if warnings were detected
     */
    fun hasWarnings(): Boolean {
        return this == COMPLETED_WITH_WARNINGS
    }
}
