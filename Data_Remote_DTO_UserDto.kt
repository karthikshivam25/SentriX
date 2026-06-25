package com.sentrix.data.remote.dto

import com.google.gson.annotations.SerializedName

/**
 * ThreatDto
 *
 * Data Transfer Object used to represent threat information
 * received from or sent to the SentriX backend API.
 *
 * This DTO is primarily used by:
 * - ThreatApiService
 * - ThreatRepository
 * - ThreatAnalysisService
 * - CyberDefenseService
 * - RiskScoringService
 *
 * Note:
 * DTOs should only be used in the data layer.
 * They should be mapped to Domain models before
 * being used in business logic.
 */
data class ThreatDto(

    /**
     * Unique threat identifier.
     */
    @SerializedName("threat_id")
    val threatId: String,

    /**
     * Name of the detected threat.
     *
     * Example:
     * "Android.Banker.XYZ"
     */
    @SerializedName("threat_name")
    val threatName: String,

    /**
     * Threat category.
     *
     * Examples:
     * MALWARE
     * PHISHING
     * SPYWARE
     * RANSOMWARE
     */
    @SerializedName("category")
    val category: String,

    /**
     * Threat severity level.
     *
     * Examples:
     * LOW
     * MEDIUM
     * HIGH
     * CRITICAL
     */
    @SerializedName("severity")
    val severity: String,

    /**
     * Numerical risk score assigned by
     * the SentriX Threat Intelligence Engine.
     *
     * Range: 0 - 100
     */
    @SerializedName("risk_score")
    val riskScore: Int,

    /**
     * Human-readable threat description.
     */
    @SerializedName("description")
    val description: String,

    /**
     * Indicates whether the threat is currently active.
     */
    @SerializedName("is_active")
    val isActive: Boolean,

    /**
     * Recommended mitigation or remediation steps.
     */
    @SerializedName("recommended_action")
    val recommendedAction: String,

    /**
     * Source of threat intelligence.
     *
     * Examples:
     * SentriX Cloud
     * VirusTotal
     * Local Scanner
     */
    @SerializedName("source")
    val source: String,

    /**
     * Timestamp when the threat was detected.
     * Stored as Unix timestamp in milliseconds.
     */
    @SerializedName("detected_at")
    val detectedAt: Long,

    /**
     * Timestamp when the threat information
     * was last updated.
     */
    @SerializedName("updated_at")
    val updatedAt: Long
)
