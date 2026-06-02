package com.sentrix.core.enums

enum class ThreatLevel(
    val level: Int,
    val displayName: String,
    val severity: String,
    val colorHex: String
) {

    SAFE(
        level = 0,
        displayName = "Safe",
        severity = "LOW",
        colorHex = "#00C853"
    ),

    LOW(
        level = 1,
        displayName = "Low Risk",
        severity = "LOW",
        colorHex = "#64DD17"
    ),

    MEDIUM(
        level = 2,
        displayName = "Medium Risk",
        severity = "MEDIUM",
        colorHex = "#FFD600"
    ),

    HIGH(
        level = 3,
        displayName = "High Risk",
        severity = "HIGH",
        colorHex = "#FF6D00"
    ),

    CRITICAL(
        level = 4,
        displayName = "Critical Threat",
        severity = "CRITICAL",
        colorHex = "#D50000"
    );

    companion object {

        fun fromLevel(level: Int): ThreatLevel {
            return values().find { it.level == level }
                ?: SAFE
        }

        fun fromSeverity(severity: String): ThreatLevel {
            return values().find {
                it.severity.equals(severity, true)
            } ?: SAFE
        }
    }
}
