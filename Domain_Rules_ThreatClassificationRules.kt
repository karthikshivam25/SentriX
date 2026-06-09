package com.sentrix.domain.rules

/**
 * SentriX Threat Classification Rules
 *
 * Responsible for classifying detected threats into
 * predefined security categories.
 */
object ThreatClassificationRules {

    enum class ThreatCategory {
        MALWARE,
        PHISHING,
        SCAM,
        SPYWARE,
        RANSOMWARE,
        ROOT_COMPROMISE,
        NETWORK_ATTACK,
        DATA_LEAK,
        SUSPICIOUS_BEHAVIOR,
        SAFE,
        UNKNOWN
    }

    /**
     * Classify threat based on threat indicators.
     */
    fun classifyThreat(
        malwareDetected: Boolean = false,
        phishingDetected: Boolean = false,
        scamDetected: Boolean = false,
        spywareDetected: Boolean = false,
        ransomwareDetected: Boolean = false,
        rootDetected: Boolean = false,
        networkAttackDetected: Boolean = false,
        dataLeakDetected: Boolean = false,
        suspiciousBehaviorDetected: Boolean = false
    ): ThreatCategory {

        return when {
            ransomwareDetected -> ThreatCategory.RANSOMWARE
            malwareDetected -> ThreatCategory.MALWARE
            phishingDetected -> ThreatCategory.PHISHING
            scamDetected -> ThreatCategory.SCAM
            spywareDetected -> ThreatCategory.SPYWARE
            rootDetected -> ThreatCategory.ROOT_COMPROMISE
            networkAttackDetected -> ThreatCategory.NETWORK_ATTACK
            dataLeakDetected -> ThreatCategory.DATA_LEAK
            suspiciousBehaviorDetected -> ThreatCategory.SUSPICIOUS_BEHAVIOR
            else -> ThreatCategory.SAFE
        }
    }

    /**
     * Classify threat from threat type string.
     */
    fun classifyThreat(threatType: String?): ThreatCategory {

        if (threatType.isNullOrBlank()) {
            return ThreatCategory.UNKNOWN
        }

        return when (threatType.trim().lowercase()) {

            "malware",
            "trojan",
            "virus",
            "worm",
            "adware" ->
                ThreatCategory.MALWARE

            "phishing",
            "credential theft",
            "fake login" ->
                ThreatCategory.PHISHING

            "scam",
            "fraud",
            "financial fraud" ->
                ThreatCategory.SCAM

            "spyware",
            "keylogger" ->
                ThreatCategory.SPYWARE

            "ransomware" ->
                ThreatCategory.RANSOMWARE

            "root",
            "root compromise",
            "rooted device" ->
                ThreatCategory.ROOT_COMPROMISE

            "network attack",
            "mitm",
            "dns spoofing",
            "packet injection" ->
                ThreatCategory.NETWORK_ATTACK

            "data leak",
            "data breach",
            "information disclosure" ->
                ThreatCategory.DATA_LEAK

            "suspicious behavior",
            "abnormal activity" ->
                ThreatCategory.SUSPICIOUS_BEHAVIOR

            "safe" ->
                ThreatCategory.SAFE

            else ->
                ThreatCategory.UNKNOWN
        }
    }

    /**
     * Returns true if the category represents an actual threat.
     */
    fun isThreat(category: ThreatCategory): Boolean {
        return category != ThreatCategory.SAFE &&
                category != ThreatCategory.UNKNOWN
    }

    /**
     * Returns threat display name.
     */
    fun getDisplayName(category: ThreatCategory): String {
        return when (category) {
            ThreatCategory.MALWARE -> "Malware"
            ThreatCategory.PHISHING -> "Phishing"
            ThreatCategory.SCAM -> "Scam"
            ThreatCategory.SPYWARE -> "Spyware"
            ThreatCategory.RANSOMWARE -> "Ransomware"
            ThreatCategory.ROOT_COMPROMISE -> "Root Compromise"
            ThreatCategory.NETWORK_ATTACK -> "Network Attack"
            ThreatCategory.DATA_LEAK -> "Data Leak"
            ThreatCategory.SUSPICIOUS_BEHAVIOR -> "Suspicious Behavior"
            ThreatCategory.SAFE -> "Safe"
            ThreatCategory.UNKNOWN -> "Unknown"
        }
    }

    /**
     * Returns recommended action.
     */
    fun getRecommendedAction(category: ThreatCategory): String {
        return when (category) {
            ThreatCategory.RANSOMWARE ->
                "Immediately isolate the device and initiate recovery procedures."

            ThreatCategory.MALWARE ->
                "Run deep scan and quarantine affected files."

            ThreatCategory.PHISHING ->
                "Block URL and warn the user."

            ThreatCategory.SCAM ->
                "Prevent interaction and notify the user."

            ThreatCategory.SPYWARE ->
                "Remove application and revoke permissions."

            ThreatCategory.ROOT_COMPROMISE ->
                "Restrict sensitive operations and alert user."

            ThreatCategory.NETWORK_ATTACK ->
                "Block connection and inspect network traffic."

            ThreatCategory.DATA_LEAK ->
                "Secure exposed data and notify affected users."

            ThreatCategory.SUSPICIOUS_BEHAVIOR ->
                "Monitor activity and increase security checks."

            ThreatCategory.SAFE ->
                "No action required."

            ThreatCategory.UNKNOWN ->
                "Further analysis required."
        }
    }
}
