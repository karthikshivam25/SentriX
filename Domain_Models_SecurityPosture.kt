package com.sentrix.domain.models

/**
 * SecurityPosture
 *
 * Represents the overall security posture
 * assessment of a user, device, organization,
 * or managed environment within the SentriX
 * cybersecurity platform.
 *
 * Security posture provides a comprehensive
 * evaluation of protection effectiveness,
 * risk exposure, compliance status, threat
 * readiness, and security maturity.
 *
 * Used by:
 * - SecurityDashboard
 * - CyberDefenseManager
 * - ComplianceManager
 * - RiskAssessmentEngine
 * - ThreatAnalysisManager
 * - ExecutiveReportingService
 * - SecurityAnalyticsEngine
 * - AIRecommendationEngine
 */
data class SecurityPosture(

    /**
     * Unique posture identifier.
     */
    val postureId: String,

    /**
     * Entity identifier associated
     * with this posture assessment.
     */
    val entityId: String,

    /**
     * Entity type being assessed.
     */
    val entityType: SecurityEntityType,

    /**
     * Assessment timestamp.
     */
    val assessedAt: Long,

    /**
     * Overall security score.
     *
     * Range:
     * 0 - 100
     */
    val securityScore: Int,

    /**
     * Overall risk score.
     *
     * Higher values indicate
     * greater risk exposure.
     */
    val riskScore: Int,

    /**
     * Current security maturity level.
     */
    val maturityLevel: SecurityMaturityLevel,

    /**
     * Current threat level.
     */
    val threatLevel: ThreatLevel,

    /**
     * Overall posture status.
     */
    val postureStatus: SecurityPostureStatus,

    /**
     * Compliance score.
     */
    val complianceScore: Int,

    /**
     * Vulnerability score.
     */
    val vulnerabilityScore: Int,

    /**
     * Endpoint protection score.
     */
    val endpointProtectionScore: Int,

    /**
     * Network security score.
     */
    val networkSecurityScore: Int,

    /**
     * Identity security score.
     */
    val identitySecurityScore: Int,

    /**
     * Data protection score.
     */
    val dataProtectionScore: Int,

    /**
     * Cloud security score.
     */
    val cloudSecurityScore: Int = 0,

    /**
     * Number of active threats.
     */
    val activeThreats: Int = 0,

    /**
     * Number of critical threats.
     */
    val criticalThreats: Int = 0,

    /**
     * Number of unresolved vulnerabilities.
     */
    val unresolvedVulnerabilities: Int = 0,

    /**
     * Number of failed compliance controls.
     */
    val failedComplianceControls: Int = 0,

    /**
     * Number of detected security incidents.
     */
    val securityIncidents: Int = 0,

    /**
     * Compliance frameworks currently evaluated.
     */
    val complianceFrameworks: List<String> =
        emptyList(),

    /**
     * Security strengths identified.
     */
    val strengths: List<String> =
        emptyList(),

    /**
     * Security weaknesses identified.
     */
    val weaknesses: List<String> =
        emptyList(),

    /**
     * Recommended security improvements.
     */
    val recommendations: List<String> =
        emptyList(),

    /**
     * Security control assessments.
     */
    val securityControls: List<SecurityControlAssessment> =
        emptyList(),

    /**
     * Additional metadata.
     */
    val metadata: Map<String, String> =
        emptyMap()
)

/**
 * Security entity classifications.
 *
 * Represents the object whose
 * security posture is evaluated.
 */
enum class SecurityEntityType {

    /**
     * Individual user.
     */
    USER,

    /**
     * Device or endpoint.
     */
    DEVICE,

    /**
     * Application.
     */
    APPLICATION,

    /**
     * Network environment.
     */
    NETWORK,

    /**
     * Cloud environment.
     */
    CLOUD,

    /**
     * Organization-wide assessment.
     */
    ORGANIZATION
}

/**
 * Security maturity levels.
 *
 * Represents the maturity of
 * implemented security controls.
 */
enum class SecurityMaturityLevel {

    /**
     * Initial security maturity.
     */
    INITIAL,

    /**
     * Developing security maturity.
     */
    DEVELOPING,

    /**
     * Defined security maturity.
     */
    DEFINED,

    /**
     * Managed security maturity.
     */
    MANAGED,

    /**
     * Optimized security maturity.
     */
    OPTIMIZED
}

/**
 * Security posture status indicators.
 */
enum class SecurityPostureStatus {

    /**
     * Excellent security posture.
     */
    SECURE,

    /**
     * Minor improvements recommended.
     */
    GOOD,

    /**
     * Moderate risks identified.
     */
    FAIR,

    /**
     * Significant security weaknesses.
     */
    AT_RISK,

    /**
     * Critical security concerns.
     */
    CRITICAL
}

/**
 * SecurityControlAssessment
 *
 * Represents the assessment result
 * of a specific security control.
 */
data class SecurityControlAssessment(

    /**
     * Control identifier.
     */
    val controlId: String,

    /**
     * Control name.
     */
    val controlName: String,

    /**
     * Control category.
     */
    val category: SecurityControlCategory,

    /**
     * Assessment score.
     *
     * Range:
     * 0 - 100
     */
    val score: Int,

    /**
     * Assessment status.
     */
    val status: SecurityControlStatus,

    /**
     * Findings associated with
     * this control.
     */
    val findings: List<String> =
        emptyList(),

    /**
     * Improvement recommendations.
     */
    val recommendations: List<String> =
        emptyList()
)

/**
 * Security control categories.
 */
enum class SecurityControlCategory {

    /**
     * Access management controls.
     */
    ACCESS_CONTROL,

    /**
     * Identity protection controls.
     */
    IDENTITY_SECURITY,

    /**
     * Endpoint security controls.
     */
    ENDPOINT_SECURITY,

    /**
     * Network security controls.
     */
    NETWORK_SECURITY,

    /**
     * Data protection controls.
     */
    DATA_PROTECTION,

    /**
     * Application security controls.
     */
    APPLICATION_SECURITY,

    /**
     * Cloud security controls.
     */
    CLOUD_SECURITY,

    /**
     * Compliance and governance controls.
     */
    COMPLIANCE
}

/**
 * Security control assessment status.
 */
enum class SecurityControlStatus {

    /**
     * Control operating effectively.
     */
    EFFECTIVE,

    /**
     * Control partially effective.
     */
    PARTIALLY_EFFECTIVE,

    /**
     * Control requires improvement.
     */
    NEEDS_IMPROVEMENT,

    /**
     * Control failed assessment.
     */
    FAILED,

    /**
     * Control not evaluated.
     */
    NOT_ASSESSED
}
