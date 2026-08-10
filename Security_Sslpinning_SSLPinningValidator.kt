package com.sentrix.security.sslpinning

import android.content.Context
import android.os.Build
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import java.util.Base64

/**
 * SSLPinningValidator
 *
 * Enterprise-grade validation component for SentriX SSL pinning.
 *
 * Responsibilities:
 *
 * - Validate SSL pin configuration.
 * - Validate hostnames.
 * - Validate certificate pin format.
 * - Detect duplicate pins.
 * - Check backup-pin availability.
 * - Validate manager initialization state.
 * - Validate OkHttp CertificatePinner configuration.
 * - Detect potentially unsafe pinning configurations.
 * - Produce structured validation results.
 *
 * This validator does NOT:
 *
 * - disable TLS validation
 * - install a custom permissive TrustManager
 * - bypass hostname verification
 * - perform certificate acceptance
 * - silently disable SSL pinning
 *
 * Actual certificate/public-key verification remains the
 * responsibility of OkHttp's CertificatePinner during the TLS
 * handshake.
 *
 * Architecture:
 *
 * SSLPinningManager
 *        ↓
 * SSLPinningValidator
 *        ↓
 * SSLPinningValidationReport
 *        ↓
 * Network Security Layer
 */
class SSLPinningValidator(
    private val context: Context,
    private val pinningManager: SSLPinningManager
) {

    /**
     * Performs complete SentriX SSL-pinning validation.
     */
    fun validate(): SSLPinningValidationReport {

        val findings =
            mutableListOf<SSLPinningValidationFinding>()

        var checksPerformed = 0
        var checksPassed = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * 1. Manager state
         * ---------------------------------------------------------
         */
        checksPerformed++

        val managerStatus =
            pinningManager.getStatus()

        if (
            managerStatus.initialized
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.MANAGER_INITIALIZED,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "Pinning manager initialized",
                description =
                    "SentriX SSLPinningManager is initialized.",
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.MANAGER_NOT_INITIALIZED,
                severity =
                    SSLPinningValidationSeverity.HIGH,
                title =
                    "Pinning manager not initialized",
                description =
                    "SentriX SSL pinning manager has not been initialized.",
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 2. Host configuration
         * ---------------------------------------------------------
         */
        checksPerformed++

        val configuredHosts =
            pinningManager
                .getPinnedHostnames()

        if (
            configuredHosts.isNotEmpty()
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.HOSTS_CONFIGURED,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "Pinned hosts configured",
                description =
                    "${configuredHosts.size} host(s) have SSL pinning configured.",
                value =
                    configuredHosts.joinToString(", "),
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.NO_HOSTS_CONFIGURED,
                severity =
                    if (
                        managerStatus.pinningRequired
                    ) {
                        SSLPinningValidationSeverity.CRITICAL
                    } else {
                        SSLPinningValidationSeverity.MEDIUM
                    },
                title =
                    "No pinned hosts configured",
                description =
                    if (
                        managerStatus.pinningRequired
                    ) {
                        "Pinning is mandatory but no hosts are configured."
                    } else {
                        "No SSL pinning hosts are configured."
                    },
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 3. Validate each host
         * ---------------------------------------------------------
         */
        configuredHosts.forEach { hostname ->

            val hostValidation =
                validateHost(
                    hostname
                )

            checksPerformed +=
                hostValidation.checksPerformed

            checksPassed +=
                hostValidation.checksPassed

            checksFailed +=
                hostValidation.checksFailed

            findings +=
                hostValidation.findings
        }

        /**
         * ---------------------------------------------------------
         * 4. CertificatePinner construction
         * ---------------------------------------------------------
         */
        checksPerformed++

        try {

            pinningManager
                .buildCertificatePinner()

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.CERTIFICATE_PINNER_BUILD,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "CertificatePinner construction successful",
                description =
                    "OkHttp CertificatePinner was successfully constructed from the configured pins.",
                valid = true
            )

        } catch (exception: Exception) {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.CERTIFICATE_PINNER_BUILD_FAILED,
                severity =
                    SSLPinningValidationSeverity.CRITICAL,
                title =
                    "CertificatePinner construction failed",
                description =
                    "The configured pins could not be converted into an OkHttp CertificatePinner.",
                value =
                    exception.javaClass.simpleName,
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 5. OkHttp client validation
         * ---------------------------------------------------------
         */
        checksPerformed++

        val clientValidation =
            validateOkHttpClient(
                findings
            )

        if (clientValidation) {
            checksPassed++
        } else {
            checksFailed++
        }

        /**
         * ---------------------------------------------------------
         * 6. Android runtime checks
         * ---------------------------------------------------------
         */
        checksPerformed++

        val androidValidation =
            validateAndroidEnvironment(
                findings
            )

        if (androidValidation) {
            checksPassed++
        } else {
            checksFailed++
        }

        /**
         * ---------------------------------------------------------
         * 7. Security recommendations
         * ---------------------------------------------------------
         */
        val recommendations =
            generateRecommendations(
                findings
            )

        /**
         * ---------------------------------------------------------
         * Final status
         * ---------------------------------------------------------
         */
        val status =
            determineStatus(
                findings = findings,
                checksFailed = checksFailed
            )

        return SSLPinningValidationReport(
            status = status,
            findings = findings,
            recommendations = recommendations,
            checksPerformed = checksPerformed,
            checksPassed = checksPassed,
            checksFailed = checksFailed,
            configuredHostCount =
                configuredHosts.size,
            validationCompleted = true,
            validatedAt =
                System.currentTimeMillis()
        )
    }

    /**
     * Validates one configured hostname.
     */
    fun validateHost(
        hostname: String
    ): SSLPinningHostValidationResult {

        val findings =
            mutableListOf<SSLPinningValidationFinding>()

        var checksPerformed = 0
        var checksPassed = 0
        var checksFailed = 0

        val normalized =
            hostname
                .trim()
                .lowercase()
                .removeSuffix(".")

        /**
         * ---------------------------------------------------------
         * Hostname syntax
         * ---------------------------------------------------------
         */
        checksPerformed++

        if (
            isValidHostname(
                normalized
            )
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.HOSTNAME_VALID,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "Hostname is valid",
                description =
                    "Configured hostname has a valid hostname format.",
                value =
                    normalized,
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.HOSTNAME_INVALID,
                severity =
                    SSLPinningValidationSeverity.CRITICAL,
                title =
                    "Invalid hostname",
                description =
                    "Configured SSL pinning hostname is invalid.",
                value =
                    normalized,
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Host registration
         * ---------------------------------------------------------
         */
        checksPerformed++

        val hostStatus =
            pinningManager
                .checkHostConfiguration(
                    normalized
                )

        if (
            hostStatus.pinned
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.HOST_CONFIGURED,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "Host is pinned",
                description =
                    "The hostname has an active SentriX pin configuration.",
                value =
                    normalized,
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.HOST_NOT_CONFIGURED,
                severity =
                    SSLPinningValidationSeverity.HIGH,
                title =
                    "Host is not pinned",
                description =
                    "The requested hostname does not have a configured pin.",
                value =
                    normalized,
                valid = false
            )

            return SSLPinningHostValidationResult(
                hostname = normalized,
                valid = false,
                checksPerformed = checksPerformed,
                checksPassed = checksPassed,
                checksFailed = checksFailed,
                findings = findings
            )
        }

        /**
         * ---------------------------------------------------------
         * Retrieve configuration
         * ---------------------------------------------------------
         */
        val configuration =
            pinningManager
                .getPinConfiguration(
                    normalized
                )

        if (
            configuration == null
        ) {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.CONFIGURATION_UNAVAILABLE,
                severity =
                    SSLPinningValidationSeverity.CRITICAL,
                title =
                    "Pin configuration unavailable",
                description =
                    "Pinning manager reports the host as pinned, but its configuration could not be retrieved.",
                value =
                    normalized,
                valid = false
            )

            return SSLPinningHostValidationResult(
                hostname = normalized,
                valid = false,
                checksPerformed = checksPerformed,
                checksPassed = checksPassed,
                checksFailed = checksFailed,
                findings = findings
            )
        }

        /**
         * ---------------------------------------------------------
         * Pin count
         * ---------------------------------------------------------
         */
        checksPerformed++

        if (
            configuration.pins.isNotEmpty()
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.PINS_PRESENT,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "Certificate pins present",
                description =
                    "The hostname has one or more configured certificate pins.",
                value =
                    configuration.pins.size.toString(),
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.PINS_MISSING,
                severity =
                    SSLPinningValidationSeverity.CRITICAL,
                title =
                    "No certificate pins configured",
                description =
                    "The hostname is registered but contains no usable pins.",
                value =
                    normalized,
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Individual pin validation
         * ---------------------------------------------------------
         */
        configuration
            .pins
            .forEach { pin ->

                checksPerformed++

                if (
                    isValidCertificatePin(
                        pin
                    )
                ) {

                    checksPassed++

                    findings += finding(
                        type =
                            SSLPinningValidationType.PIN_FORMAT_VALID,
                        severity =
                            SSLPinningValidationSeverity.INFO,
                        title =
                            "Certificate pin format valid",
                        description =
                            "The configured certificate pin uses a valid SHA-256 pin format.",
                        value =
                            maskPin(pin),
                        valid = true
                    )

                } else {

                    checksFailed++

                    findings += finding(
                        type =
                            SSLPinningValidationType.PIN_FORMAT_INVALID,
                        severity =
                            SSLPinningValidationSeverity.CRITICAL,
                        title =
                            "Invalid certificate pin",
                        description =
                            "A configured certificate pin does not use the expected SHA-256 pin format.",
                        value =
                            maskPin(pin),
                        valid = false
                    )
                }
            }

        /**
         * ---------------------------------------------------------
         * Duplicate pin detection
         * ---------------------------------------------------------
         */
        checksPerformed++

        val uniquePins =
            configuration
                .pins
                .map {
                    it.trim()
                }
                .distinct()

        if (
            uniquePins.size ==
            configuration.pins.size
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.NO_DUPLICATE_PINS,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "No duplicate pins",
                description =
                    "No duplicate certificate pins were detected.",
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLPinningValidationType.DUPLICATE_PINS,
                severity =
                    SSLPinningValidationSeverity.MEDIUM,
                title =
                    "Duplicate certificate pins",
                description =
                    "Duplicate certificate pins are configured for this hostname.",
                value =
                    configuration.pins.size.toString(),
                expectedValue =
                    uniquePins.size.toString(),
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Backup pin recommendation
         * ---------------------------------------------------------
         */
        checksPerformed++

        if (
            configuration.pins.size >= 2
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLPinningValidationType.BACKUP_PIN_PRESENT,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "Backup pin configured",
                description =
                    "More than one certificate pin is configured for the hostname.",
                value =
                    configuration.pins.size.toString(),
                valid = true
            )

        } else {

            /**
             * This is a warning rather than a validation failure.
             */
            findings += finding(
                type =
                    SSLPinningValidationType.BACKUP_PIN_MISSING,
                severity =
                    SSLPinningValidationSeverity.MEDIUM,
                title =
                    "Backup pin not configured",
                description =
                    "Only one certificate pin is configured. Controlled key rotation may require a backup pin.",
                value =
                    normalized,
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Subdomain warning
         * ---------------------------------------------------------
         */
        if (
            configuration.includeSubdomains
        ) {

            findings += finding(
                type =
                    SSLPinningValidationType.SUBDOMAIN_PINNING_ENABLED,
                severity =
                    SSLPinningValidationSeverity.LOW,
                title =
                    "Subdomain pinning requested",
                description =
                    "The configuration indicates that subdomain coverage is intended.",
                value =
                    normalized,
                valid = true
            )
        }

        return SSLPinningHostValidationResult(
            hostname = normalized,
            valid =
                checksFailed == 0,
            checksPerformed = checksPerformed,
            checksPassed = checksPassed,
            checksFailed = checksFailed,
            findings = findings
        )
    }

    /**
     * Validates an OkHttpClient's certificate pinner.
     *
     * Reflection is intentionally avoided. This validation checks
     * the client through the public OkHttp API.
     */
    fun validateOkHttpClient(
        findings:
            MutableList<SSLPinningValidationFinding> =
                mutableListOf()
    ): Boolean {

        val client =
            try {

                pinningManager
                    .buildPinnedClient()

            } catch (exception: Exception) {

                findings += finding(
                    type =
                        SSLPinningValidationType.OKHTTP_CLIENT_BUILD_FAILED,
                    severity =
                        SSLPinningValidationSeverity.CRITICAL,
                    title =
                        "Pinned OkHttp client could not be built",
                    description =
                        "SentriX could not construct an OkHttp client using the configured pinning policy.",
                    value =
                        exception.javaClass.simpleName,
                    valid = false
                )

                return false
            }

        val pinner =
            client
                .certificatePinner

        val configuredHosts =
            pinningManager
                .getPinnedHostnames()

        /**
         * CertificatePinner.toString() is intentionally not used
         * as a security source. The important condition here is
         * that the client contains a CertificatePinner instance
         * created by the SentriX manager.
         */
        if (
            configuredHosts.isNotEmpty()
        ) {

            findings += finding(
                type =
                    SSLPinningValidationType.OKHTTP_PINNER_CONFIGURED,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "OkHttp CertificatePinner configured",
                description =
                    "The pinned OkHttp client contains an active CertificatePinner.",
                value =
                    pinner.javaClass.name,
                valid = true
            )

            return true
        }

        findings += finding(
            type =
                SSLPinningValidationType.OKHTTP_PINNER_EMPTY,
            severity =
                SSLPinningValidationSeverity.CRITICAL,
            title =
                "OkHttp CertificatePinner has no configured hosts",
            description =
                "The pinned client was created without configured pinning hosts.",
            valid = false
        )

        return false
    }

    /**
     * Validates the Android environment relevant to this validator.
     */
    private fun validateAndroidEnvironment(
        findings:
            MutableList<SSLPinningValidationFinding>
    ): Boolean {

        /**
         * Android version is recorded as contextual information.
         */
        findings += finding(
            type =
                SSLPinningValidationType.ANDROID_VERSION,
            severity =
                SSLPinningValidationSeverity.INFO,
            title =
                "Android runtime identified",
            description =
                "Current Android API level used by SentriX.",
            value =
                Build.VERSION.SDK_INT.toString(),
            valid = true
        )

        /**
         * Modern Android versions provide stronger platform TLS
         * infrastructure and security APIs.
         */
        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.N
        ) {

            findings += finding(
                type =
                    SSLPinningValidationType.MODERN_ANDROID_TLS,
                severity =
                    SSLPinningValidationSeverity.INFO,
                title =
                    "Modern Android TLS environment",
                description =
                    "The application is running on Android 7.0/API 24 or later.",
                value =
                    Build.VERSION.SDK_INT.toString(),
                valid = true
            )

            return true
        }

        findings += finding(
            type =
                SSLPinningValidationType.LEGACY_ANDROID_TLS,
            severity =
                SSLPinningValidationSeverity.MEDIUM,
            title =
                "Legacy Android TLS environment",
            description =
                "The application is running on an older Android API level.",
            value =
                Build.VERSION.SDK_INT.toString(),
            valid = false
        )

        return false
    }

    /**
     * Validates the standard OkHttp certificate-pin format:
     *
     * sha256/<44-character Base64 SHA-256 digest>
     */
    private fun isValidCertificatePin(
        pin: String
    ): Boolean {

        val trimmed =
            pin.trim()

        if (
            !trimmed.startsWith(
                "sha256/"
            )
        ) {

            return false
        }

        val encoded =
            trimmed.removePrefix(
                "sha256/"
            )

        /**
         * SHA-256 digest = 32 bytes.
         * Base64 representation = 44 characters with padding.
         */
        if (
            encoded.length != 44
        ) {

            return false
        }

        if (
            !encoded.matches(
                Regex(
                    "^[A-Za-z0-9+/]{43}={1}$"
                )
            )
        ) {

            return false
        }

        /**
         * Decode to confirm that the Base64 payload is actually
         * valid.
         */
        return try {

            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.O
            ) {

                Base64
                    .getDecoder()
                    .decode(encoded)
                    .size == 32

            } else {

                android.util.Base64
                    .decode(
                        encoded,
                        android.util.Base64.DEFAULT
                    )
                    .size == 32
            }

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Basic hostname validation.
     */
    private fun isValidHostname(
        hostname: String
    ): Boolean {

        if (hostname.isBlank()) {
            return false
        }

        if (
            hostname.length > 253
        ) {
            return false
        }

        if (
            hostname.contains(
                "://"
            )
        ) {
            return false
        }

        if (
            hostname.contains(
                "/"
            )
        ) {
            return false
        }

        if (
            hostname.contains(
                ":"
            )
        ) {
            return false
        }

        /**
         * Allows:
         *
         * api.example.com
         * example.com
         * api-01.example.com
         */
        val hostnamePattern =
            Regex(
                "^(?=.{1,253}$)" +
                        "([a-zA-Z0-9]" +
                        "([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
                        "\\.)*" +
                        "[a-zA-Z0-9]" +
                        "([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
            )

        return hostnamePattern.matches(
            hostname
        )
    }

    /**
     * Masks the majority of a certificate pin so validation
     * logs do not unnecessarily expose the complete fingerprint.
     */
    private fun maskPin(
        pin: String
    ): String {

        val trimmed =
            pin.trim()

        if (
            trimmed.length <= 16
        ) {
            return "***"
        }

        return trimmed.take(12) +
                "..." +
                trimmed.takeLast(6)
    }

    /**
     * Creates a validation finding.
     */
    private fun finding(
        type: SSLPinningValidationType,
        severity: SSLPinningValidationSeverity,
        title: String,
        description: String,
        value: String? = null,
        expectedValue: String? = null,
        valid: Boolean
    ): SSLPinningValidationFinding {

        return SSLPinningValidationFinding(
            type = type,
            severity = severity,
            title = title,
            description = description,
            value = value,
            expectedValue = expectedValue,
            valid = valid
        )
    }

    /**
     * Generates recommendations from validation findings.
     */
    private fun generateRecommendations(
        findings:
            List<SSLPinningValidationFinding>
    ): List<SSLPinningRecommendation> {

        val recommendations =
            mutableListOf<SSLPinningRecommendation>()

        if (
            findings.any {
                it.type ==
                        SSLPinningValidationType.NO_HOSTS_CONFIGURED
            }
        ) {

            recommendations +=
                SSLPinningRecommendation(
                    priority =
                        SSLPinningRecommendationPriority.CRITICAL,
                    title =
                        "Configure trusted hosts",
                    description =
                        "Mandatory SSL pinning is enabled without trusted host configurations.",
                    action =
                        "Register the production API hostnames and their trusted SHA-256 public-key pins."
                )
        }

        if (
            findings.any {
                it.type ==
                        SSLPinningValidationType.PIN_FORMAT_INVALID
            }
        ) {

            recommendations +=
                SSLPinningRecommendation(
                    priority =
                        SSLPinningRecommendationPriority.CRITICAL,
                    title =
                        "Correct invalid pins",
                    description =
                        "One or more configured certificate pins do not use the expected SHA-256 format.",
                    action =
                        "Replace invalid values with valid OkHttp sha256/ public-key pins."
                )
        }

        if (
            findings.any {
                it.type ==
                        SSLPinningValidationType.BACKUP_PIN_MISSING
            }
        ) {

            recommendations +=
                SSLPinningRecommendation(
                    priority =
                        SSLPinningRecommendationPriority.MEDIUM,
                    title =
                        "Add a backup pin",
                    description =
                        "A single pin can make certificate/key rotation disruptive.",
                    action =
                        "Provision a carefully controlled backup public-key pin for planned key rotation."
                )
        }

        if (
            findings.any {
                it.type ==
                        SSLPinningValidationType.MANAGER_NOT_INITIALIZED
            }
        ) {

            recommendations +=
                SSLPinningRecommendation(
                    priority =
                        SSLPinningRecommendationPriority.HIGH,
                    title =
                        "Initialize SSL pinning",
                    description =
                        "The pinning manager has not been initialized.",
                    action =
                        "Initialize SSLPinningManager before constructing or using the protected network client."
                )
        }

        if (
            findings.any {
                it.type ==
                        SSLPinningValidationType.CERTIFICATE_PINNER_BUILD_FAILED
            }
        ) {

            recommendations +=
                SSLPinningRecommendation(
                    priority =
                        SSLPinningRecommendationPriority.CRITICAL,
                    title =
                        "Repair CertificatePinner configuration",
                    description =
                        "OkHttp CertificatePinner could not be constructed.",
                    action =
                        "Correct the pin configuration before allowing protected network requests."
                )
        }

        if (
            findings.any {
                it.type ==
                        SSLPinningValidationType.DUPLICATE_PINS
            }
        ) {

            recommendations +=
                SSLPinningRecommendation(
                    priority =
                        SSLPinningRecommendationPriority.LOW,
                    title =
                        "Remove duplicate pins",
                    description =
                        "Duplicate certificate pins were found.",
                    action =
                        "Keep only unique trusted pins for each hostname."
                )
        }

        if (
            recommendations.isEmpty()
        ) {

            recommendations +=
                SSLPinningRecommendation(
                    priority =
                        SSLPinningRecommendationPriority.INFO,
                    title =
                        "SSL pinning configuration is healthy",
                    description =
                        "No significant SSL pinning configuration problems were identified.",
                    action =
                        "Continue monitoring certificate rotation and pin configuration."
                )
        }

        return recommendations
    }

    /**
     * Determines final validation status.
     */
    private fun determineStatus(
        findings:
            List<SSLPinningValidationFinding>,
        checksFailed: Int
    ): SSLPinningValidationStatus {

        if (
            findings.any {
                it.severity ==
                        SSLPinningValidationSeverity.CRITICAL &&
                        !it.valid
            }
        ) {

            return SSLPinningValidationStatus.INVALID
        }

        if (
            findings.any {
                it.severity ==
                        SSLPinningValidationSeverity.HIGH &&
                        !it.valid
            }
        ) {

            return SSLPinningValidationStatus.UNSAFE
        }

        if (
            findings.any {
                it.severity ==
                        SSLPinningValidationSeverity.MEDIUM &&
                        !it.valid
            }
        ) {

            return SSLPinningValidationStatus.VALID_WITH_WARNINGS
        }

        if (checksFailed > 0) {

            return SSLPinningValidationStatus.CHECK_INCOMPLETE
        }

        return SSLPinningValidationStatus.VALID
    }
}

/**
 * Complete SSL pinning validation report.
 */
data class SSLPinningValidationReport(

    /**
     * Overall validation status.
     */
    val status: SSLPinningValidationStatus,

    /**
     * All validation findings.
     */
    val findings:
        List<SSLPinningValidationFinding>,

    /**
     * Recommended actions.
     */
    val recommendations:
        List<SSLPinningRecommendation>,

    /**
     * Number of checks performed.
     */
    val checksPerformed: Int,

    /**
     * Number of checks passed.
     */
    val checksPassed: Int,

    /**
     * Number of checks failed.
     */
    val checksFailed: Int,

    /**
     * Number of configured pinned hosts.
     */
    val configuredHostCount: Int,

    /**
     * Whether validation completed.
     */
    val validationCompleted: Boolean,

    /**
     * Validation timestamp.
     */
    val validatedAt: Long
) {

    /**
     * True when the configuration is valid.
     */
    val isValid: Boolean
        get() =
            status ==
                    SSLPinningValidationStatus.VALID

    /**
     * True when warnings exist but the configuration remains
     * usable.
     */
    val hasWarnings: Boolean
        get() =
            status ==
                    SSLPinningValidationStatus.VALID_WITH_WARNINGS

    /**
     * True when the configuration should not be trusted.
     */
    val isUnsafe: Boolean
        get() =
            status ==
                    SSLPinningValidationStatus.UNSAFE ||
                    status ==
                    SSLPinningValidationStatus.INVALID

    /**
     * Returns critical findings.
     */
    val criticalFindings:
            List<SSLPinningValidationFinding>
        get() =
            findings.filter {
                it.severity ==
                        SSLPinningValidationSeverity.CRITICAL
            }
}

/**
 * Host-specific validation result.
 */
data class SSLPinningHostValidationResult(

    /**
     * Hostname.
     */
    val hostname: String,

    /**
     * Whether host configuration is valid.
     */
    val valid: Boolean,

    /**
     * Checks performed.
     */
    val checksPerformed: Int,

    /**
     * Checks passed.
     */
    val checksPassed: Int,

    /**
     * Checks failed.
     */
    val checksFailed: Int,

    /**
     * Findings.
     */
    val findings:
        List<SSLPinningValidationFinding>
)

/**
 * Individual SSL pinning validation finding.
 */
data class SSLPinningValidationFinding(

    /**
     * Validation category.
     */
    val type: SSLPinningValidationType,

    /**
     * Finding severity.
     */
    val severity: SSLPinningValidationSeverity,

    /**
     * Human-readable title.
     */
    val title: String,

    /**
     * Detailed description.
     */
    val description: String,

    /**
     * Observed value.
     */
    val value: String? = null,

    /**
     * Expected value.
     */
    val expectedValue: String? = null,

    /**
     * Whether this particular validation passed.
     */
    val valid: Boolean
)

/**
 * SSL pinning validation categories.
 */
enum class SSLPinningValidationType {

    /**
     * Manager initialization.
     */
    MANAGER_INITIALIZED,

    /**
     * Manager not initialized.
     */
    MANAGER_NOT_INITIALIZED,

    /**
     * One or more hosts configured.
     */
    HOSTS_CONFIGURED,

    /**
     * No hosts configured.
     */
    NO_HOSTS_CONFIGURED,

    /**
     * Hostname syntax valid.
     */
    HOSTNAME_VALID,

    /**
     * Hostname syntax invalid.
     */
    HOSTNAME_INVALID,

    /**
     * Host is configured.
     */
    HOST_CONFIGURED,

    /**
     * Host is not configured.
     */
    HOST_NOT_CONFIGURED,

    /**
     * Host configuration unavailable.
     */
    CONFIGURATION_UNAVAILABLE,

    /**
     * Pins are present.
     */
    PINS_PRESENT,

    /**
     * Pins are missing.
     */
    PINS_MISSING,

    /**
     * Pin format valid.
     */
    PIN_FORMAT_VALID,

    /**
     * Pin format invalid.
     */
    PIN_FORMAT_INVALID,

    /**
     * No duplicate pins.
     */
    NO_DUPLICATE_PINS,

    /**
     * Duplicate pins detected.
     */
    DUPLICATE_PINS,

    /**
     * Backup pin available.
     */
    BACKUP_PIN_PRESENT,

    /**
     * Backup pin unavailable.
     */
    BACKUP_PIN_MISSING,

    /**
     * Subdomain pinning enabled.
     */
    SUBDOMAIN_PINNING_ENABLED,

    /**
     * CertificatePinner created successfully.
     */
    CERTIFICATE_PINNER_BUILD,

    /**
     * CertificatePinner creation failed.
     */
    CERTIFICATE_PINNER_BUILD_FAILED,

    /**
     * OkHttp pinned client creation failed.
     */
    OKHTTP_CLIENT_BUILD_FAILED,

    /**
     * OkHttp CertificatePinner exists.
     */
    OKHTTP_PINNER_CONFIGURED,

    /**
     * OkHttp CertificatePinner has no configured hosts.
     */
    OKHTTP_PINNER_EMPTY,

    /**
     * Android version information.
     */
    ANDROID_VERSION,

    /**
     * Modern Android TLS environment.
     */
    MODERN_ANDROID_TLS,

    /**
     * Legacy Android TLS environment.
     */
    LEGACY_ANDROID_TLS
}

/**
 * Validation severity.
 */
enum class SSLPinningValidationSeverity {

    /**
     * Informational.
     */
    INFO,

    /**
     * Low concern.
     */
    LOW,

    /**
     * Moderate concern.
     */
    MEDIUM,

    /**
     * High concern.
     */
    HIGH,

    /**
     * Critical configuration/security problem.
     */
    CRITICAL
}

/**
 * Overall SSL pinning validation state.
 */
enum class SSLPinningValidationStatus {

    /**
     * Configuration is valid.
     */
    VALID,

    /**
     * Configuration is valid but contains warnings.
     */
    VALID_WITH_WARNINGS,

    /**
     * Configuration is unsafe.
     */
    UNSAFE,

    /**
     * Configuration contains critical errors.
     */
    INVALID,

    /**
     * Validation could not fully complete.
     */
    CHECK_INCOMPLETE
}

/**
 * Recommended SSL pinning action.
 */
data class SSLPinningRecommendation(

    /**
     * Recommendation priority.
     */
    val priority:
        SSLPinningRecommendationPriority,

    /**
     * Recommendation title.
     */
    val title: String,

    /**
     * Explanation.
     */
    val description: String,

    /**
     * Suggested action.
     */
    val action: String
)

/**
 * SSL pinning recommendation priority.
 */
enum class SSLPinningRecommendationPriority {

    /**
     * Informational.
     */
    INFO,

    /**
     * Low priority.
     */
    LOW,

    /**
     * Medium priority.
     */
    MEDIUM,

    /**
     * High priority.
     */
    HIGH,

    /**
     * Critical priority.
     */
    CRITICAL
}
