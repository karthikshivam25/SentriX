package com.sentrix.security.sslpinning

/**
 * SSLPinningConfiguration
 *
 * Central configuration model for SentriX SSL/TLS pinning.
 *
 * Responsibilities:
 *
 * - Define hosts that require certificate pinning.
 * - Store primary and backup public-key pins.
 * - Define TLS protocol requirements.
 * - Define certificate validation policies.
 * - Define pinning enforcement behavior.
 * - Control security reporting.
 * - Provide host-specific pinning configuration.
 *
 * SECURITY PRINCIPLES:
 *
 * 1. Pinning is fail-closed by default.
 * 2. Pins are public-key SHA-256 pins.
 * 3. Backup pins are strongly recommended.
 * 4. TLS 1.2 and TLS 1.3 are the supported defaults.
 * 5. Pinning never replaces normal certificate validation.
 * 6. Hostname verification remains enabled.
 * 7. Configuration is immutable.
 *
 * Example pin:
 *
 * sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
 *
 * The actual application should replace the placeholder with
 * the real SHA-256 SubjectPublicKeyInfo pin.
 */
data class SSLPinningConfiguration(

    /**
     * Whether SSL pinning is globally enabled.
     */
    val enabled: Boolean = true,

    /**
     * Whether pinning failures must block the connection.
     *
     * Recommended value:
     *
     * true
     */
    val failClosed: Boolean = true,

    /**
     * Host-specific pinning configurations.
     *
     * Example:
     *
     * mapOf(
     *     "api.example.com" to
     *         SSLHostPinConfiguration(...)
     * )
     */
    val hosts:
        Map<String, SSLHostPinConfiguration> =
        emptyMap(),

    /**
     * Globally allowed TLS protocols.
     */
    val allowedTlsProtocols:
        Set<String> =
        setOf(
            SecureSSLSocketFactory.TLS_1_3,
            SecureSSLSocketFactory.TLS_1_2
        ),

    /**
     * Globally allowed cipher suites.
     *
     * Empty means use the secure platform defaults.
     */
    val allowedCipherSuites:
        Set<String> =
        emptySet(),

    /**
     * Whether hostname verification is mandatory.
     */
    val hostnameVerificationEnabled: Boolean = true,

    /**
     * Whether certificate-chain validation is mandatory.
     */
    val certificateChainValidationEnabled: Boolean = true,

    /**
     * Whether certificate validity dates should be checked.
     */
    val certificateValidityCheckEnabled: Boolean = true,

    /**
     * Whether handshake information should be collected.
     */
    val handshakeValidationEnabled: Boolean = true,

    /**
     * Whether security reports should be generated.
     */
    val reportingEnabled: Boolean = true,

    /**
     * Whether a security alert should be generated when pinning
     * fails.
     */
    val alertOnPinningFailure: Boolean = true,

    /**
     * Whether backup pins are required.
     *
     * Recommended for production deployments.
     */
    val requireBackupPin: Boolean = true,

    /**
     * Minimum number of pins required for a host.
     */
    val minimumPinsPerHost: Int = 2,

    /**
     * Whether unknown hosts should be allowed.
     *
     * For strict enterprise security this should normally be false
     * when the application expects every protected API host to have
     * an explicit configuration.
     *
     * This setting applies to pinning policy, not general Internet
     * access.
     */
    val allowUnconfiguredHosts: Boolean = false,

    /**
     * Whether wildcard host configurations are permitted.
     */
    val wildcardHostsEnabled: Boolean = false,

    /**
     * Optional configuration version.
     */
    val version: Int = 1,

    /**
     * Configuration environment.
     */
    val environment:
        SSLPinningEnvironment =
        SSLPinningEnvironment.PRODUCTION
) {

    /**
     * Returns the normalized host configuration.
     */
    fun getHostConfiguration(
        hostname: String
    ): SSLHostPinConfiguration? {

        val normalized =
            normalizeHostname(
                hostname
            )

        /**
         * First attempt exact match.
         */
        hosts[normalized]?.let {
            return it
        }

        if (
            !wildcardHostsEnabled
        ) {
            return null
        }

        /**
         * Optional wildcard matching.
         *
         * Example:
         *
         * *.example.com
         */
        return hosts.entries
            .firstOrNull { entry ->

                isWildcardHost(
                    pattern =
                        entry.key,
                    hostname =
                        normalized
                )

            }
            ?.value
    }

    /**
     * Returns whether the supplied host has explicit pinning
     * configuration.
     */
    fun isHostConfigured(
        hostname: String
    ): Boolean {

        return getHostConfiguration(
            hostname
        ) != null
    }

    /**
     * Returns all configured hosts.
     */
    fun getConfiguredHosts():
            Set<String> {

        return hosts.keys
            .map {
                normalizeHostname(it)
            }
            .toSet()
    }

    /**
     * Returns whether the host should be pinned.
     */
    fun shouldPinHost(
        hostname: String
    ): Boolean {

        if (!enabled) {
            return false
        }

        val hostConfiguration =
            getHostConfiguration(
                hostname
            )

        if (
            hostConfiguration != null
        ) {

            return hostConfiguration.enabled
        }

        return !allowUnconfiguredHosts
    }

    /**
     * Returns all pins configured for a host.
     */
    fun getPinsForHost(
        hostname: String
    ): Set<String> {

        return getHostConfiguration(
            hostname
        )
            ?.allPins()
            ?: emptySet()
    }

    /**
     * Returns primary pins for a host.
     */
    fun getPrimaryPinsForHost(
        hostname: String
    ): Set<String> {

        return getHostConfiguration(
            hostname
        )
            ?.primaryPins
            ?: emptySet()
    }

    /**
     * Returns backup pins for a host.
     */
    fun getBackupPinsForHost(
        hostname: String
    ): Set<String> {

        return getHostConfiguration(
            hostname
        )
            ?.backupPins
            ?: emptySet()
    }

    /**
     * Validates the complete configuration using SentriX's
     * existing SSL pin validator.
     */
    fun validate():
            SSLPinningConfigurationValidationResult {

        val findings =
            mutableListOf<SSLPinningConfigurationFinding>()

        var checksPerformed = 0
        var checksPassed = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * Global configuration
         * ---------------------------------------------------------
         */
        checksPerformed++

        if (
            minimumPinsPerHost >= 1
        ) {

            checksPassed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.MINIMUM_PIN_COUNT_VALID,
                severity =
                    SSLPinningConfigurationSeverity.INFO,
                title =
                    "Minimum pin count is valid",
                description =
                    "The configured minimum number of pins per host is at least one.",
                value =
                    minimumPinsPerHost.toString(),
                valid = true
            )

        } else {

            checksFailed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.INVALID_MINIMUM_PIN_COUNT,
                severity =
                    SSLPinningConfigurationSeverity.CRITICAL,
                title =
                    "Invalid minimum pin count",
                description =
                    "The minimum pin count must be at least one.",
                value =
                    minimumPinsPerHost.toString(),
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * TLS protocol configuration
         * ---------------------------------------------------------
         */
        checksPerformed++

        val invalidProtocols =
            allowedTlsProtocols
                .filterNot {
                    it ==
                            SecureSSLSocketFactory.TLS_1_2 ||
                    it ==
                            SecureSSLSocketFactory.TLS_1_3
                }

        if (
            invalidProtocols.isEmpty() &&
            allowedTlsProtocols.isNotEmpty()
        ) {

            checksPassed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.TLS_PROTOCOL_CONFIGURATION_VALID,
                severity =
                    SSLPinningConfigurationSeverity.INFO,
                title =
                    "TLS protocol configuration valid",
                description =
                    "Configured TLS protocols are supported by the SentriX policy.",
                value =
                    allowedTlsProtocols
                        .joinToString(", "),
                valid = true
            )

        } else {

            checksFailed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.INVALID_TLS_PROTOCOL_CONFIGURATION,
                severity =
                    SSLPinningConfigurationSeverity.HIGH,
                title =
                    "Invalid TLS protocol configuration",
                description =
                    "The TLS protocol configuration contains unsupported or invalid protocols.",
                value =
                    invalidProtocols
                        .joinToString(", "),
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Host configurations
         * ---------------------------------------------------------
         */
        hosts.forEach { (hostname, hostConfiguration) ->

            val hostResult =
                validateHostConfiguration(
                    hostname =
                        hostname,
                    configuration =
                        hostConfiguration
                )

            checksPerformed +=
                hostResult.checksPerformed

            checksPassed +=
                hostResult.checksPassed

            checksFailed +=
                hostResult.checksFailed

            findings +=
                hostResult.findings
        }

        /**
         * ---------------------------------------------------------
         * Backup-pin policy
         * ---------------------------------------------------------
         */
        if (
            requireBackupPin &&
            hosts.isNotEmpty()
        ) {

            checksPerformed++

            val hostsWithoutBackupPins =
                hosts
                    .filterValues {
                        it.enabled &&
                                it.backupPins.isEmpty()
                    }
                    .keys

            if (
                hostsWithoutBackupPins.isEmpty()
            ) {

                checksPassed++

                findings += SSLPinningConfigurationFinding(
                    type =
                        SSLPinningConfigurationFindingType.BACKUP_PIN_POLICY_SATISFIED,
                    severity =
                        SSLPinningConfigurationSeverity.INFO,
                    title =
                        "Backup-pin policy satisfied",
                    description =
                        "All enabled hosts have at least one backup pin.",
                    valid = true
                )

            } else {

                checksFailed++

                findings += SSLPinningConfigurationFinding(
                    type =
                        SSLPinningConfigurationFindingType.MISSING_BACKUP_PIN,
                    severity =
                        SSLPinningConfigurationSeverity.CRITICAL,
                    title =
                        "Backup pin missing",
                    description =
                        "One or more enabled hosts do not have a backup pin.",
                    value =
                        hostsWithoutBackupPins
                            .joinToString(", "),
                    valid = false
                )
            }
        }

        /**
         * ---------------------------------------------------------
         * Final state
         * ---------------------------------------------------------
         */
        val valid =
            checksFailed == 0

        return SSLPinningConfigurationValidationResult(
            valid =
                valid,
            findings =
                findings,
            checksPerformed =
                checksPerformed,
            checksPassed =
                checksPassed,
            checksFailed =
                checksFailed,
            message =
                if (valid) {
                    "SSL pinning configuration is valid."
                } else {
                    "SSL pinning configuration contains security findings."
                }
        )
    }

    /**
     * Validates a host-specific configuration.
     */
    private fun validateHostConfiguration(
        hostname: String,
        configuration:
            SSLHostPinConfiguration
    ): SSLPinningHostValidationResult {

        val findings =
            mutableListOf<SSLPinningConfigurationFinding>()

        var checksPerformed = 0
        var checksPassed = 0
        var checksFailed = 0

        val normalizedHost =
            normalizeHostname(
                hostname
            )

        /**
         * ---------------------------------------------------------
         * Hostname
         * ---------------------------------------------------------
         */
        checksPerformed++

        val hostnameValid =
            isValidHostname(
                normalizedHost
            )

        if (hostnameValid) {

            checksPassed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.HOSTNAME_VALID,
                severity =
                    SSLPinningConfigurationSeverity.INFO,
                title =
                    "Host configuration valid",
                description =
                    "The configured hostname has a valid structure.",
                value =
                    normalizedHost,
                valid = true
            )

        } else {

            checksFailed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.INVALID_HOSTNAME,
                severity =
                    SSLPinningConfigurationSeverity.CRITICAL,
                title =
                    "Invalid pinning hostname",
                description =
                    "The configured hostname is invalid.",
                value =
                    normalizedHost,
                valid = false
            )
        }

        /**
         * Disabled hosts do not need active pin validation.
         */
        if (
            !configuration.enabled
        ) {

            return SSLPinningHostValidationResult(
                valid =
                    checksFailed == 0,
                findings =
                    findings,
                checksPerformed =
                    checksPerformed,
                checksPassed =
                    checksPassed,
                checksFailed =
                    checksFailed
            )
        }

        /**
         * ---------------------------------------------------------
         * Pin count
         * ---------------------------------------------------------
         */
        checksPerformed++

        val totalPins =
            configuration
                .allPins()
                .size

        if (
            totalPins >=
            minimumPinsPerHost
        ) {

            checksPassed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.PIN_COUNT_VALID,
                severity =
                    SSLPinningConfigurationSeverity.INFO,
                title =
                    "Host pin count valid",
                description =
                    "The host contains the required number of pins.",
                value =
                    totalPins.toString(),
                expectedValue =
                    minimumPinsPerHost.toString(),
                valid = true
            )

        } else {

            checksFailed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.INSUFFICIENT_PIN_COUNT,
                severity =
                    SSLPinningConfigurationSeverity.CRITICAL,
                title =
                    "Insufficient pins",
                description =
                    "The host does not contain the minimum number of configured pins.",
                value =
                    totalPins.toString(),
                expectedValue =
                    minimumPinsPerHost.toString(),
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Pin format
         * ---------------------------------------------------------
         */
        val publicKeyValidator =
            PublicKeyPinValidator()

        val pinSetResult =
            publicKeyValidator.validatePinSet(
                configuration.allPins()
            )

        checksPerformed++

        if (
            pinSetResult.valid
        ) {

            checksPassed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.PIN_FORMAT_VALID,
                severity =
                    SSLPinningConfigurationSeverity.INFO,
                title =
                    "Host pins are valid",
                description =
                    "All configured public-key pins use the expected SHA-256 format.",
                value =
                    pinSetResult.validPins.toString(),
                valid = true
            )

        } else {

            checksFailed++

            findings += SSLPinningConfigurationFinding(
                type =
                    SSLPinningConfigurationFindingType.INVALID_PIN_FORMAT,
                severity =
                    SSLPinningConfigurationSeverity.CRITICAL,
                title =
                    "Invalid host pin",
                description =
                    "One or more configured public-key pins have an invalid format.",
                value =
                    pinSetResult.invalidPins
                        .joinToString(", "),
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Backup pin
         * ---------------------------------------------------------
         */
        if (
            requireBackupPin
        ) {

            checksPerformed++

            if (
                configuration.backupPins.isNotEmpty()
            ) {

                checksPassed++

                findings += SSLPinningConfigurationFinding(
                    type =
                        SSLPinningConfigurationFindingType.BACKUP_PIN_PRESENT,
                    severity =
                        SSLPinningConfigurationSeverity.INFO,
                    title =
                        "Backup pin configured",
                    description =
                        "The host has at least one backup public-key pin.",
                    valid = true
                )

            } else {

                checksFailed++

                findings += SSLPinningConfigurationFinding(
                    type =
                        SSLPinningConfigurationFindingType.MISSING_BACKUP_PIN,
                    severity =
                        SSLPinningConfigurationSeverity.CRITICAL,
                    title =
                        "Backup pin missing",
                    description =
                        "Production pinning requires a backup public-key pin.",
                    valid = false
                )
            }
        }

        return SSLPinningHostValidationResult(
            valid =
                checksFailed == 0,
            findings =
                findings,
            checksPerformed =
                checksPerformed,
            checksPassed =
                checksPassed,
            checksFailed =
                checksFailed
        )
    }

    /**
     * Basic hostname validation.
     */
    private fun isValidHostname(
        hostname: String
    ): Boolean {

        if (
            hostname.isBlank()
        ) {
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
                "?"
            )
        ) {
            return false
        }

        if (
            hostname.contains(
                "#"
            )
        ) {
            return false
        }

        val wildcard =
            hostname.startsWith(
                "*."
            )

        if (
            wildcard &&
            !wildcardHostsEnabled
        ) {
            return false
        }

        val value =
            if (wildcard) {
                hostname.removePrefix("*.")
            } else {
                hostname
            }

        return value
            .split(".")
            .all { label ->

                label.isNotBlank() &&
                        label.length <= 63 &&
                        label.first() != '-' &&
                        label.last() != '-' &&
                        label.all { character ->

                            character.isLetterOrDigit() ||
                                    character == '-'
                        }
            }
    }

    /**
     * Checks wildcard hostname matching.
     */
    private fun isWildcardHost(
        pattern: String,
        hostname: String
    ): Boolean {

        val normalizedPattern =
            normalizeHostname(
                pattern
            )

        if (
            !normalizedPattern.startsWith(
                "*."
            )
        ) {
            return false
        }

        val suffix =
            normalizedPattern
                .removePrefix(
                    "*."
                )

        if (
            !hostname.endsWith(
                ".$suffix"
            )
        ) {
            return false
        }

        val prefix =
            hostname.removeSuffix(
                ".$suffix"
            )

        return prefix.isNotBlank() &&
                !prefix.contains(".")
    }

    /**
     * Normalizes hostname values.
     */
    private fun normalizeHostname(
        hostname: String
    ): String {

        return hostname
            .trim()
            .lowercase()
            .removeSuffix(".")
    }
}

/**
 * Host-specific SSL pinning configuration.
 *
 * Primary pins identify the currently trusted public keys.
 *
 * Backup pins should normally represent a future/rotation key.
 */
data class SSLHostPinConfiguration(

    /**
     * Whether pinning is enabled for this host.
     */
    val enabled: Boolean = true,

    /**
     * Primary public-key pins.
     */
    val primaryPins:
        Set<String> =
        emptySet(),

    /**
     * Backup public-key pins.
     */
    val backupPins:
        Set<String> =
        emptySet(),

    /**
     * Optional host-specific TLS protocol override.
     *
     * Empty means use global configuration.
     */
    val allowedTlsProtocols:
        Set<String> =
        emptySet(),

    /**
     * Optional host-specific cipher-suite override.
     *
     * Empty means use global configuration.
     */
    val allowedCipherSuites:
        Set<String> =
        emptySet(),

    /**
     * Whether hostname verification is required for this host.
     */
    val hostnameVerificationEnabled: Boolean = true,

    /**
     * Whether certificate-chain validation is required.
     */
    val certificateChainValidationEnabled: Boolean = true,

    /**
     * Optional description for administrative/security reporting.
     */
    val description: String? = null,

    /**
     * Configuration version for this host.
     */
    val version: Int = 1
) {

    /**
     * Returns primary and backup pins combined.
     */
    fun allPins(): Set<String> {

        return primaryPins +
                backupPins
    }

    /**
     * Returns whether at least one pin exists.
     */
    fun hasPins(): Boolean {

        return allPins()
            .isNotEmpty()
    }

    /**
     * Returns whether a backup pin exists.
     */
    fun hasBackupPin(): Boolean {

        return backupPins.isNotEmpty()
    }

    /**
     * Returns total configured pins.
     */
    fun pinCount(): Int {

        return allPins().size
    }
}

/**
 * SSL pinning environment.
 */
enum class SSLPinningEnvironment {

    /**
     * Production application.
     */
    PRODUCTION,

    /**
     * Staging environment.
     */
    STAGING,

    /**
     * Development environment.
     */
    DEVELOPMENT,

    /**
     * Testing environment.
     */
    TEST
}

/**
 * Complete configuration validation result.
 */
data class SSLPinningConfigurationValidationResult(

    /**
     * Overall configuration validity.
     */
    val valid: Boolean,

    /**
     * Configuration findings.
     */
    val findings:
        List<SSLPinningConfigurationFinding>,

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
     * Human-readable summary.
     */
    val message: String
) {

    /**
     * Critical configuration findings.
     */
    val criticalFindings:
        List<SSLPinningConfigurationFinding>
        get() =
            findings.filter {
                it.severity ==
                        SSLPinningConfigurationSeverity.CRITICAL
            }

    /**
     * Whether production deployment should be permitted.
     */
    val productionReady: Boolean
        get() =
            valid &&
                    criticalFindings.isEmpty()
}

/**
 * Host configuration validation result.
 */
data class SSLPinningHostValidationResult(

    /**
     * Whether host configuration is valid.
     */
    val valid: Boolean,

    /**
     * Host findings.
     */
    val findings:
        List<SSLPinningConfigurationFinding>,

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
    val checksFailed: Int
)

/**
 * Individual configuration security finding.
 */
data class SSLPinningConfigurationFinding(

    /**
     * Finding type.
     */
    val type:
        SSLPinningConfigurationFindingType,

    /**
     * Finding severity.
     */
    val severity:
        SSLPinningConfigurationSeverity,

    /**
     * Finding title.
     */
    val title: String,

    /**
     * Detailed explanation.
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
     * Whether the check passed.
     */
    val valid: Boolean
)

/**
 * Configuration finding categories.
 */
enum class SSLPinningConfigurationFindingType {

    /**
     * Minimum pin count is valid.
     */
    MINIMUM_PIN_COUNT_VALID,

    /**
     * Minimum pin count is invalid.
     */
    INVALID_MINIMUM_PIN_COUNT,

    /**
     * TLS protocol configuration is valid.
     */
    TLS_PROTOCOL_CONFIGURATION_VALID,

    /**
     * TLS protocol configuration is invalid.
     */
    INVALID_TLS_PROTOCOL_CONFIGURATION,

    /**
     * Hostname is valid.
     */
    HOSTNAME_VALID,

    /**
     * Hostname is invalid.
     */
    INVALID_HOSTNAME,

    /**
     * Host pin count is valid.
     */
    PIN_COUNT_VALID,

    /**
     * Host does not contain enough pins.
     */
    INSUFFICIENT_PIN_COUNT,

    /**
     * Pin format is valid.
     */
    PIN_FORMAT_VALID,

    /**
     * Pin format is invalid.
     */
    INVALID_PIN_FORMAT,

    /**
     * Backup pin exists.
     */
    BACKUP_PIN_PRESENT,

    /**
     * Backup pin is missing.
     */
    MISSING_BACKUP_PIN,

    /**
     * Backup-pin policy satisfied.
     */
    BACKUP_PIN_POLICY_SATISFIED
}

/**
 * Configuration finding severity.
 */
enum class SSLPinningConfigurationSeverity {

    /**
     * Informational finding.
     */
    INFO,

    /**
     * Low severity.
     */
    LOW,

    /**
     * Medium severity.
     */
    MEDIUM,

    /**
     * High severity.
     */
    HIGH,

    /**
     * Critical security configuration problem.
     */
    CRITICAL
)
