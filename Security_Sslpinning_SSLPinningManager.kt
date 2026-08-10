package com.sentrix.security.sslpinning

import android.content.Context
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import java.util.concurrent.ConcurrentHashMap

/**
 * SSLPinningManager
 *
 * Central manager for SentriX SSL/TLS certificate pinning.
 *
 * Responsibilities:
 *
 * - Register trusted certificate/public-key pins.
 * - Manage pins per hostname.
 * - Build OkHttp clients with CertificatePinner.
 * - Validate pinning configuration.
 * - Enable/disable pinning according to explicit application policy.
 * - Provide pinning status information.
 * - Prevent accidental use of an unpinned client when pinning is
 *   configured as mandatory.
 *
 * Architecture:
 *
 * SentriX Network Layer
 *        ↓
 * SSLPinningManager
 *        ↓
 * CertificatePinner
 *        ↓
 * OkHttpClient
 *        ↓
 * HTTPS Server
 *
 * IMPORTANT:
 *
 * This manager does not disable TLS certificate validation.
 *
 * Certificate pinning is an additional restriction on top of the
 * normal Android/OkHttp trust chain.
 *
 * Pin format:
 *
 * sha256/<base64-SHA256-public-key-hash>
 *
 * Example:
 *
 * sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
 *
 * Production applications should normally provision at least one
 * backup pin to allow controlled certificate/key rotation.
 */
class SSLPinningManager(
    private val context: Context,
    private val configuration: SSLPinningConfiguration =
        SSLPinningConfiguration()
) {

    /**
     * Thread-safe hostname → pin configuration registry.
     */
    private val pinRegistry =
        ConcurrentHashMap<String, SSLPinConfiguration>()

    /**
     * Prevents multiple initialization operations from racing.
     */
    @Volatile
    private var initialized = false

    /**
     * Initializes the manager with the pins provided through
     * SSLPinningConfiguration.
     */
    @Synchronized
    fun initialize(): SSLPinningInitializationResult {

        if (initialized) {

            return SSLPinningInitializationResult(
                success = true,
                alreadyInitialized = true,
                registeredHostCount =
                    pinRegistry.size,
                message =
                    "SSLPinningManager is already initialized."
            )
        }

        pinRegistry.clear()

        val errors =
            mutableListOf<String>()

        configuration
            .pins
            .forEach { pinConfiguration ->

                val validation =
                    validatePinConfiguration(
                        pinConfiguration
                    )

                if (validation.isValid) {

                    pinRegistry[
                        normalizeHostname(
                            pinConfiguration.hostname
                        )
                    ] =
                        pinConfiguration

                } else {

                    errors +=
                        validation.errors
                            .map {
                                "${pinConfiguration.hostname}: $it"
                            }
                }
            }

        if (errors.isNotEmpty()) {

            initialized = false

            return SSLPinningInitializationResult(
                success = false,
                alreadyInitialized = false,
                registeredHostCount =
                    pinRegistry.size,
                message =
                    "SSL pinning initialization failed.",
                errors = errors
            )
        }

        if (
            configuration.pinningRequired &&
            pinRegistry.isEmpty()
        ) {

            initialized = false

            return SSLPinningInitializationResult(
                success = false,
                alreadyInitialized = false,
                registeredHostCount = 0,
                message =
                    "Pinning is required but no valid pins are configured.",
                errors =
                    listOf(
                        "No trusted SSL pin configurations were registered."
                    )
            )
        }

        initialized = true

        return SSLPinningInitializationResult(
            success = true,
            alreadyInitialized = false,
            registeredHostCount =
                pinRegistry.size,
            message =
                "SSL pinning initialized successfully."
        )
    }

    /**
     * Registers or replaces the pin configuration for a hostname.
     *
     * Dynamic registration should normally happen during trusted
     * application initialization rather than from untrusted input.
     */
    @Synchronized
    fun registerPin(
        pinConfiguration: SSLPinConfiguration
    ): SSLPinOperationResult {

        val validation =
            validatePinConfiguration(
                pinConfiguration
            )

        if (!validation.isValid) {

            return SSLPinOperationResult(
                success = false,
                message =
                    "Pin configuration is invalid.",
                errors =
                    validation.errors
            )
        }

        val hostname =
            normalizeHostname(
                pinConfiguration.hostname
            )

        pinRegistry[
            hostname
        ] = pinConfiguration

        return SSLPinOperationResult(
            success = true,
            message =
                "SSL pin configuration registered for $hostname."
        )
    }

    /**
     * Removes the pin configuration for a hostname.
     */
    @Synchronized
    fun removePin(
        hostname: String
    ): SSLPinOperationResult {

        val normalized =
            normalizeHostname(
                hostname
            )

        val removed =
            pinRegistry.remove(
                normalized
            )

        return if (removed != null) {

            SSLPinOperationResult(
                success = true,
                message =
                    "SSL pin configuration removed for $normalized."
            )

        } else {

            SSLPinOperationResult(
                success = false,
                message =
                    "No SSL pin configuration exists for $normalized."
            )
        }
    }

    /**
     * Returns whether a hostname has pinning configured.
     */
    fun isPinned(
        hostname: String
    ): Boolean {

        return pinRegistry.containsKey(
            normalizeHostname(hostname)
        )
    }

    /**
     * Returns the configured pin information for a hostname.
     *
     * The returned configuration contains public pin values and
     * does not contain private keys or credentials.
     */
    fun getPinConfiguration(
        hostname: String
    ): SSLPinConfiguration? {

        return pinRegistry[
            normalizeHostname(hostname)
        ]
    }

    /**
     * Returns all currently registered hostnames.
     */
    fun getPinnedHostnames():
            Set<String> {

        return pinRegistry
            .keys
            .toSet()
    }

    /**
     * Builds an OkHttpClient configured with certificate pinning.
     *
     * When pinningRequired is true, failure to create a correctly
     * pinned client results in an exception rather than silently
     * returning an unprotected client.
     */
    fun buildPinnedClient(
        baseClient: OkHttpClient? = null
    ): OkHttpClient {

        ensureInitialized()

        val certificatePinner =
            buildCertificatePinner()

        val builder =
            (
                baseClient
                    ?: OkHttpClient.Builder()
                )
                .newBuilder()

        builder.certificatePinner(
            certificatePinner
        )

        return builder.build()
    }

    /**
     * Builds the OkHttp CertificatePinner from the registered
     * hostname/pin configuration.
     */
    fun buildCertificatePinner():
            CertificatePinner {

        ensureInitialized()

        val builder =
            CertificatePinner.Builder()

        pinRegistry.values.forEach { pinConfiguration ->

            val hostname =
                normalizeHostname(
                    pinConfiguration.hostname
                )

            pinConfiguration
                .pins
                .forEach { pin ->

                    builder.add(
                        hostname,
                        pin
                    )
                }
        }

        return builder.build()
    }

    /**
     * Validates all currently registered configurations.
     */
    fun validateConfiguration():
            SSLPinningValidationResult {

        val errors =
            mutableListOf<String>()

        val warnings =
            mutableListOf<String>()

        if (pinRegistry.isEmpty()) {

            errors +=
                "No SSL pin configurations are registered."

        }

        pinRegistry.values.forEach { configuration ->

            val validation =
                validatePinConfiguration(
                    configuration
                )

            errors +=
                validation.errors.map {
                    "${configuration.hostname}: $it"
                }

            warnings +=
                validation.warnings.map {
                    "${configuration.hostname}: $it"
                }

            /**
             * Backup-pin recommendation.
             */
            if (
                configuration.pins.size == 1
            ) {

                warnings +=
                    "${configuration.hostname}: " +
                            "Only one pin is configured. " +
                            "Consider a controlled backup pin " +
                            "for key rotation."
            }
        }

        /**
         * Verify mandatory pinning configuration.
         */
        if (
            this.configuration.pinningRequired &&
            pinRegistry.isEmpty()
        ) {

            errors +=
                "Mandatory pinning is enabled without any configured host pins."
        }

        return SSLPinningValidationResult(
            valid =
                errors.isEmpty(),
            errors = errors,
            warnings = warnings
        )
    }

    /**
     * Returns the manager's current status.
     */
    fun getStatus():
            SSLPinningManagerStatus {

        return SSLPinningManagerStatus(
            initialized = initialized,
            pinningRequired =
                configuration.pinningRequired,
            pinnedHostCount =
                pinRegistry.size,
            enabled =
                initialized &&
                        pinRegistry.isNotEmpty()
        )
    }

    /**
     * Returns whether pinning is initialized and active.
     */
    fun isEnabled(): Boolean {

        return initialized &&
                pinRegistry.isNotEmpty()
    }

    /**
     * Returns whether SentriX requires pinning.
     */
    fun isPinningRequired(): Boolean {

        return configuration.pinningRequired
    }

    /**
     * Performs an application-level configuration check.
     *
     * This does not establish a network connection. Actual server
     * certificate validation is performed by OkHttp during the TLS
     * handshake.
     */
    fun checkHostConfiguration(
        hostname: String
    ): SSLPinHostStatus {

        val normalized =
            normalizeHostname(
                hostname
            )

        val pinConfiguration =
            pinRegistry[
                normalized
            ]

        return if (
            pinConfiguration == null
        ) {

            SSLPinHostStatus(
                hostname = normalized,
                pinned = false,
                pinCount = 0,
                status =
                    SSLPinHostConfigurationStatus.NOT_CONFIGURED
            )

        } else {

            SSLPinHostStatus(
                hostname = normalized,
                pinned = true,
                pinCount =
                    pinConfiguration.pins.size,
                status =
                    if (
                        pinConfiguration.pins.isEmpty()
                    ) {
                        SSLPinHostConfigurationStatus.INVALID
                    } else {
                        SSLPinHostConfigurationStatus.CONFIGURED
                    }
            )
        }
    }

    /**
     * Ensures the manager is initialized before building a client
     * or certificate pinner.
     */
    private fun ensureInitialized() {

        if (!initialized) {

            val result =
                initialize()

            if (!result.success) {

                throw SSLPinningConfigurationException(
                    result.message
                )
            }
        }

        if (
            configuration.pinningRequired &&
            pinRegistry.isEmpty()
        ) {

            throw SSLPinningConfigurationException(
                "Mandatory SSL pinning is enabled, " +
                        "but no valid pins are configured."
            )
        }
    }

    /**
     * Validates one hostname/pin configuration.
     */
    private fun validatePinConfiguration(
        pinConfiguration: SSLPinConfiguration
    ): SSLPinValidationResult {

        val errors =
            mutableListOf<String>()

        val warnings =
            mutableListOf<String>()

        val hostname =
            pinConfiguration.hostname.trim()

        if (hostname.isBlank()) {

            errors +=
                "Hostname cannot be blank."
        }

        if (
            hostname.contains(
                "://"
            )
        ) {

            errors +=
                "Hostname must not contain a URL scheme."
        }

        if (
            hostname.contains(
                "/"
            )
        ) {

            errors +=
                "Hostname must not contain a path."
        }

        if (
            hostname.contains(
                ":"
            )
        ) {

            errors +=
                "Hostname must not contain a port."
        }

        if (pinConfiguration.pins.isEmpty()) {

            errors +=
                "At least one certificate pin is required."
        }

        pinConfiguration
            .pins
            .forEach { pin ->

                if (
                    !isValidPinFormat(
                        pin
                    )
                ) {

                    errors +=
                        "Invalid certificate pin format: $pin"
                }
            }

        if (
            pinConfiguration.pins
                .distinct()
                .size !=
            pinConfiguration.pins.size
        ) {

            warnings +=
                "Duplicate certificate pins were configured."
        }

        if (
            pinConfiguration.includeSubdomains
        ) {

            warnings +=
                "Subdomain pinning is enabled; verify that all affected subdomains are trusted."
        }

        return SSLPinValidationResult(
            isValid =
                errors.isEmpty(),
            errors = errors,
            warnings = warnings
        )
    }

    /**
     * Validates the standard OkHttp pin format:
     *
     * sha256/<base64-value>
     */
    private fun isValidPinFormat(
        pin: String
    ): Boolean {

        val trimmed =
            pin.trim()

        if (
            !trimmed.startsWith(
                PIN_PREFIX
            )
        ) {
            return false
        }

        val value =
            trimmed.removePrefix(
                PIN_PREFIX
            )

        /**
         * SHA-256 produces 32 bytes.
         * Base64 encoding of 32 bytes is 44 characters.
         */
        return value.length == 44 &&
                value.matches(
                    Regex(
                        BASE64_SHA256_PATTERN
                    )
                )
    }

    /**
     * Normalizes hostnames.
     */
    private fun normalizeHostname(
        hostname: String
    ): String {

        return hostname
            .trim()
            .lowercase()
            .removeSuffix(".")
    }

    companion object {

        /**
         * OkHttp certificate pin prefix.
         */
        private const val PIN_PREFIX =
            "sha256/"

        /**
         * Base64 character set with optional padding.
         */
        private const val BASE64_SHA256_PATTERN =
            "^[A-Za-z0-9+/]{43}={0,1}$"
    }
}

/**
 * Complete SSL pinning configuration.
 */
data class SSLPinningConfiguration(

    /**
     * Hostname-specific certificate pin definitions.
     */
    val pins:
        List<SSLPinConfiguration> = emptyList(),

    /**
     * Whether SentriX requires certificate pinning.
     *
     * When true, the network layer should not silently fall back
     * to an unpinned client.
     */
    val pinningRequired: Boolean = true
)

/**
 * SSL pin configuration for one hostname.
 */
data class SSLPinConfiguration(

    /**
     * Server hostname.
     *
     * Example:
     *
     * api.sentrix.example
     */
    val hostname: String,

    /**
     * One or more trusted certificate/public-key pins.
     *
     * Recommended format:
     *
     * sha256/<base64-SHA256-public-key-hash>
     */
    val pins: Set<String>,

    /**
     * Whether subdomains should also be covered.
     *
     * Note:
     *
     * This value is informational in this manager. If wildcard or
     * subdomain pinning is required, configure the corresponding
     * OkHttp CertificatePinner hostname pattern explicitly.
     */
    val includeSubdomains: Boolean = false
)

/**
 * Result of SSL pinning initialization.
 */
data class SSLPinningInitializationResult(

    /**
     * Initialization succeeded.
     */
    val success: Boolean,

    /**
     * Indicates the manager was already initialized.
     */
    val alreadyInitialized: Boolean,

    /**
     * Number of registered hosts.
     */
    val registeredHostCount: Int,

    /**
     * Human-readable status.
     */
    val message: String,

    /**
     * Initialization errors.
     */
    val errors: List<String> = emptyList()
)

/**
 * Result of an SSL pinning operation.
 */
data class SSLPinOperationResult(

    /**
     * Operation succeeded.
     */
    val success: Boolean,

    /**
     * Human-readable result.
     */
    val message: String,

    /**
     * Errors associated with the operation.
     */
    val errors: List<String> = emptyList()
)

/**
 * Result of complete pinning configuration validation.
 */
data class SSLPinningValidationResult(

    /**
     * Whether configuration is valid.
     */
    val valid: Boolean,

    /**
     * Validation errors.
     */
    val errors: List<String>,

    /**
     * Non-fatal warnings.
     */
    val warnings: List<String>
)

/**
 * Validation result for an individual pin configuration.
 */
private data class SSLPinValidationResult(

    /**
     * Whether the configuration is valid.
     */
    val isValid: Boolean,

    /**
     * Fatal validation errors.
     */
    val errors: List<String>,

    /**
     * Non-fatal warnings.
     */
    val warnings: List<String>
)

/**
 * Current SSL pinning manager state.
 */
data class SSLPinningManagerStatus(

    /**
     * Manager initialization state.
     */
    val initialized: Boolean,

    /**
     * Whether pinning is mandatory.
     */
    val pinningRequired: Boolean,

    /**
     * Number of pinned hosts.
     */
    val pinnedHostCount: Int,

    /**
     * Whether pinning is currently active.
     */
    val enabled: Boolean
)

/**
 * Host-specific pinning state.
 */
data class SSLPinHostStatus(

    /**
     * Hostname.
     */
    val hostname: String,

    /**
     * Whether pinning is configured.
     */
    val pinned: Boolean,

    /**
     * Number of configured pins.
     */
    val pinCount: Int,

    /**
     * Configuration state.
     */
    val status: SSLPinHostConfigurationStatus
)

/**
 * Host configuration state.
 */
enum class SSLPinHostConfigurationStatus {

    /**
     * No pin configuration exists.
     */
    NOT_CONFIGURED,

    /**
     * Valid configuration exists.
     */
    CONFIGURED,

    /**
     * Configuration exists but is invalid.
     */
    INVALID
}

/**
 * SSL pinning configuration exception.
 */
class SSLPinningConfigurationException(
    message: String
) : IllegalStateException(
    message
)
