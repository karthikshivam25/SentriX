package com.sentrix.security.certificates

import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

/**
 * SentriX Certificate Pin Manager
 *
 * Enterprise-grade certificate pin management component.
 *
 * Responsibilities:
 *
 * - Register certificate SHA-256 pins.
 * - Register Subject Public Key Info (SPKI) SHA-256 pins.
 * - Remove pins.
 * - Query configured pins.
 * - Validate certificates against configured pins.
 * - Support hostname-specific pin policies.
 * - Support pin expiration.
 * - Support backup pins.
 * - Detect pin configuration errors.
 * - Provide auditable pin-validation results.
 *
 * Pin types supported:
 *
 * 1. CERTIFICATE_SHA256
 *    - SHA-256 digest of the complete DER certificate.
 *
 * 2. PUBLIC_KEY_SHA256
 *    - SHA-256 digest of the certificate's Subject Public Key Info.
 *
 * Public-key pinning is generally more resilient to certificate renewal
 * than certificate pinning because the certificate may change while
 * the public key remains the same.
 *
 * This class DOES NOT:
 *
 * - Modify Android's trust store.
 * - Disable TLS validation.
 * - Accept invalid certificates.
 * - Replace TrustManager.
 * - Automatically trust pinned certificates.
 * - Store private keys.
 *
 * Important security boundary:
 *
 *      CertificateTrustManager
 *          │
 *          └── "Is the certificate trusted?"
 *
 *      CertificatePinManager
 *          │
 *          └── "Does the certificate/key match an expected pin?"
 *
 * A certificate MUST still pass ordinary certificate validation and
 * trust checks unless a higher-level security architecture explicitly
 * defines another controlled policy.
 *
 * Architecture:
 *
 *      Certificate
 *          │
 *          ▼
 *      CertificatePinManager
 *          │
 *      ┌───┴──────────────┐
 *      ▼                  ▼
 * Certificate SHA256   Public-Key SHA256
 *      │                  │
 *      └─────────┬────────┘
 *                ▼
 *          PinMatchResult
 */
class CertificatePinManager(
    private val certificateManager: CertificateManager
) {

    /**
     * Hostname/domain-specific pin configurations.
     *
     * ConcurrentHashMap is used because pin configurations may be
     * read by multiple networking threads.
     */
    private val pinConfigurations =
        ConcurrentHashMap<String, CertificatePinConfiguration>()

    // =========================================================================
    // Pin Registration
    // =========================================================================

    /**
     * Registers a complete pin configuration for a host.
     *
     * Existing configuration for the same normalized host is replaced.
     */
    fun registerConfiguration(
        configuration: CertificatePinConfiguration
    ): PinConfigurationResult {

        val validation =
            validateConfiguration(
                configuration
            )

        if (
            validation !is
            PinConfigurationValidation.Valid
        ) {

            return PinConfigurationResult.Invalid(
                validation.reason
            )
        }

        val normalizedHost =
            normalizeHost(
                configuration.host
            )

        pinConfigurations[
            normalizedHost
        ] =
            configuration.copy(
                host =
                    normalizedHost
            )

        return PinConfigurationResult.Registered(
            normalizedHost
        )
    }

    /**
     * Registers a certificate SHA-256 pin.
     */
    fun registerCertificatePin(
        host: String,
        pin: String,
        expiresAtMillis: Long? = null,
        isBackup: Boolean = false
    ): PinConfigurationResult {

        return registerPin(
            host = host,
            pin =
                CertificatePin(
                    value = pin,
                    type =
                        CertificatePinType
                            .CERTIFICATE_SHA256,
                    expiresAtMillis =
                        expiresAtMillis,
                    isBackup =
                        isBackup
                )
        )
    }

    /**
     * Registers a public-key SHA-256 pin.
     */
    fun registerPublicKeyPin(
        host: String,
        pin: String,
        expiresAtMillis: Long? = null,
        isBackup: Boolean = false
    ): PinConfigurationResult {

        return registerPin(
            host = host,
            pin =
                CertificatePin(
                    value = pin,
                    type =
                        CertificatePinType
                            .PUBLIC_KEY_SHA256,
                    expiresAtMillis =
                        expiresAtMillis,
                    isBackup =
                        isBackup
                )
        )
    }

    /**
     * Adds a single pin to an existing host configuration.
     *
     * If the host does not exist, a new configuration is created.
     */
    fun registerPin(
        host: String,
        pin: CertificatePin
    ): PinConfigurationResult {

        val normalizedHost =
            normalizeHost(
                host
            )

        if (
            normalizedHost.isBlank()
        ) {

            return PinConfigurationResult.Invalid(
                "Host must not be blank."
            )
        }

        val pinValidation =
            validatePin(
                pin
            )

        if (
            pinValidation !is
            PinConfigurationValidation.Valid
        ) {

            return PinConfigurationResult.Invalid(
                pinValidation.reason
            )
        }

        pinConfigurations.compute(
            normalizedHost
        ) { _, existing ->

            val current =
                existing
                    ?: CertificatePinConfiguration(
                        host =
                            normalizedHost,
                        pins =
                            emptySet()
                    )

            current.copy(
                pins =
                    current.pins +
                            pin.copy(
                                value =
                                    normalizePin(
                                        pin.value
                                    )
                            )
            )
        }

        return PinConfigurationResult.Registered(
            normalizedHost
        )
    }

    /**
     * Registers multiple pins at once.
     */
    fun registerPins(
        host: String,
        pins: Collection<CertificatePin>
    ): PinConfigurationResult {

        if (
            pins.isEmpty()
        ) {

            return PinConfigurationResult.Invalid(
                "At least one pin is required."
            )
        }

        val normalizedHost =
            normalizeHost(
                host
            )

        for (
            pin in pins
        ) {

            val validation =
                validatePin(
                    pin
                )

            if (
                validation !is
                PinConfigurationValidation.Valid
            ) {

                return PinConfigurationResult.Invalid(
                    validation.reason
                )
            }
        }

        val normalizedPins =
            pins.map {
                it.copy(
                    value =
                        normalizePin(
                            it.value
                        )
                )
            }.toSet()

        pinConfigurations.compute(
            normalizedHost
        ) { _, existing ->

            val current =
                existing
                    ?: CertificatePinConfiguration(
                        host =
                            normalizedHost,
                        pins =
                            emptySet()
                    )

            current.copy(
                pins =
                    current.pins +
                            normalizedPins
            )
        }

        return PinConfigurationResult.Registered(
            normalizedHost
        )
    }

    // =========================================================================
    // Pin Removal
    // =========================================================================

    /**
     * Removes an entire host configuration.
     */
    fun removeConfiguration(
        host: String
    ): Boolean {

        return pinConfigurations.remove(
            normalizeHost(
                host
            )
        ) != null
    }

    /**
     * Removes a specific pin from a host.
     */
    fun removePin(
        host: String,
        pin: String,
        type: CertificatePinType
    ): Boolean {

        val normalizedHost =
            normalizeHost(
                host
            )

        val configuration =
            pinConfigurations[
                normalizedHost
            ]
                ?: return false

        val normalizedPin =
            normalizePin(
                pin
            )

        val matchingPin =
            configuration.pins
                .firstOrNull {
                    it.type == type &&
                            normalizePin(
                                it.value
                            ) == normalizedPin
                }
                ?: return false

        val updatedPins =
            configuration.pins -
                    matchingPin

        if (
            updatedPins.isEmpty()
        ) {

            pinConfigurations.remove(
                normalizedHost
            )

        } else {

            pinConfigurations[
                normalizedHost
            ] =
                configuration.copy(
                    pins =
                        updatedPins
                )
        }

        return true
    }

    /**
     * Removes all configured pins.
     */
    fun clearAll() {
        pinConfigurations.clear()
    }

    // =========================================================================
    // Configuration Lookup
    // =========================================================================

    /**
     * Returns a host's pin configuration.
     */
    fun getConfiguration(
        host: String
    ): CertificatePinConfiguration? {

        return pinConfigurations[
            normalizeHost(
                host
            )
        ]
    }

    /**
     * Returns all configured hostnames.
     */
    fun getConfiguredHosts():
            Set<String> {

        return pinConfigurations.keys.toSet()
    }

    /**
     * Returns all pin configurations.
     */
    fun getAllConfigurations():
            List<CertificatePinConfiguration> {

        return pinConfigurations.values.toList()
    }

    /**
     * Determines whether a host has pinning configured.
     */
    fun isConfigured(
        host: String
    ): Boolean {

        return pinConfigurations.containsKey(
            normalizeHost(
                host
            )
        )
    }

    /**
     * Returns the number of configured pins for a host.
     */
    fun getPinCount(
        host: String
    ): Int {

        return getConfiguration(
            host
        )?.pins?.size ?: 0
    }

    // =========================================================================
    // Certificate Pin Validation
    // =========================================================================

    /**
     * Validates a certificate against the configured pins for a host.
     *
     * A valid certificate must match at least one active configured pin.
     */
    fun validate(
        host: String,
        certificate: X509Certificate
    ): CertificatePinValidationResult {

        return validate(
            host = host,
            certificate = certificate,
            requirePinConfiguration = true
        )
    }

    /**
     * Performs certificate pin validation.
     *
     * If requirePinConfiguration is false, an unconfigured host returns
     * NotConfigured rather than automatically failing.
     */
    fun validate(
        host: String,
        certificate: X509Certificate,
        requirePinConfiguration: Boolean
    ): CertificatePinValidationResult {

        val normalizedHost =
            normalizeHost(
                host
            )

        if (
            normalizedHost.isBlank()
        ) {

            return CertificatePinValidationResult.InvalidHost(
                host
            )
        }

        val configuration =
            findConfiguration(
                normalizedHost
            )

        if (
            configuration == null
        ) {

            return if (
                requirePinConfiguration
            ) {

                CertificatePinValidationResult
                    .PinConfigurationMissing(
                        normalizedHost
                    )

            } else {

                CertificatePinValidationResult
                    .NotConfigured(
                        normalizedHost
                    )
            }
        }

        if (
            !configuration.enabled
        ) {

            return CertificatePinValidationResult
                .PinningDisabled(
                    normalizedHost
                )
        }

        val activePins =
            getActivePins(
                configuration
            )

        if (
            activePins.isEmpty()
        ) {

            return CertificatePinValidationResult
                .NoActivePins(
                    normalizedHost
                )
        }

        return validateAgainstPins(
            certificate =
                certificate,
            pins =
                activePins
        )
    }

    /**
     * Validates a certificate against an explicit collection of pins.
     */
    fun validateAgainstPins(
        certificate: X509Certificate,
        pins: Collection<CertificatePin>
    ): CertificatePinValidationResult {

        if (
            pins.isEmpty()
        ) {

            return CertificatePinValidationResult
                .NoActivePins(
                    null
                )
        }

        val certificateFingerprint =
            try {

                normalizePin(
                    certificateManager
                        .getSha256Fingerprint(
                            certificate
                        )
                )

            } catch (
                exception: Exception
            ) {

                return CertificatePinValidationResult
                    .FingerprintCalculationFailed(
                        exception
                    )
            }

        val publicKeyFingerprint =
            try {

                calculatePublicKeySha256(
                    certificate
                )

            } catch (
                exception: Exception
            ) {

                return CertificatePinValidationResult
                    .FingerprintCalculationFailed(
                        exception
                    )
            }

        val now =
            System.currentTimeMillis()

        val activePins =
            pins.filter {
                it.isActive(
                    now
                )
            }

        for (
            pin in activePins
        ) {

            val normalizedPin =
                normalizePin(
                    pin.value
                )

            val matches =
                when (
                    pin.type
                ) {

                    CertificatePinType
                        .CERTIFICATE_SHA256 ->

                        normalizedPin ==
                                certificateFingerprint

                    CertificatePinType
                        .PUBLIC_KEY_SHA256 ->

                        normalizedPin ==
                                publicKeyFingerprint
                }

            if (
                matches
            ) {

                return CertificatePinValidationResult
                    .Matched(
                        pinType =
                            pin.type,
                        isBackup =
                            pin.isBackup,
                        matchedPin =
                            normalizedPin
                    )
            }
        }

        return CertificatePinValidationResult
            .Mismatch(
                certificateSha256 =
                    certificateFingerprint,
                publicKeySha256 =
                    publicKeyFingerprint
            )
    }

    // =========================================================================
    // Certificate Pin Convenience Methods
    // =========================================================================

    /**
     * Determines whether a certificate matches at least one configured pin.
     */
    fun isPinned(
        host: String,
        certificate: X509Certificate
    ): Boolean {

        return validate(
            host = host,
            certificate = certificate
        ) is
                CertificatePinValidationResult.Matched
    }

    /**
     * Determines whether a certificate matches a certificate SHA-256 pin.
     */
    fun matchesCertificatePin(
        certificate: X509Certificate,
        expectedPin: String
    ): Boolean {

        val actual =
            try {

                certificateManager
                    .getSha256Fingerprint(
                        certificate
                    )

            } catch (
                _: Exception
            ) {

                return false
            }

        return normalizePin(
            actual
        ) ==
                normalizePin(
                    expectedPin
                )
    }

    /**
     * Determines whether a certificate's public key matches a
     * SHA-256 public-key pin.
     */
    fun matchesPublicKeyPin(
        certificate: X509Certificate,
        expectedPin: String
    ): Boolean {

        val actual =
            try {

                calculatePublicKeySha256(
                    certificate
                )

            } catch (
                _: Exception
            ) {

                return false
            }

        return normalizePin(
            actual
        ) ==
                normalizePin(
                    expectedPin
                )
    }

    // =========================================================================
    // Pin Calculation
    // =========================================================================

    /**
     * Calculates SHA-256 over the complete DER certificate.
     *
     * Result format:
     *
     *      AA:BB:CC:...
     */
    fun calculateCertificateSha256(
        certificate: X509Certificate
    ): String {

        val digest =
            MessageDigest.getInstance(
                CertificatePinConstants.SHA_256
            )

        return digestHex(
            digest.digest(
                certificate.encoded
            )
        )
    }

    /**
     * Calculates SHA-256 over the certificate's SubjectPublicKeyInfo.
     *
     * This is the value used for public-key pinning.
     */
    fun calculatePublicKeySha256(
        certificate: X509Certificate
    ): String {

        val digest =
            MessageDigest.getInstance(
                CertificatePinConstants.SHA_256
            )

        return digestHex(
            digest.digest(
                certificate.publicKey.encoded
            )
        )
    }

    /**
     * Calculates a Base64 SHA-256 public-key pin.
     *
     * This representation is useful when integrating with systems that
     * represent SPKI pins as Base64 SHA-256 values.
     */
    fun calculatePublicKeySha256Base64(
        certificate: X509Certificate
    ): String {

        val digest =
            MessageDigest.getInstance(
                CertificatePinConstants.SHA_256
            )

        val hash =
            digest.digest(
                certificate.publicKey.encoded
            )

        return android.util.Base64.encodeToString(
            hash,
            android.util.Base64.NO_WRAP
        )
    }

    /**
     * Calculates a Base64 SHA-256 certificate pin.
     */
    fun calculateCertificateSha256Base64(
        certificate: X509Certificate
    ): String {

        val digest =
            MessageDigest.getInstance(
                CertificatePinConstants.SHA_256
            )

        val hash =
            digest.digest(
                certificate.encoded
            )

        return android.util.Base64.encodeToString(
            hash,
            android.util.Base64.NO_WRAP
        )
    }

    /**
     * Converts a byte array into colon-separated uppercase hexadecimal.
     */
    private fun digestHex(
        bytes: ByteArray
    ): String {

        return bytes.joinToString(":") {
            "%02X".format(
                it.toInt() and 0xFF
            )
        }
    }

    // =========================================================================
    // Active Pins
    // =========================================================================

    /**
     * Returns all currently active pins.
     */
    fun getActivePins(
        host: String
    ): List<CertificatePin> {

        val configuration =
            getConfiguration(
                host
            )
                ?: return emptyList()

        return getActivePins(
            configuration
        )
    }

    /**
     * Filters a configuration to currently active pins.
     */
    private fun getActivePins(
        configuration: CertificatePinConfiguration
    ): List<CertificatePin> {

        val now =
            System.currentTimeMillis()

        return configuration.pins
            .filter {
                it.isActive(
                    now
                )
            }
    }

    /**
     * Returns expired pins for diagnostics.
     */
    fun getExpiredPins(
        host: String
    ): List<CertificatePin> {

        val configuration =
            getConfiguration(
                host
            )
                ?: return emptyList()

        val now =
            System.currentTimeMillis()

        return configuration.pins
            .filter {
                it.expiresAtMillis != null &&
                        it.expiresAtMillis <= now
            }
    }

    /**
     * Determines whether a host has at least one active backup pin.
     */
    fun hasBackupPin(
        host: String
    ): Boolean {

        return getActivePins(
            host
        ).any {
            it.isBackup
        }
    }

    /**
     * Determines whether a host has at least one active primary pin.
     */
    fun hasPrimaryPin(
        host: String
    ): Boolean {

        return getActivePins(
            host
        ).any {
            !it.isBackup
        }
    }

    // =========================================================================
    // Host Matching
    // =========================================================================

    /**
     * Finds an exact host configuration first.
     *
     * Wildcard configurations are then considered if enabled.
     *
     * Example:
     *
     *      api.example.com
     *
     * can match:
     *
     *      *.example.com
     */
    private fun findConfiguration(
        host: String
    ): CertificatePinConfiguration? {

        val normalized =
            normalizeHost(
                host
            )

        // Exact match has priority.
        pinConfigurations[
            normalized
        ]?.let {
            return it
        }

        // Wildcard lookup.
        val labels =
            normalized.split(
                "."
            )

        if (
            labels.size < 2
        ) {

            return null
        }

        for (
            index in 0 until labels.lastIndex
        ) {

            val wildcardHost =
                "*." +
                        labels
                            .drop(
                                index + 1
                            )
                            .joinToString(
                                "."
                            )

            val configuration =
                pinConfigurations[
                    wildcardHost
                ]

            if (
                configuration != null &&
                configuration.allowSubdomains
            ) {

                return configuration
            }
        }

        return null
    }

    /**
     * Normalizes a hostname for configuration lookup.
     */
    private fun normalizeHost(
        host: String
    ): String {

        return host
            .trim()
            .lowercase()
            .removeSuffix(".")
    }

    // =========================================================================
    // Configuration Validation
    // =========================================================================

    /**
     * Validates a complete pin configuration.
     */
    private fun validateConfiguration(
        configuration: CertificatePinConfiguration
    ): PinConfigurationValidation {

        if (
            configuration.host.isBlank()
        ) {

            return PinConfigurationValidation.Invalid(
                "Pin configuration host must not be blank."
            )
        }

        if (
            configuration.pins.isEmpty()
        ) {

            return PinConfigurationValidation.Invalid(
                "Pin configuration must contain at least one pin."
            )
        }

        if (
            configuration.pins.size >
            CertificatePinConstants
                .MAX_PINS_PER_HOST
        ) {

            return PinConfigurationValidation.Invalid(
                "Too many pins configured for one host."
            )
        }

        for (
            pin in configuration.pins
        ) {

            val result =
                validatePin(
                    pin
                )

            if (
                result !is
                PinConfigurationValidation.Valid
            ) {

                return result
            }
        }

        return PinConfigurationValidation.Valid
    }

    /**
     * Validates a single certificate pin.
     */
    private fun validatePin(
        pin: CertificatePin
    ): PinConfigurationValidation {

        if (
            pin.value.isBlank()
        ) {

            return PinConfigurationValidation.Invalid(
                "Pin value must not be blank."
            )
        }

        val normalized =
            normalizePin(
                pin.value
            )

        /**
         * SHA-256 always contains 32 bytes.
         *
         * Hex representation therefore contains 64 characters.
         */
        if (
            normalized.length !=
            CertificatePinConstants
                .SHA_256_HEX_LENGTH
        ) {

            /**
             * Base64 pins are also accepted.
             *
             * SHA-256 Base64 representation is normally 44 characters
             * including padding.
             */
            val isBase64 =
                try {

                    val decoded =
                        android.util.Base64.decode(
                            pin.value,
                            android.util.Base64.DEFAULT
                        )

                    decoded.size ==
                            CertificatePinConstants
                                .SHA_256_BYTE_LENGTH

                } catch (
                    _: Exception
                ) {

                    false
                }

            if (
                !isBase64
            ) {

                return PinConfigurationValidation.Invalid(
                    "Pin must be a SHA-256 fingerprint in hexadecimal " +
                            "or Base64 format."
                )
            }
        }

        if (
            pin.expiresAtMillis != null &&
            pin.expiresAtMillis <=
            0L
        ) {

            return PinConfigurationValidation.Invalid(
                "Pin expiration timestamp is invalid."
            )
        }

        return PinConfigurationValidation.Valid
    }

    // =========================================================================
    // Pin Normalization
    // =========================================================================

    /**
     * Normalizes hexadecimal fingerprints.
     *
     * Base64 values are preserved as normalized strings.
     */
    private fun normalizePin(
        pin: String
    ): String {

        val trimmed =
            pin.trim()

        val compact =
            trimmed
                .replace(
                    ":",
                    ""
                )
                .replace(
                    "-",
                    ""
                )
                .replace(
                    " ",
                    ""
                )

        return if (
            compact.matches(
                Regex(
                    "[0-9A-Fa-f]+"
                )
            )
        ) {

            compact.uppercase()

        } else {

            compact
        }
    }

    // =========================================================================
    // Constant-Time Comparison
    // =========================================================================

    /**
     * Performs constant-time comparison of two byte arrays.
     *
     * This is useful when comparing sensitive cryptographic material.
     */
    fun constantTimeEquals(
        first: ByteArray,
        second: ByteArray
    ): Boolean {

        return MessageDigest.isEqual(
            first,
            second
        )
    }

    /**
     * Performs constant-time comparison of two SHA-256 hexadecimal
     * fingerprints.
     */
    fun constantTimePinEquals(
        first: String,
        second: String
    ): Boolean {

        val firstBytes =
            pinToBytes(
                first
            )

        val secondBytes =
            pinToBytes(
                second
            )

        if (
            firstBytes == null ||
            secondBytes == null
        ) {

            return false
        }

        return constantTimeEquals(
            firstBytes,
            secondBytes
        )
    }

    /**
     * Converts a hexadecimal SHA-256 fingerprint into bytes.
     */
    private fun pinToBytes(
        pin: String
    ): ByteArray? {

        val normalized =
            normalizePin(
                pin
            )

        if (
            normalized.length !=
            CertificatePinConstants
                .SHA_256_HEX_LENGTH
        ) {

            return null
        }

        return try {

            ByteArray(
                normalized.length / 2
            ) { index ->

                normalized
                    .substring(
                        index * 2,
                        index * 2 + 2
                    )
                    .toInt(
                        16
                    )
                    .toByte()
            }

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Configuration Health
    // =========================================================================

    /**
     * Performs a configuration health check for a host.
     */
    fun checkConfigurationHealth(
        host: String
    ): CertificatePinConfigurationHealth {

        val configuration =
            getConfiguration(
                host
            )
                ?: return CertificatePinConfigurationHealth(
                    host =
                        normalizeHost(
                            host
                        ),
                    configured =
                        false,
                    activePinCount =
                        0,
                    primaryPinCount =
                        0,
                    backupPinCount =
                        0,
                    expiredPinCount =
                        0,
                    healthy =
                        false
                )

        val activePins =
            getActivePins(
                configuration
            )

        val expiredPins =
            getExpiredPins(
                host
            )

        val primaryPins =
            activePins.count {
                !it.isBackup
            }

        val backupPins =
            activePins.count {
                it.isBackup
            }

        return CertificatePinConfigurationHealth(
            host =
                configuration.host,
            configured =
                true,
            activePinCount =
                activePins.size,
            primaryPinCount =
                primaryPins,
            backupPinCount =
                backupPins,
            expiredPinCount =
                expiredPins.size,
            healthy =
                configuration.enabled &&
                        activePins.isNotEmpty() &&
                        primaryPins > 0
        )
    }

    // =========================================================================
    // Certificate Pin Inventory
    // =========================================================================

    /**
     * Returns a safe inventory of configured pin metadata.
     *
     * The actual pin values are not returned by this diagnostic method.
     */
    fun getPinInventory():
            List<CertificatePinInventoryItem> {

        return pinConfigurations
            .values
            .flatMap { configuration ->

                configuration.pins.map { pin ->

                    CertificatePinInventoryItem(

                        host =
                            configuration.host,

                        type =
                            pin.type,

                        isBackup =
                            pin.isBackup,

                        expiresAtMillis =
                            pin.expiresAtMillis,

                        active =
                            pin.isActive(
                                System.currentTimeMillis()
                            )
                    )
                }
            }
    }
}

/**
 * Certificate pin configuration for a host.
 */
data class CertificatePinConfiguration(

    /**
     * Hostname or wildcard hostname.
     */
    val host: String,

    /**
     * Configured certificate/public-key pins.
     */
    val pins: Set<CertificatePin>,

    /**
     * Whether pin validation is enabled.
     */
    val enabled: Boolean = true,

    /**
     * Whether wildcard configuration can match subdomains.
     */
    val allowSubdomains: Boolean = false
)

/**
 * Individual certificate pin.
 */
data class CertificatePin(

    /**
     * SHA-256 pin value.
     */
    val value: String,

    /**
     * Type of identity being pinned.
     */
    val type: CertificatePinType,

    /**
     * Optional expiration timestamp.
     */
    val expiresAtMillis: Long? = null,

    /**
     * Indicates whether this is a backup pin.
     */
    val isBackup: Boolean = false
) {

    /**
     * Determines whether this pin is currently active.
     */
    fun isActive(
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Boolean {

        return expiresAtMillis == null ||
                expiresAtMillis >
                currentTimeMillis
    }
}

/**
 * Supported certificate pin types.
 */
enum class CertificatePinType {

    /**
     * SHA-256 digest of the entire DER encoded certificate.
     */
    CERTIFICATE_SHA256,

    /**
     * SHA-256 digest of the DER encoded SubjectPublicKeyInfo.
     */
    PUBLIC_KEY_SHA256
}

/**
 * Result of adding/removing certificate pins.
 */
sealed class PinConfigurationResult {

    /**
     * Pin configuration was successfully registered.
     */
    data class Registered(
        val host: String
    ) : PinConfigurationResult()

    /**
     * Pin configuration was invalid.
     */
    data class Invalid(
        val reason: String
    ) : PinConfigurationResult()
}

/**
 * Result of certificate pin validation.
 */
sealed class CertificatePinValidationResult {

    /**
     * Certificate matched an active pin.
     */
    data class Matched(

        val pinType:
            CertificatePinType,

        val isBackup: Boolean,

        val matchedPin: String

    ) : CertificatePinValidationResult()

    /**
     * Certificate did not match any configured pin.
     *
     * The calculated values are included for diagnostic/audit purposes.
     */
    data class Mismatch(

        val certificateSha256: String,

        val publicKeySha256: String

    ) : CertificatePinValidationResult()

    /**
     * No pin configuration exists for the host.
     */
    data class PinConfigurationMissing(
        val host: String
    ) : CertificatePinValidationResult()

    /**
     * Host does not have pinning configured.
     */
    data class NotConfigured(
        val host: String
    ) : CertificatePinValidationResult()

    /**
     * Pinning has been disabled for this host.
     */
    data class PinningDisabled(
        val host: String
    ) : CertificatePinValidationResult()

    /**
     * Configuration exists but contains no active pins.
     */
    data class NoActivePins(
        val host: String?
    ) : CertificatePinValidationResult()

    /**
     * Host input is invalid.
     */
    data class InvalidHost(
        val host: String
    ) : CertificatePinValidationResult()

    /**
     * SHA-256 calculation failed.
     */
    data class FingerprintCalculationFailed(
        val cause: Throwable
    ) : CertificatePinValidationResult()
}

/**
 * Internal pin configuration validation result.
 */
private sealed class PinConfigurationValidation {

    data object Valid :
        PinConfigurationValidation()

    data class Invalid(
        val reason: String
    ) : PinConfigurationValidation()
}

/**
 * Pin configuration health information.
 */
data class CertificatePinConfigurationHealth(

    val host: String,

    val configured: Boolean,

    val activePinCount: Int,

    val primaryPinCount: Int,

    val backupPinCount: Int,

    val expiredPinCount: Int,

    val healthy: Boolean
)

/**
 * Safe pin inventory entry.
 *
 * The actual cryptographic pin value is intentionally not exposed.
 */
data class CertificatePinInventoryItem(

    val host: String,

    val type: CertificatePinType,

    val isBackup: Boolean,

    val expiresAtMillis: Long?,

    val active: Boolean
)

/**
 * Internal constants for CertificatePinManager.
 */
private object CertificatePinConstants {

    const val SHA_256 =
        "SHA-256"

    const val SHA_256_BYTE_LENGTH =
        32

    const val SHA_256_HEX_LENGTH =
        64

    /**
     * Prevents accidentally loading an excessive number of pins
     * into one hostname configuration.
     */
    const val MAX_PINS_PER_HOST =
        20
}
