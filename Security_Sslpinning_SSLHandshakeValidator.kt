package com.sentrix.security.sslpinning

import android.content.Context
import android.os.Build
import java.net.IDN
import java.net.InetAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket

/**
 * SSLHandshakeValidator
 *
 * Enterprise-grade TLS handshake validation component for SentriX.
 *
 * Responsibilities:
 *
 * - Validate an established SSL/TLS session.
 * - Validate negotiated TLS protocol.
 * - Validate negotiated cipher suite.
 * - Validate peer certificate availability.
 * - Validate certificate chain structure.
 * - Validate certificate validity periods.
 * - Validate hostname information.
 * - Validate public-key pins when configured.
 * - Produce structured handshake security reports.
 *
 * IMPORTANT:
 *
 * This validator operates on an already-established TLS session.
 *
 * It does NOT:
 *
 * - accept invalid certificates.
 * - replace Android's TrustManager.
 * - disable hostname verification.
 * - disable OkHttp CertificatePinner.
 * - establish trust by itself.
 *
 * Normal TLS trust validation should happen during the handshake.
 * This component performs additional SentriX security inspection
 * after a successful TLS negotiation.
 *
 * Recommended flow:
 *
 *     TLS Handshake
 *          ↓
 * Android TrustManager
 *          ↓
 * Hostname Verification
 *          ↓
 * OkHttp CertificatePinner
 *          ↓
 * SSLHandshakeValidator
 *          ↓
 * SentriX Security Report
 */
class SSLHandshakeValidator(
    private val context: Context,
    private val certificatePinValidator:
        CertificatePinValidator,
    private val publicKeyPinValidator:
        PublicKeyPinValidator,
    private val configuration:
        SSLHandshakeValidatorConfiguration =
        SSLHandshakeValidatorConfiguration()
) {

    /**
     * Validates an established SSLSession.
     *
     * The session should already have completed a successful TLS
     * handshake before calling this method.
     */
    fun validate(
        session: SSLSession,
        expectedHostname: String? = null,
        configuredPins: Set<String> = emptySet()
    ): SSLHandshakeValidationResult {

        val findings =
            mutableListOf<SSLHandshakeFinding>()

        var checksPerformed = 0
        var checksPassed = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * 1. TLS session validity
         * ---------------------------------------------------------
         */
        checksPerformed++

        val sessionValid =
            validateSessionObject(
                session
            )

        if (sessionValid) {

            checksPassed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.SESSION_VALID,
                severity =
                    SSLHandshakeFindingSeverity.INFO,
                title =
                    "TLS session available",
                description =
                    "A valid SSL/TLS session is available for inspection.",
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.SESSION_INVALID,
                severity =
                    SSLHandshakeFindingSeverity.CRITICAL,
                title =
                    "Invalid TLS session",
                description =
                    "The SSL/TLS session could not be validated.",
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 2. TLS protocol
         * ---------------------------------------------------------
         */
        checksPerformed++

        val protocol =
            try {
                session.protocol
            } catch (_: Exception) {
                null
            }

        if (
            protocol != null &&
            isAllowedProtocol(
                protocol
            )
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.PROTOCOL_VALID,
                severity =
                    SSLHandshakeFindingSeverity.INFO,
                title =
                    "TLS protocol accepted",
                description =
                    "The negotiated TLS protocol satisfies the SentriX security policy.",
                value =
                    protocol,
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.PROTOCOL_WEAK,
                severity =
                    SSLHandshakeFindingSeverity.CRITICAL,
                title =
                    "TLS protocol rejected",
                description =
                    "The negotiated TLS protocol does not satisfy the configured SentriX policy.",
                value =
                    protocol,
                expectedValue =
                    configuration
                        .allowedProtocols
                        .joinToString(", "),
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 3. Cipher suite
         * ---------------------------------------------------------
         */
        checksPerformed++

        val cipherSuite =
            try {
                session.cipherSuite
            } catch (_: Exception) {
                null
            }

        if (
            cipherSuite != null &&
            isAllowedCipherSuite(
                cipherSuite
            )
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.CIPHER_SUITE_VALID,
                severity =
                    SSLHandshakeFindingSeverity.INFO,
                title =
                    "TLS cipher suite accepted",
                description =
                    "The negotiated cipher suite satisfies the SentriX security policy.",
                value =
                    cipherSuite,
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.CIPHER_SUITE_WEAK,
                severity =
                    SSLHandshakeFindingSeverity.HIGH,
                title =
                    "TLS cipher suite rejected",
                description =
                    "The negotiated cipher suite does not satisfy the SentriX security policy.",
                value =
                    cipherSuite,
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 4. Hostname
         * ---------------------------------------------------------
         */
        if (
            expectedHostname != null
        ) {

            checksPerformed++

            val hostnameResult =
                validateHostname(
                    session = session,
                    expectedHostname =
                        expectedHostname
                )

            if (
                hostnameResult.valid
            ) {

                checksPassed++

            } else {

                checksFailed++
            }

            findings +=
                hostnameResult.findings
        }

        /**
         * ---------------------------------------------------------
         * 5. Peer certificates
         * ---------------------------------------------------------
         */
        checksPerformed++

        val peerCertificates =
            try {

                session
                    .peerCertificates

            } catch (_: SSLPeerUnverifiedException) {

                null

            } catch (_: Exception) {

                null
            }

        if (
            peerCertificates != null &&
            peerCertificates.isNotEmpty()
        ) {

            checksPassed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.PEER_CERTIFICATES_AVAILABLE,
                severity =
                    SSLHandshakeFindingSeverity.INFO,
                title =
                    "Peer certificate chain available",
                description =
                    "The TLS session provided a peer certificate chain.",
                value =
                    peerCertificates.size.toString(),
                valid = true
            )

        } else {

            checksFailed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.PEER_CERTIFICATES_UNAVAILABLE,
                severity =
                    SSLHandshakeFindingSeverity.CRITICAL,
                title =
                    "Peer certificates unavailable",
                description =
                    "The peer certificate chain could not be retrieved.",
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 6. Certificate chain
         * ---------------------------------------------------------
         */
        val x509Chain =
            peerCertificates
                ?.mapNotNull {
                    it as? X509Certificate
                }
                ?: emptyList()

        if (
            x509Chain.isNotEmpty()
        ) {

            val chainResult =
                validateCertificateChain(
                    x509Chain
                )

            checksPerformed +=
                chainResult.checksPerformed

            checksPassed +=
                chainResult.checksPassed

            checksFailed +=
                chainResult.checksFailed

            findings +=
                chainResult.findings
        }

        /**
         * ---------------------------------------------------------
         * 7. Public-key pin validation
         * ---------------------------------------------------------
         */
        if (
            configuredPins.isNotEmpty() &&
            x509Chain.isNotEmpty()
        ) {

            checksPerformed++

            val pinResult =
                publicKeyPinValidator
                    .validateCertificateKey(
                        certificate =
                            x509Chain.first(),
                        pins =
                            configuredPins
                    )

            if (
                pinResult.valid
            ) {

                checksPassed++

                findings += finding(
                    type =
                        SSLHandshakeFindingType.PUBLIC_KEY_PIN_MATCH,
                    severity =
                        SSLHandshakeFindingSeverity.INFO,
                    title =
                        "Public-key pin matched",
                    description =
                        "The peer certificate public key matched a configured SentriX pin.",
                    value =
                        maskPin(
                            pinResult.matchedPin
                        ),
                    valid = true
                )

            } else {

                checksFailed++

                findings += finding(
                    type =
                        SSLHandshakeFindingType.PUBLIC_KEY_PIN_MISMATCH,
                    severity =
                        SSLHandshakeFindingSeverity.CRITICAL,
                    title =
                        "Public-key pin mismatch",
                    description =
                        "The peer certificate public key did not match any configured SentriX pin.",
                    value =
                        maskPin(
                            pinResult.calculatedPin
                        ),
                    valid = false
                )
            }
        }

        /**
         * ---------------------------------------------------------
         * 8. Certificate expiry
         * ---------------------------------------------------------
         */
        if (
            x509Chain.isNotEmpty()
        ) {

            val expiryResult =
                validateCertificateExpiry(
                    x509Chain
                )

            checksPerformed +=
                expiryResult.checksPerformed

            checksPassed +=
                expiryResult.checksPassed

            checksFailed +=
                expiryResult.checksFailed

            findings +=
                expiryResult.findings
        }

        /**
         * ---------------------------------------------------------
         * 9. TLS session metadata
         * ---------------------------------------------------------
         */
        val sessionInfo =
            buildSessionInfo(
                session
            )

        /**
         * ---------------------------------------------------------
         * Final status
         * ---------------------------------------------------------
         */
        val status =
            determineStatus(
                findings
            )

        return SSLHandshakeValidationResult(
            valid =
                status ==
                        SSLHandshakeValidationStatus.VALID ||
                        status ==
                        SSLHandshakeValidationStatus.VALID_WITH_WARNINGS,
            status =
                status,
            findings =
                findings,
            sessionInfo =
                sessionInfo,
            checksPerformed =
                checksPerformed,
            checksPassed =
                checksPassed,
            checksFailed =
                checksFailed,
            validatedAt =
                System.currentTimeMillis()
        )
    }

    /**
     * Validates an SSLSocket after the TLS handshake.
     *
     * If the socket has not completed its handshake, the method
     * performs the handshake before inspection.
     */
    fun validateSocket(
        socket: SSLSocket,
        expectedHostname: String? = null,
        configuredPins: Set<String> = emptySet()
    ): SSLHandshakeValidationResult {

        if (
            !socket.isConnected
        ) {

            return invalidResult(
                "SSL socket is not connected."
            )
        }

        return try {

            /**
             * Ensure a completed handshake.
             */
            socket.startHandshake()

            validate(
                session =
                    socket.session,
                expectedHostname =
                    expectedHostname
                        ?: socket.inetAddress?.hostName,
                configuredPins =
                    configuredPins
            )

        } catch (exception: Exception) {

            invalidResult(
                message =
                    "TLS handshake validation failed.",
                errorType =
                    exception.javaClass.simpleName
            )
        }
    }

    /**
     * Validates a certificate chain independently.
     */
    fun validateCertificateChain(
        chain: List<X509Certificate>
    ): SSLHandshakeCertificateChainResult {

        val findings =
            mutableListOf<SSLHandshakeFinding>()

        var checksPerformed = 0
        var checksPassed = 0
        var checksFailed = 0

        if (
            chain.isEmpty()
        ) {

            return SSLHandshakeCertificateChainResult(
                valid = false,
                findings =
                    listOf(
                        finding(
                            type =
                                SSLHandshakeFindingType.CERTIFICATE_CHAIN_EMPTY,
                            severity =
                                SSLHandshakeFindingSeverity.CRITICAL,
                            title =
                                "Certificate chain empty",
                            description =
                                "No X509 certificates were supplied.",
                            valid = false
                        )
                    ),
                checksPerformed = 1,
                checksPassed = 0,
                checksFailed = 1
            )
        }

        /**
         * Validate each certificate's validity period.
         */
        chain.forEachIndexed { index, certificate ->

            checksPerformed++

            val valid =
                isCertificateValid(
                    certificate
                )

            if (valid) {

                checksPassed++

                findings += finding(
                    type =
                        SSLHandshakeFindingType.CERTIFICATE_VALID,
                    severity =
                        SSLHandshakeFindingSeverity.INFO,
                    title =
                        "Certificate validity period accepted",
                    description =
                        "Certificate $index is currently within its validity period.",
                    value =
                        safeSubject(
                            certificate
                        ),
                    valid = true
                )

            } else {

                checksFailed++

                findings += finding(
                    type =
                        SSLHandshakeFindingType.CERTIFICATE_EXPIRED,
                    severity =
                        SSLHandshakeFindingSeverity.CRITICAL,
                    title =
                        "Certificate validity period rejected",
                    description =
                        "Certificate $index is expired or not yet valid.",
                    value =
                        safeSubject(
                            certificate
                        ),
                    valid = false
                )
            }
        }

        /**
         * Validate chain ordering.
         */
        checksPerformed++

        val chainOrdered =
            validateChainOrdering(
                chain
            )

        if (chainOrdered) {

            checksPassed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.CERTIFICATE_CHAIN_ORDER_VALID,
                severity =
                    SSLHandshakeFindingSeverity.INFO,
                title =
                    "Certificate chain order valid",
                description =
                    "Each certificate is consistent with the issuer relationship of the next certificate.",
                valid = true
            )

        } else {

            /**
             * Chain ordering is diagnostic here. The platform
             * TrustManager remains authoritative for actual
             * certificate-chain trust.
             */
            checksFailed++

            findings += finding(
                type =
                    SSLHandshakeFindingType.CERTIFICATE_CHAIN_ORDER_INVALID,
                severity =
                    SSLHandshakeFindingSeverity.MEDIUM,
                title =
                    "Certificate chain order requires review",
                description =
                    "The supplied certificate chain does not appear to follow the expected issuer relationship.",
                valid = false
            )
        }

        return SSLHandshakeCertificateChainResult(
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
     * Validates expected hostname against the TLS session.
     *
     * This is a supplementary check. Platform/OkHttp hostname
     * verification remains authoritative.
     */
    private fun validateHostname(
        session: SSLSession,
        expectedHostname: String
    ): SSLHandshakeHostnameResult {

        val findings =
            mutableListOf<SSLHandshakeFinding>()

        val normalizedExpected =
            normalizeHostname(
                expectedHostname
            )

        val peerHost =
            try {
                normalizeHostname(
                    session.peerHost
                )
            } catch (_: Exception) {
                ""
            }

        /**
         * A direct peerHost match is useful as a sanity check,
         * but does not replace certificate hostname verification.
         */
        if (
            normalizedExpected.isNotBlank() &&
            peerHost.isNotBlank() &&
            normalizedExpected ==
            peerHost
        ) {

            findings += finding(
                type =
                    SSLHandshakeFindingType.HOSTNAME_MATCH,
                severity =
                    SSLHandshakeFindingSeverity.INFO,
                title =
                    "TLS peer hostname matches expected host",
                description =
                    "The TLS session peer hostname matches the expected hostname.",
                value =
                    normalizedExpected,
                valid = true
            )

            return SSLHandshakeHostnameResult(
                valid = true,
                findings = findings
            )
        }

        /**
         * Try certificate SAN/CN matching as an additional
         * diagnostic validation.
         */
        val certificates =
            try {
                session.peerCertificates
                    .mapNotNull {
                        it as? X509Certificate
                    }
            } catch (_: Exception) {
                emptyList()
            }

        val certificateMatches =
            certificates.any {
                certificateMatchesHostname(
                    certificate = it,
                    hostname =
                        normalizedExpected
                )
            }

        if (certificateMatches) {

            findings += finding(
                type =
                    SSLHandshakeFindingType.CERTIFICATE_HOSTNAME_MATCH,
                severity =
                    SSLHandshakeFindingSeverity.INFO,
                title =
                    "Certificate hostname matches",
                description =
                    "The peer certificate contains a matching hostname identity.",
                value =
                    normalizedExpected,
                valid = true
            )

            return SSLHandshakeHostnameResult(
                valid = true,
                findings = findings
            )
        }

        findings += finding(
            type =
                SSLHandshakeFindingType.HOSTNAME_MISMATCH,
            severity =
                SSLHandshakeFindingSeverity.CRITICAL,
            title =
                "TLS hostname mismatch",
            description =
                "The expected hostname could not be matched to the TLS peer.",
            value =
                normalizedExpected,
            expectedValue =
                peerHost,
            valid = false
        )

        return SSLHandshakeHostnameResult(
            valid = false,
            findings = findings
        )
    }

    /**
     * Checks whether a certificate is currently valid.
     */
    private fun isCertificateValid(
        certificate: X509Certificate
    ): Boolean {

        return try {

            certificate.checkValidity()

            true

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Validates the basic issuer/subject relationship in a
     * certificate chain.
     *
     * This is diagnostic only. It does not replace TrustManager
     * path validation.
     */
    private fun validateChainOrdering(
        chain: List<X509Certificate>
    ): Boolean {

        if (
            chain.size <= 1
        ) {
            return true
        }

        for (
            index in 0 until chain.lastIndex
        ) {

            val current =
                chain[index]

            val issuer =
                chain[index + 1]

            if (
                current.issuerX500Principal !=
                issuer.subjectX500Principal
            ) {

                return false
            }
        }

        return true
    }

    /**
     * Validates certificate expiry state for the entire chain.
     */
    private fun validateCertificateExpiry(
        chain: List<X509Certificate>
    ): SSLHandshakeCertificateExpiryResult {

        val findings =
            mutableListOf<SSLHandshakeFinding>()

        var checksPassed = 0
        var checksFailed = 0

        chain.forEachIndexed { index, certificate ->

            val valid =
                isCertificateValid(
                    certificate
                )

            if (valid) {

                checksPassed++

            } else {

                checksFailed++
            }

            findings += finding(
                type =
                    if (valid) {
                        SSLHandshakeFindingType.CERTIFICATE_VALID
                    } else {
                        SSLHandshakeFindingType.CERTIFICATE_EXPIRED
                    },
                severity =
                    if (valid) {
                        SSLHandshakeFindingSeverity.INFO
                    } else {
                        SSLHandshakeFindingSeverity.CRITICAL
                    },
                title =
                    if (valid) {
                        "Certificate $index is valid"
                    } else {
                        "Certificate $index is expired or not yet valid"
                    },
                description =
                    "Certificate validity was checked.",
                value =
                    safeSubject(
                        certificate
                    ),
                valid = valid
            )
        }

        return SSLHandshakeCertificateExpiryResult(
            findings =
                findings,
            checksPerformed =
                chain.size,
            checksPassed =
                checksPassed,
            checksFailed =
                checksFailed
        )
    }

    /**
     * Determines whether the negotiated TLS protocol is allowed.
     */
    private fun isAllowedProtocol(
        protocol: String
    ): Boolean {

        return configuration
            .allowedProtocols
            .contains(
                protocol
            )
    }

    /**
     * Determines whether the negotiated cipher suite is allowed.
     */
    private fun isAllowedCipherSuite(
        cipherSuite: String
    ): Boolean {

        /**
         * If no explicit cipher allowlist is configured, reject
         * only obviously weak/obsolete cipher suites.
         */
        if (
            configuration
                .allowedCipherSuites
                .isEmpty()
        ) {

            val upper =
                cipherSuite.uppercase()

            val forbiddenTokens =
                listOf(
                    "_NULL_",
                    "_ANON_",
                    "_EXPORT_",
                    "_RC4_",
                    "_DES_",
                    "_3DES_",
                    "_MD5",
                    "_RC2_"
                )

            return forbiddenTokens.none {
                upper.contains(it)
            }
        }

        return configuration
            .allowedCipherSuites
            .contains(
                cipherSuite
            )
    }

    /**
     * Basic SSL session sanity check.
     */
    private fun validateSessionObject(
        session: SSLSession
    ): Boolean {

        return try {

            session.protocol.isNotBlank() &&
                    session.cipherSuite.isNotBlank()

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Builds a structured session-information object.
     */
    private fun buildSessionInfo(
        session: SSLSession
    ): SSLHandshakeSessionInfo {

        val peerHost =
            try {
                session.peerHost
            } catch (_: Exception) {
                null
            }

        val peerPort =
            try {
                session.peerPort
            } catch (_: Exception) {
                -1
            }

        return SSLHandshakeSessionInfo(
            protocol =
                safeValue {
                    session.protocol
                },
            cipherSuite =
                safeValue {
                    session.cipherSuite
                },
            peerHost =
                peerHost,
            peerPort =
                peerPort,
            sessionIdLength =
                try {
                    session.id.size
                } catch (_: Exception) {
                    0
                },
            creationTime =
                try {
                    session.creationTime
                } catch (_: Exception) {
                    0L
                },
            lastAccessedTime =
                try {
                    session.lastAccessedTime
                } catch (_: Exception) {
                    0L
                }
        )
    }

    /**
     * Performs certificate hostname matching.
     *
     * Subject Alternative Name is preferred.
     * Common Name is retained as a compatibility fallback for
     * diagnostic purposes only.
     */
    private fun certificateMatchesHostname(
        certificate: X509Certificate,
        hostname: String
    ): Boolean {

        val normalized =
            normalizeHostname(
                hostname
            )

        /**
         * DNS SAN = type 2.
         */
        val dnsNames =
            try {

                certificate
                    .subjectAlternativeNames
                    ?.mapNotNull { entry ->

                        if (
                            entry.size >= 2 &&
                            entry[0] is Int &&
                            entry[0] == 2 &&
                            entry[1] is String
                        ) {
                            entry[1] as String
                        } else {
                            null
                        }
                    }
                    ?: emptyList()

            } catch (_: Exception) {

                emptyList()
            }

        if (
            dnsNames.any {
                hostnamePatternMatches(
                    pattern = it,
                    hostname = normalized
                )
            }
        ) {

            return true
        }

        /**
         * IP SAN = type 7.
         */
        val ipNames =
            try {

                certificate
                    .subjectAlternativeNames
                    ?.mapNotNull { entry ->

                        if (
                            entry.size >= 2 &&
                            entry[0] is Int &&
                            entry[0] == 7 &&
                            entry[1] is String
                        ) {
                            entry[1] as String
                        } else {
                            null
                        }
                    }
                    ?: emptyList()

            } catch (_: Exception) {

                emptyList()
            }

        if (
            ipNames.any {
                it == normalized
            }
        ) {

            return true
        }

        /**
         * CN fallback is used only for this supplementary diagnostic
         * check. Modern hostname verification should rely on SAN.
         */
        val commonName =
            extractCommonName(
                certificate
            )

        return commonName != null &&
                hostnamePatternMatches(
                    pattern =
                        commonName,
                    hostname =
                        normalized
                )
    }

    /**
     * Basic wildcard hostname matching.
     *
     * Only a left-most wildcard is accepted.
     *
     * Example:
     *
     * *.example.com
     *
     * matches:
     *
     * api.example.com
     *
     * but not:
     *
     * deep.api.example.com
     */
    private fun hostnamePatternMatches(
        pattern: String,
        hostname: String
    ): Boolean {

        val normalizedPattern =
            normalizeHostname(
                pattern
            )

        if (
            normalizedPattern ==
            hostname
        ) {

            return true
        }

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
            suffix.isBlank()
        ) {

            return false
        }

        val hostnameParts =
            hostname.split(".")

        val suffixParts =
            suffix.split(".")

        if (
            hostnameParts.size !=
            suffixParts.size + 1
        ) {

            return false
        }

        return hostname.endsWith(
            ".$suffix"
        )
    }

    /**
     * Extracts Common Name from the certificate subject.
     */
    private fun extractCommonName(
        certificate: X509Certificate
    ): String? {

        val subject =
            try {
                certificate
                    .subjectX500Principal
                    .name
            } catch (_: Exception) {
                return null
            }

        val match =
            Regex(
                "(^|,)\\s*CN=([^,]+)"
            )
                .find(
                    subject
                )

        return match
            ?.groupValues
            ?.getOrNull(2)
            ?.trim()
    }

    /**
     * Normalizes a hostname.
     */
    private fun normalizeHostname(
        hostname: String
    ): String {

        return try {

            IDN
                .toASCII(
                    hostname
                        .trim()
                        .removeSuffix(".")
                )
                .lowercase()

        } catch (_: Exception) {

            hostname
                .trim()
                .removeSuffix(".")
                .lowercase()
        }
    }

    /**
     * Safely extracts a certificate subject.
     */
    private fun safeSubject(
        certificate: X509Certificate
    ): String? {

        return try {

            certificate
                .subjectX500Principal
                .name

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Masks pin information in reports.
     */
    private fun maskPin(
        pin: String?
    ): String? {

        if (pin == null) {
            return null
        }

        if (
            pin.length <= 16
        ) {
            return "***"
        }

        return pin.take(12) +
                "..." +
                pin.takeLast(6)
    }

    /**
     * Safely executes a session accessor.
     */
    private fun safeValue(
        block: () -> String
    ): String? {

        return try {

            block()

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Creates a finding.
     */
    private fun finding(
        type: SSLHandshakeFindingType,
        severity: SSLHandshakeFindingSeverity,
        title: String,
        description: String,
        value: String? = null,
        expectedValue: String? = null,
        valid: Boolean
    ): SSLHandshakeFinding {

        return SSLHandshakeFinding(
            type =
                type,
            severity =
                severity,
            title =
                title,
            description =
                description,
            value =
                value,
            expectedValue =
                expectedValue,
            valid =
                valid
        )
    }

    /**
     * Determines overall validation status.
     */
    private fun determineStatus(
        findings:
            List<SSLHandshakeFinding>
    ): SSLHandshakeValidationStatus {

        if (
            findings.any {
                !it.valid &&
                        it.severity ==
                        SSLHandshakeFindingSeverity.CRITICAL
            }
        ) {

            return SSLHandshakeValidationStatus.INVALID
        }

        if (
            findings.any {
                !it.valid &&
                        it.severity ==
                        SSLHandshakeFindingSeverity.HIGH
            }
        ) {

            return SSLHandshakeValidationStatus.UNSAFE
        }

        if (
            findings.any {
                !it.valid &&
                        it.severity ==
                        SSLHandshakeFindingSeverity.MEDIUM
            }
        ) {

            return SSLHandshakeValidationStatus.VALID_WITH_WARNINGS
        }

        return SSLHandshakeValidationStatus.VALID
    }

    /**
     * Creates a failed validation result.
     */
    private fun invalidResult(
        message: String,
        errorType: String? = null
    ): SSLHandshakeValidationResult {

        return SSLHandshakeValidationResult(
            valid = false,
            status =
                SSLHandshakeValidationStatus.INVALID,
            findings =
                listOf(
                    finding(
                        type =
                            SSLHandshakeFindingType.HANDSHAKE_VALIDATION_FAILED,
                        severity =
                            SSLHandshakeFindingSeverity.CRITICAL,
                        title =
                            "TLS handshake validation failed",
                        description =
                            message,
                        value =
                            errorType,
                        valid = false
                    )
                ),
            sessionInfo = null,
            checksPerformed = 1,
            checksPassed = 0,
            checksFailed = 1,
            validatedAt =
                System.currentTimeMillis()
        )
    }
}

/**
 * SSL handshake validator configuration.
 */
data class SSLHandshakeValidatorConfiguration(

    /**
     * TLS protocols accepted by SentriX.
     *
     * TLS 1.2 is retained for compatibility with supported
     * Android/server environments.
     */
    val allowedProtocols:
        Set<String> =
        setOf(
            SecureSSLSocketFactory.TLS_1_3,
            SecureSSLSocketFactory.TLS_1_2
        ),

    /**
     * Explicit cipher-suite allowlist.
     *
     * Empty means use a conservative rejection policy for
     * obviously obsolete suites.
     */
    val allowedCipherSuites:
        Set<String> =
        emptySet(),

    /**
     * Whether certificate validity periods should be checked.
     */
    val validateCertificateDates: Boolean = true,

    /**
     * Whether certificate-chain ordering should be inspected.
     */
    val validateCertificateChainOrdering: Boolean = true,

    /**
     * Whether hostname validation should be performed when an
     * expected hostname is supplied.
     */
    val validateHostname: Boolean = true
)

/**
 * Overall handshake validation result.
 */
data class SSLHandshakeValidationResult(

    /**
     * Overall validation result.
     */
    val valid: Boolean,

    /**
     * Overall status.
     */
    val status:
        SSLHandshakeValidationStatus,

    /**
     * Security findings.
     */
    val findings:
        List<SSLHandshakeFinding>,

    /**
     * Negotiated TLS session information.
     */
    val sessionInfo:
        SSLHandshakeSessionInfo?,

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
     * Validation timestamp.
     */
    val validatedAt: Long
) {

    /**
     * Critical findings.
     */
    val criticalFindings:
        List<SSLHandshakeFinding>
        get() =
            findings.filter {
                it.severity ==
                        SSLHandshakeFindingSeverity.CRITICAL
            }

    /**
     * True when a pin mismatch was detected.
     */
    val hasPinMismatch: Boolean
        get() =
            findings.any {
                it.type ==
                        SSLHandshakeFindingType.PUBLIC_KEY_PIN_MISMATCH
            }
}

/**
 * TLS session metadata.
 */
data class SSLHandshakeSessionInfo(

    /**
     * Negotiated protocol.
     */
    val protocol: String?,

    /**
     * Negotiated cipher suite.
     */
    val cipherSuite: String?,

    /**
     * Peer hostname.
     */
    val peerHost: String?,

    /**
     * Peer port.
     */
    val peerPort: Int,

    /**
     * TLS session ID length.
     */
    val sessionIdLength: Int,

    /**
     * Session creation timestamp.
     */
    val creationTime: Long,

    /**
     * Last accessed timestamp.
     */
    val lastAccessedTime: Long
)

/**
 * Certificate-chain validation result.
 */
data class SSLHandshakeCertificateChainResult(

    /**
     * Whether chain checks passed.
     */
    val valid: Boolean,

    /**
     * Chain findings.
     */
    val findings:
        List<SSLHandshakeFinding>,

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
 * Hostname validation result.
 */
data class SSLHandshakeHostnameResult(

    /**
     * Whether hostname validation passed.
     */
    val valid: Boolean,

    /**
     * Hostname findings.
     */
    val findings:
        List<SSLHandshakeFinding>
)

/**
 * Certificate-expiry validation result.
 */
data class SSLHandshakeCertificateExpiryResult(

    /**
     * Certificate findings.
     */
    val findings:
        List<SSLHandshakeFinding>,

    /**
     * Number of checks performed.
     */
    val checksPerformed: Int,

    /**
     * Number passed.
     */
    val checksPassed: Int,

    /**
     * Number failed.
     */
    val checksFailed: Int
)

/**
 * Individual TLS handshake finding.
 */
data class SSLHandshakeFinding(

    /**
     * Finding type.
     */
    val type:
        SSLHandshakeFindingType,

    /**
     * Severity.
     */
    val severity:
        SSLHandshakeFindingSeverity,

    /**
     * Finding title.
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
     * Whether this individual check passed.
     */
    val valid: Boolean
)

/**
 * TLS handshake finding categories.
 */
enum class SSLHandshakeFindingType {

    /**
     * TLS session is available.
     */
    SESSION_VALID,

    /**
     * TLS session is invalid.
     */
    SESSION_INVALID,

    /**
     * Negotiated TLS protocol accepted.
     */
    PROTOCOL_VALID,

    /**
     * Negotiated TLS protocol rejected.
     */
    PROTOCOL_WEAK,

    /**
     * Cipher suite accepted.
     */
    CIPHER_SUITE_VALID,

    /**
     * Cipher suite rejected.
     */
    CIPHER_SUITE_WEAK,

    /**
     * Peer certificate chain available.
     */
    PEER_CERTIFICATES_AVAILABLE,

    /**
     * Peer certificate chain unavailable.
     */
    PEER_CERTIFICATES_UNAVAILABLE,

    /**
     * Certificate chain is empty.
     */
    CERTIFICATE_CHAIN_EMPTY,

    /**
     * Certificate validity period accepted.
     */
    CERTIFICATE_VALID,

    /**
     * Certificate expired/not-yet-valid.
     */
    CERTIFICATE_EXPIRED,

    /**
     * Certificate chain ordering accepted.
     */
    CERTIFICATE_CHAIN_ORDER_VALID,

    /**
     * Certificate chain ordering requires review.
     */
    CERTIFICATE_CHAIN_ORDER_INVALID,

    /**
     * Hostname matches.
     */
    HOSTNAME_MATCH,

    /**
     * Certificate hostname matches.
     */
    CERTIFICATE_HOSTNAME_MATCH,

    /**
     * Hostname mismatch.
     */
    HOSTNAME_MISMATCH,

    /**
     * Public-key pin matched.
     */
    PUBLIC_KEY_PIN_MATCH,

    /**
     * Public-key pin mismatch.
     */
    PUBLIC_KEY_PIN_MISMATCH,

    /**
     * Generic handshake validation failure.
     */
    HANDSHAKE_VALIDATION_FAILED
}

/**
 * TLS handshake finding severity.
 */
enum class SSLHandshakeFindingSeverity {

    /**
     * Informational.
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
     * Critical security failure.
     */
    CRITICAL
}

/**
 * Overall TLS handshake validation state.
 */
enum class SSLHandshakeValidationStatus {

    /**
     * All required checks passed.
     */
    VALID,

    /**
     * Validation passed with non-critical warnings.
     */
    VALID_WITH_WARNINGS,

    /**
     * High-severity security problem detected.
     */
    UNSAFE,

    /**
     * Critical validation failure detected.
     */
    INVALID
}
