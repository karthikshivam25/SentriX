package com.sentrix.security.certificates

import android.util.Base64
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * SentriX Certificate Parser
 *
 * Responsible for parsing and normalizing X.509 certificates from
 * different representations.
 *
 * Supported input formats:
 *
 * - DER encoded certificate bytes
 * - PEM encoded certificate bytes
 * - PEM certificate String
 * - Base64 encoded DER certificate
 * - Certificate chains containing multiple PEM certificates
 *
 * Responsibilities:
 *
 * - Parse X.509 certificates.
 * - Normalize PEM input.
 * - Decode Base64 certificate data.
 * - Parse certificate chains.
 * - Extract safe certificate metadata.
 * - Validate parser input structure.
 *
 * This class DOES NOT:
 *
 * - Decide whether a certificate is trusted.
 * - Validate certificate expiration.
 * - Validate PKIX chains.
 * - Perform SSL pinning.
 * - Modify certificates.
 * - Store private keys.
 * - Extract private key material.
 *
 * Trust and security decisions belong to:
 *
 *      CertificateValidator
 *      CertificateTrustManager
 *      CertificateChainValidator
 *      SSL Pinning subsystem
 *
 * Architecture:
 *
 *      Raw Certificate
 *             │
 *             ▼
 *      CertificateParser
 *             │
 *       ┌─────┼─────┐
 *       ▼     ▼     ▼
 *      DER    PEM   Base64
 *       │     │     │
 *       └─────┼─────┘
 *             ▼
 *      X509Certificate
 *             │
 *             ▼
 *      CertificateValidator
 */
class CertificateParser {

    // =========================================================================
    // Certificate Factory
    // =========================================================================

    /**
     * X.509 certificate factory.
     *
     * CertificateFactory is thread-safe in the way it is used here because
     * a new factory is obtained for each parsing operation.
     */
    private fun createCertificateFactory():
            CertificateFactory {

        return CertificateFactory.getInstance(
            CertificateParserConstants.X509_TYPE
        )
    }

    // =========================================================================
    // DER Parsing
    // =========================================================================

    /**
     * Parses a DER-encoded X.509 certificate.
     *
     * @param certificateBytes DER encoded certificate bytes.
     *
     * @return parsed X509Certificate.
     *
     * @throws CertificateException if the certificate cannot be parsed.
     */
    @Throws(CertificateException::class)
    fun parseDer(
        certificateBytes: ByteArray
    ): X509Certificate {

        validateInput(
            certificateBytes
        )

        val factory =
            createCertificateFactory()

        return factory.generateCertificate(
            ByteArrayInputStream(
                certificateBytes
            )
        ) as? X509Certificate
            ?: throw CertificateException(
                "Certificate is not an X.509 certificate."
            )
    }

    // =========================================================================
    // PEM Parsing
    // =========================================================================

    /**
     * Parses an X.509 certificate from a PEM string.
     *
     * Expected format:
     *
     * -----BEGIN CERTIFICATE-----
     * Base64 data
     * -----END CERTIFICATE-----
     */
    @Throws(CertificateException::class)
    fun parsePem(
        pemCertificate: String
    ): X509Certificate {

        require(
            pemCertificate.isNotBlank()
        ) {
            "PEM certificate must not be blank."
        }

        val normalizedPem =
            normalizePem(
                pemCertificate
            )

        val encodedData =
            extractPemBody(
                normalizedPem
            )

        val decodedData =
            decodeBase64(
                encodedData
            )

        return parseDer(
            decodedData
        )
    }

    /**
     * Parses PEM data supplied as UTF-8 bytes.
     */
    @Throws(CertificateException::class)
    fun parsePem(
        pemBytes: ByteArray
    ): X509Certificate {

        validateInput(
            pemBytes
        )

        val pemString =
            pemBytes.toString(
                Charsets.UTF_8
            )

        return parsePem(
            pemString
        )
    }

    // =========================================================================
    // Base64 Parsing
    // =========================================================================

    /**
     * Parses a Base64 encoded DER certificate.
     *
     * The input must contain the Base64 representation of the DER
     * certificate without PEM headers.
     */
    @Throws(CertificateException::class)
    fun parseBase64(
        base64Certificate: String
    ): X509Certificate {

        require(
            base64Certificate.isNotBlank()
        ) {
            "Base64 certificate must not be blank."
        }

        val normalized =
            base64Certificate
                .trim()
                .replace(
                    "\\s".toRegex(),
                    ""
                )

        val decoded =
            decodeBase64(
                normalized
            )

        return parseDer(
            decoded
        )
    }

    // =========================================================================
    // Automatic Format Detection
    // =========================================================================

    /**
     * Automatically determines whether the supplied text is PEM or
     * Base64 encoded certificate data.
     */
    @Throws(CertificateException::class)
    fun parse(
        certificateData: String
    ): X509Certificate {

        require(
            certificateData.isNotBlank()
        ) {
            "Certificate data must not be blank."
        }

        val trimmed =
            certificateData.trim()

        return if (
            containsPemCertificate(
                trimmed
            )
        ) {

            parsePem(
                trimmed
            )

        } else {

            parseBase64(
                trimmed
            )
        }
    }

    /**
     * Automatically parses either DER or PEM byte data.
     */
    @Throws(CertificateException::class)
    fun parse(
        certificateData: ByteArray
    ): X509Certificate {

        validateInput(
            certificateData
        )

        return if (
            looksLikePem(
                certificateData
            )
        ) {

            parsePem(
                certificateData
            )

        } else {

            parseDer(
                certificateData
            )
        }
    }

    // =========================================================================
    // Certificate Chain Parsing
    // =========================================================================

    /**
     * Parses multiple certificates from a PEM chain.
     *
     * Example:
     *
     * -----BEGIN CERTIFICATE-----
     * Leaf
     * -----END CERTIFICATE-----
     *
     * -----BEGIN CERTIFICATE-----
     * Intermediate
     * -----END CERTIFICATE-----
     *
     * -----BEGIN CERTIFICATE-----
     * Root
     * -----END CERTIFICATE-----
     *
     * The original order is preserved.
     */
    @Throws(CertificateException::class)
    fun parsePemChain(
        pemChain: String
    ): List<X509Certificate> {

        require(
            pemChain.isNotBlank()
        ) {
            "PEM certificate chain must not be blank."
        }

        val certificates =
            mutableListOf<X509Certificate>()

        val beginMarker =
            Regex.escape(
                CertificateParserConstants
                    .PEM_BEGIN_CERTIFICATE
            )

        val endMarker =
            Regex.escape(
                CertificateParserConstants
                    .PEM_END_CERTIFICATE
            )

        val pattern =
            Regex(
                "$beginMarker(.*?)$endMarker",
                setOf(
                    RegexOption.DOT_MATCHES_ALL
                )
            )

        val matches =
            pattern.findAll(
                pemChain
            )

        for (
            match in matches
        ) {

            val completeCertificate =
                CertificateParserConstants
                    .PEM_BEGIN_CERTIFICATE +
                        match.groupValues[1] +
                        CertificateParserConstants
                            .PEM_END_CERTIFICATE

            certificates +=
                parsePem(
                    completeCertificate
                )
        }

        if (
            certificates.isEmpty()
        ) {

            throw CertificateException(
                "No PEM certificates were found."
            )
        }

        return certificates
    }

    /**
     * Parses a chain from a list of DER certificate byte arrays.
     */
    @Throws(CertificateException::class)
    fun parseDerChain(
        certificateChain: List<ByteArray>
    ): List<X509Certificate> {

        if (
            certificateChain.isEmpty()
        ) {

            throw CertificateException(
                "Certificate chain must not be empty."
            )
        }

        return certificateChain.map {
            parseDer(
                it
            )
        }
    }

    /**
     * Parses a collection of certificates automatically.
     */
    @Throws(CertificateException::class)
    fun parseChain(
        certificateData: Collection<String>
    ): List<X509Certificate> {

        if (
            certificateData.isEmpty()
        ) {

            throw CertificateException(
                "Certificate collection must not be empty."
            )
        }

        return certificateData.map {
            parse(
                it
            )
        }
    }

    // =========================================================================
    // PEM Utilities
    // =========================================================================

    /**
     * Determines whether the input contains a PEM certificate.
     */
    fun containsPemCertificate(
        certificateData: String
    ): Boolean {

        return certificateData.contains(
            CertificateParserConstants
                .PEM_BEGIN_CERTIFICATE
        ) &&
                certificateData.contains(
                    CertificateParserConstants
                        .PEM_END_CERTIFICATE
                )
    }

    /**
     * Determines whether byte data appears to be PEM text.
     */
    fun looksLikePem(
        certificateData: ByteArray
    ): Boolean {

        if (
            certificateData.isEmpty()
        ) {

            return false
        }

        val prefix =
            certificateData
                .take(
                    CertificateParserConstants
                        .PEM_DETECTION_LENGTH
                )
                .toByteArray()
                .toString(
                    Charsets.US_ASCII
                )

        return prefix.contains(
            "-----BEGIN"
        )
    }

    /**
     * Normalizes PEM line endings and surrounding whitespace.
     */
    fun normalizePem(
        pemCertificate: String
    ): String {

        return pemCertificate
            .replace(
                "\r\n",
                "\n"
            )
            .replace(
                "\r",
                "\n"
            )
            .trim()
    }

    /**
     * Extracts Base64 content from a PEM certificate.
     */
    fun extractPemBody(
        pemCertificate: String
    ): String {

        val normalized =
            normalizePem(
                pemCertificate
            )

        val beginMarker =
            CertificateParserConstants
                .PEM_BEGIN_CERTIFICATE

        val endMarker =
            CertificateParserConstants
                .PEM_END_CERTIFICATE

        val beginIndex =
            normalized.indexOf(
                beginMarker
            )

        val endIndex =
            normalized.indexOf(
                endMarker
            )

        if (
            beginIndex < 0 ||
            endIndex < 0 ||
            endIndex <=
            beginIndex +
                    beginMarker.length
        ) {

            throw IllegalArgumentException(
                "Invalid PEM certificate structure."
            )
        }

        return normalized
            .substring(
                beginIndex +
                        beginMarker.length,
                endIndex
            )
            .replace(
                "\\s".toRegex(),
                ""
            )
    }

    /**
     * Converts an X.509 certificate into PEM representation.
     */
    fun toPem(
        certificate: X509Certificate
    ): String {

        val encoded =
            certificate.encoded

        val base64 =
            Base64.encodeToString(
                encoded,
                Base64.NO_WRAP
            )

        return buildString {

            append(
                CertificateParserConstants
                    .PEM_BEGIN_CERTIFICATE
            )

            append('\n')

            base64
                .chunked(
                    CertificateParserConstants
                        .PEM_LINE_LENGTH
                )
                .forEach { line ->

                    append(line)
                    append('\n')
                }

            append(
                CertificateParserConstants
                    .PEM_END_CERTIFICATE
            )

            append('\n')
        }
    }

    // =========================================================================
    // Base64 Utilities
    // =========================================================================

    /**
     * Decodes Base64 certificate data.
     */
    @Throws(CertificateException::class)
    private fun decodeBase64(
        encodedData: String
    ): ByteArray {

        if (
            encodedData.isBlank()
        ) {

            throw CertificateException(
                "Certificate Base64 data is empty."
            )
        }

        return try {

            Base64.decode(
                encodedData,
                Base64.DEFAULT
            )

        } catch (
            exception: IllegalArgumentException
        ) {

            throw CertificateException(
                "Invalid Base64 certificate data.",
                exception
            )
        }
    }

    /**
     * Encodes DER certificate bytes into Base64.
     */
    fun encodeBase64(
        certificateBytes: ByteArray
    ): String {

        validateInput(
            certificateBytes
        )

        return Base64.encodeToString(
            certificateBytes,
            Base64.NO_WRAP
        )
    }

    /**
     * Encodes an X.509 certificate into Base64 DER format.
     */
    fun encodeBase64(
        certificate: X509Certificate
    ): String {

        return encodeBase64(
            certificate.encoded
        )
    }

    // =========================================================================
    // Certificate Metadata
    // =========================================================================

    /**
     * Extracts basic certificate metadata without making any
     * trust/security decisions.
     */
    fun extractMetadata(
        certificate: X509Certificate
    ): ParsedCertificateMetadata {

        return ParsedCertificateMetadata(

            subject =
                certificate
                    .subjectX500Principal
                    .name,

            issuer =
                certificate
                    .issuerX500Principal
                    .name,

            serialNumber =
                certificate
                    .serialNumber
                    .toString(
                        CertificateParserConstants
                            .SERIAL_NUMBER_RADIX
                    ),

            version =
                certificate.version,

            notBefore =
                certificate.notBefore,

            notAfter =
                certificate.notAfter,

            publicKeyAlgorithm =
                certificate.publicKey.algorithm,

            publicKeyFormat =
                certificate.publicKey.format,

            signatureAlgorithm =
                certificate.sigAlgName,

            signatureAlgorithmOid =
                certificate.sigAlgOID,

            basicConstraints =
                certificate.basicConstraints,

            isCertificateAuthority =
                certificate.basicConstraints >= 0,

            keyUsage =
                certificate.keyUsage,

            extendedKeyUsage =
                certificate.extendedKeyUsage
                    ?: emptyList(),

            dnsNames =
                extractDnsNames(
                    certificate
                ),

            ipAddresses =
                extractIpAddresses(
                    certificate
                )
        )
    }

    /**
     * Extracts DNS SAN entries.
     */
    fun extractDnsNames(
        certificate: X509Certificate
    ): List<String> {

        return extractSubjectAlternativeNames(
            certificate = certificate,
            type =
                CertificateParserConstants
                    .SAN_DNS_NAME
        )
    }

    /**
     * Extracts IP SAN entries.
     */
    fun extractIpAddresses(
        certificate: X509Certificate
    ): List<String> {

        return extractSubjectAlternativeNames(
            certificate = certificate,
            type =
                CertificateParserConstants
                    .SAN_IP_ADDRESS
        )
    }

    /**
     * Extracts SAN entries by GeneralName type.
     */
    private fun extractSubjectAlternativeNames(
        certificate: X509Certificate,
        type: Int
    ): List<String> {

        val subjectAlternativeNames =
            certificate.subjectAlternativeNames
                ?: return emptyList()

        return subjectAlternativeNames
            .filter {
                it.size >= 2 &&
                        it[0] == type
            }
            .mapNotNull {
                it[1]?.toString()
            }
    }

    // =========================================================================
    // Certificate Encoding
    // =========================================================================

    /**
     * Returns the DER encoded representation of a certificate.
     */
    fun encodeDer(
        certificate: X509Certificate
    ): ByteArray {

        return certificate.encoded
    }

    /**
     * Returns the size of the DER encoded certificate.
     */
    fun getEncodedSize(
        certificate: X509Certificate
    ): Int {

        return certificate.encoded.size
    }

    // =========================================================================
    // Format Detection
    // =========================================================================

    /**
     * Identifies the apparent certificate representation.
     */
    fun detectFormat(
        certificateData: String
    ): CertificateDataFormat {

        if (
            certificateData.isBlank()
        ) {

            return CertificateDataFormat.UNKNOWN
        }

        return if (
            containsPemCertificate(
                certificateData
            )
        ) {

            CertificateDataFormat.PEM

        } else {

            CertificateDataFormat.BASE64
        }
    }

    /**
     * Identifies the apparent byte representation.
     */
    fun detectFormat(
        certificateData: ByteArray
    ): CertificateDataFormat {

        if (
            certificateData.isEmpty()
        ) {

            return CertificateDataFormat.UNKNOWN
        }

        return if (
            looksLikePem(
                certificateData
            )
        ) {

            CertificateDataFormat.PEM

        } else {

            CertificateDataFormat.DER
        }
    }

    // =========================================================================
    // Input Validation
    // =========================================================================

    /**
     * Performs basic input validation before parsing.
     */
    private fun validateInput(
        certificateData: ByteArray
    ) {

        require(
            certificateData.isNotEmpty()
        ) {
            "Certificate data must not be empty."
        }

        require(
            certificateData.size <=
                    CertificateParserConstants
                        .MAX_CERTIFICATE_SIZE_BYTES
        ) {
            "Certificate data exceeds the maximum supported size."
        }
    }

    /**
     * Validates PEM text size.
     */
    fun validatePemSize(
        pemCertificate: String
    ): Boolean {

        return pemCertificate
            .toByteArray(
                Charsets.UTF_8
            )
            .size <=
                CertificateParserConstants
                    .MAX_CERTIFICATE_SIZE_BYTES
    }

    // =========================================================================
    // Certificate Collection Helpers
    // =========================================================================

    /**
     * Removes duplicate certificates from a chain while preserving
     * the original order.
     */
    fun removeDuplicates(
        certificates: List<X509Certificate>
    ): List<X509Certificate> {

        val seenFingerprints =
            mutableSetOf<String>()

        val result =
            mutableListOf<X509Certificate>()

        for (
            certificate in certificates
        ) {

            val fingerprint =
                sha256Fingerprint(
                    certificate
                )

            if (
                seenFingerprints.add(
                    fingerprint
                )
            ) {

                result += certificate
            }
        }

        return result
    }

    /**
     * Returns the SHA-256 fingerprint of a certificate.
     *
     * Kept here as a lightweight parser utility; trust decisions
     * remain outside this class.
     */
    fun sha256Fingerprint(
        certificate: X509Certificate
    ): String {

        val digest =
            java.security.MessageDigest
                .getInstance(
                    CertificateParserConstants
                        .SHA_256
                )

        return digest
            .digest(
                certificate.encoded
            )
            .joinToString(":") {
                "%02X".format(
                    it.toInt() and 0xFF
                )
            }
    }

    // =========================================================================
    // Chain Normalization
    // =========================================================================

    /**
     * Normalizes a certificate chain by:
     *
     * - Removing duplicates.
     * - Preserving certificate order.
     *
     * This method does not attempt to reorder certificates because
     * chain ordering is a security-sensitive validation concern.
     */
    fun normalizeChain(
        certificates: List<X509Certificate>
    ): List<X509Certificate> {

        return removeDuplicates(
            certificates
        )
    }

    companion object {

        /**
         * Default singleton-style factory.
         *
         * Useful where dependency injection is not yet configured.
         */
        fun create(): CertificateParser {
            return CertificateParser()
        }
    }
}

/**
 * Parsed certificate metadata.
 *
 * This data class contains extracted information only.
 * It does not represent a trust decision.
 */
data class ParsedCertificateMetadata(

    val subject: String,

    val issuer: String,

    val serialNumber: String,

    val version: Int,

    val notBefore: java.util.Date,

    val notAfter: java.util.Date,

    val publicKeyAlgorithm: String,

    val publicKeyFormat: String,

    val signatureAlgorithm: String,

    val signatureAlgorithmOid: String,

    val basicConstraints: Int,

    val isCertificateAuthority: Boolean,

    val keyUsage: BooleanArray?,

    val extendedKeyUsage: List<String>,

    val dnsNames: List<String>,

    val ipAddresses: List<String>
)

/**
 * Supported certificate input representations.
 */
enum class CertificateDataFormat {

    /**
     * DER-encoded X.509 certificate.
     */
    DER,

    /**
     * PEM encoded X.509 certificate.
     */
    PEM,

    /**
     * Base64 encoded DER certificate.
     */
    BASE64,

    /**
     * Input format could not be determined.
     */
    UNKNOWN
}

/**
 * Internal constants for CertificateParser.
 */
private object CertificateParserConstants {

    // =========================================================================
    // Certificate Format
    // =========================================================================

    const val X509_TYPE =
        "X.509"

    const val PEM_BEGIN_CERTIFICATE =
        "-----BEGIN CERTIFICATE-----"

    const val PEM_END_CERTIFICATE =
        "-----END CERTIFICATE-----"

    // =========================================================================
    // Encoding
    // =========================================================================

    const val PEM_LINE_LENGTH =
        64

    const val PEM_DETECTION_LENGTH =
        64

    const val SERIAL_NUMBER_RADIX =
        16

    const val SHA_256 =
        "SHA-256"

    // =========================================================================
    // Subject Alternative Name Types
    // =========================================================================

    /**
     * GeneralName.dNSName.
     */
    const val SAN_DNS_NAME =
        2

    /**
     * GeneralName.iPAddress.
     */
    const val SAN_IP_ADDRESS =
        7

    // =========================================================================
    // Safety Limits
    // =========================================================================

    /**
     * Maximum certificate input size accepted by the parser.
     *
     * This prevents unexpectedly large untrusted input from being
     * processed by the parser.
     */
    const val MAX_CERTIFICATE_SIZE_BYTES =
        1024 * 1024
}
