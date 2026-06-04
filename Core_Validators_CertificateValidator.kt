package com.sentrix.core.validators

import com.sentrix.core.exceptions.InvalidCertificateException
import com.sentrix.core.exceptions.RequiredFieldException
import java.security.cert.X509Certificate
import java.util.Date

/**
 * CertificateValidator
 *
 * Responsibilities:
 * - SSL/TLS certificate validation
 * - Expiry verification
 * - Issuer validation
 * - Certificate trust checks
 * - Security assessment
 */
object CertificateValidator {

    /**
     * Validate certificate.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidCertificateException::class
    )
    fun validate(
        certificate: X509Certificate?
    ): Boolean {

        if (certificate == null) {
            throw RequiredFieldException(
                "Certificate"
            )
        }

        try {

            certificate.checkValidity()

        } catch (exception: Exception) {

            throw InvalidCertificateException(
                "Certificate is expired or not yet valid."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        certificate: X509Certificate?
    ): Boolean {

        return try {

            validate(certificate)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check certificate expiration.
     */
    fun isExpired(
        certificate: X509Certificate
    ): Boolean {

        return try {

            certificate.checkValidity()

            false

        } catch (_: Exception) {
            true
        }
    }

    /**
     * Get certificate issuer.
     */
    fun getIssuer(
        certificate: X509Certificate
    ): String {

        return certificate
            .issuerX500Principal
            .name
    }

    /**
     * Get certificate subject.
     */
    fun getSubject(
        certificate: X509Certificate
    ): String {

        return certificate
            .subjectX500Principal
            .name
    }

    /**
     * Get expiry date.
     */
    fun getExpiryDate(
        certificate: X509Certificate
    ): Date {

        return certificate.notAfter
    }

    /**
     * Get remaining validity days.
     */
    fun getRemainingDays(
        certificate: X509Certificate
    ): Long {

        val remainingTime =
            certificate.notAfter.time -
                    System.currentTimeMillis()

        return remainingTime /
                (1000 * 60 * 60 * 24)
    }

    /**
     * Check self-signed certificate.
     */
    fun isSelfSigned(
        certificate: X509Certificate
    ): Boolean {

        return certificate
            .issuerX500Principal ==
                certificate.subjectX500Principal
    }

    /**
     * Get certificate risk level.
     */
    fun getRiskLevel(
        certificate: X509Certificate
    ): String {

        return when {

            isExpired(certificate) ->
                "Critical"

            getRemainingDays(
                certificate
            ) < 30 ->
                "High"

            isSelfSigned(
                certificate
            ) ->
                "Medium"

            else ->
                "Low"
        }
    }

    /**
     * Generate certificate summary.
     */
    fun getSummary(
        certificate: X509Certificate
    ): String {

        return buildString {

            appendLine(
                "Issuer: ${
                    getIssuer(
                        certificate
                    )
                }"
            )

            appendLine(
                "Subject: ${
                    getSubject(
                        certificate
                    )
                }"
            )

            appendLine(
                "Expires: ${
                    getExpiryDate(
                        certificate
                    )
                }"
            )

            appendLine(
                "Remaining Days: ${
                    getRemainingDays(
                        certificate
                    )
                }"
            )

            appendLine(
                "Self Signed: ${
                    isSelfSigned(
                        certificate
                    )
                }"
            )

            appendLine(
                "Risk Level: ${
                    getRiskLevel(
                        certificate
                    )
                }"
            )
        }
    }
}
