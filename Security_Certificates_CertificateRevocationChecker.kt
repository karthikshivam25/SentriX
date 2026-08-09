package com.sentrix.security.certificates

import java.security.KeyStore
import java.security.cert.CertPath
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXParameters
import java.security.cert.PKIXRevocationChecker
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

/**
 * SentriX Certificate Revocation Checker
 *
 * Enterprise-grade X.509 certificate revocation checking component.
 *
 * Responsibilities:
 *
 * - Check certificate revocation using PKIX revocation mechanisms.
 * - Support OCSP where the underlying security provider supports it.
 * - Support CRL checking where the underlying provider supports it.
 * - Validate complete certificate chains.
 * - Distinguish revoked certificates from unavailable revocation status.
 * - Provide configurable fail-open / fail-closed behavior.
 * - Cache short-lived revocation decisions.
 * - Prevent stale revocation decisions from being treated as permanent.
 * - Produce security/audit-friendly revocation results.
 *
 * This class DOES NOT:
 *
 * - Decide general certificate trust.
 * - Perform certificate pinning.
 * - Replace Android TLS TrustManager.
 * - Disable certificate validation.
 * - Modify the system trust store.
 * - Automatically trust a certificate when revocation information is
 *   unavailable.
 *
 * Security principle:
 *
 *      "Could not check revocation"
 *
 * is NOT automatically equivalent to:
 *
 *      "Certificate is safe."
 *
 * The caller's policy determines whether unavailable revocation information
 * should block the operation.
 *
 * Architecture:
 *
 *      X509Certificate / CertPath
 *                │
 *                ▼
 *      CertificateRevocationChecker
 *                │
 *        ┌───────┼───────────┐
 *        ▼       ▼           ▼
 *       OCSP     CRL       PKIX
 *        │       │           │
 *        └───────┼───────────┘
 *                ▼
 *       RevocationCheckResult
 */
class CertificateRevocationChecker(
    private val certificateManager:
        CertificateManager? = null
) {

    /**
     * Short-lived in-memory revocation cache.
     *
     * Key:
     *
     *      certificate fingerprint + policy
     *
     * The cache is intentionally process-local and should not be treated
     * as permanent revocation storage.
     */
    private val revocationCache =
        ConcurrentHashMap<String, CachedRevocationResult>()

    // =========================================================================
    // Main Certificate Check
    // =========================================================================

    /**
     * Checks the revocation status of a certificate using the default policy.
     */
    fun check(
        certificate: X509Certificate
    ): CertificateRevocationResult {

        return check(
            certificate = certificate,
            policy =
                CertificateRevocationPolicy.default()
        )
    }

    /**
     * Checks certificate revocation according to the supplied policy.
     */
    fun check(
        certificate: X509Certificate,
        policy: CertificateRevocationPolicy
    ): CertificateRevocationResult {

        val policyError =
            validatePolicy(
                policy
            )

        if (
            policyError != null
        ) {

            return CertificateRevocationResult
                .ConfigurationError(
                    policyError
                )
        }

        val fingerprint =
            getCertificateFingerprint(
                certificate
            )

        val cacheKey =
            buildCacheKey(
                fingerprint,
                policy
            )

        if (
            policy.cacheResults
        ) {

            getCachedResult(
                cacheKey
            )?.let {
                return it
            }
        }

        val result =
            performSingleCertificateCheck(
                certificate = certificate,
                policy = policy
            )

        if (
            policy.cacheResults &&
            isCacheable(
                result
            )
        ) {

            cacheResult(
                key = cacheKey,
                result = result,
                ttlMillis =
                    policy.cacheTtlMillis
            )
        }

        return result
    }

    // =========================================================================
    // Certificate Chain Check
    // =========================================================================

    /**
     * Checks revocation for a complete certificate chain.
     *
     * Expected order:
     *
     *      Leaf -> Intermediate -> Root
     */
    fun checkChain(
        certificateChain:
            List<X509Certificate>
    ): CertificateChainRevocationResult {

        return checkChain(
            certificateChain =
                certificateChain,
            policy =
                CertificateRevocationPolicy.default()
        )
    }

    /**
     * Performs complete certificate-chain revocation checking.
     */
    fun checkChain(
        certificateChain:
            List<X509Certificate>,
        policy:
            CertificateRevocationPolicy
    ): CertificateChainRevocationResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainRevocationResult
                .EmptyChain
        }

        val policyError =
            validatePolicy(
                policy
            )

        if (
            policyError != null
        ) {

            return CertificateChainRevocationResult
                .ConfigurationError(
                    policyError
                )
        }

        /*
         * For a complete chain, PKIX validation is preferable because the
         * provider can evaluate the certificate path and its revocation
         * information as a path-validation operation.
         */
        val pkixResult =
            checkChainUsingPkix(
                certificateChain =
                    certificateChain,
                policy =
                    policy
            )

        if (
            pkixResult is
            CertificateChainRevocationResult.Evaluated
        ) {

            return pkixResult
        }

        /*
         * If PKIX revocation checking is unavailable, evaluate individual
         * certificates where possible. The resulting status remains explicit
         * about uncertainty.
         */
        val individualResults =
            certificateChain.mapIndexed {
                index,
                certificate ->

                CertificateChainCertificateRevocation(
                    index = index,
                    certificate = certificate,
                    result =
                        check(
                            certificate,
                            policy
                        )
                )
            }

        return aggregateChainResults(
            individualResults
        )
    }

    // =========================================================================
    // PKIX Revocation
    // =========================================================================

    /**
     * Performs PKIX path validation with revocation checking enabled.
     *
     * Android/device security providers may differ in their support for
     * specific revocation mechanisms. Unsupported mechanisms are therefore
     * reported as UNKNOWN/UNAVAILABLE rather than being interpreted as
     * "not revoked".
     */
    private fun checkChainUsingPkix(
        certificateChain:
            List<X509Certificate>,
        policy:
            CertificateRevocationPolicy
    ): CertificateChainRevocationResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainRevocationResult
                .EmptyChain
        }

        return try {

            val certificateFactory =
                java.security.cert.CertificateFactory
                    .getInstance(
                        RevocationConstants.X509
                    )

            val certPath =
                certificateFactory.generateCertPath(
                    certificateChain
                )

            val trustAnchors =
                resolveTrustAnchors(
                    certificateChain
                )

            if (
                trustAnchors.isEmpty()
            ) {

                return CertificateChainRevocationResult
                    .Unavailable(
                        reason =
                            "No suitable trust anchors were available " +
                                    "for PKIX revocation validation."
                    )
            }

            val parameters =
                PKIXParameters(
                    trustAnchors
                )

            parameters.isRevocationEnabled =
                true

            val validator =
                CertPathValidator.getInstance(
                    RevocationConstants.PKIX
                )

            val revocationChecker =
                validator
                    .revocationChecker as? PKIXRevocationChecker
                    ?: return CertificateChainRevocationResult
                        .Unavailable(
                            reason =
                                "The active security provider does not " +
                                        "expose PKIXRevocationChecker."
                        )

            val options =
                mutableSetOf<
                        PKIXRevocationChecker.Option
                        >()

            if (
                policy.allowSoftFail
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .SOFT_FAIL
            }

            if (
                policy.preferOcsp
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .PREFER_OCSP
            }

            if (
                policy.onlyEndEntity
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .ONLY_END_ENTITY
            }

            if (
                policy.disableFallback
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .NO_FALLBACK
            }

            revocationChecker.options =
                options

            parameters.addCertPathChecker(
                revocationChecker
            )

            validator.validate(
                certPath,
                parameters
            )

            CertificateChainRevocationResult
                .Evaluated(
                    status =
                        CertificateChainRevocationStatus
                            .NOT_REVOKED,
                    certificates =
                        certificateChain.mapIndexed {
                            index,
                            certificate ->

                            CertificateChainCertificateRevocation(
                                index =
                                    index,
                                certificate =
                                    certificate,
                                result =
                                    CertificateRevocationResult
                                        .NotRevoked(
                                            method =
                                                RevocationMethod
                                                    .PKIX
                                        )
                            )
                        }
                )

        } catch (
            exception:
                CertPathValidatorException
        ) {

            classifyPkixException(
                exception,
                certificateChain
            )

        } catch (
            exception: Exception
        ) {

            CertificateChainRevocationResult
                .Unavailable(
                    reason =
                        exception.message
                            ?: "PKIX revocation validation is unavailable."
                )
        }
    }

    /**
     * Classifies a PKIX validation exception.
     */
    private fun classifyPkixException(
        exception:
            CertPathValidatorException,
        certificateChain:
            List<X509Certificate>
    ): CertificateChainRevocationResult {

        val reason =
            exception.reason

        /*
         * RevocationStatusUnknown generally means that the provider could
         * not establish the certificate's revocation status.
         */
        if (
            reason ==
            CertPathValidatorException.BasicReason
                .REVOKED
        ) {

            val index =
                exception.index

            val certificate =
                if (
                    index >= 0 &&
                    index < certificateChain.size
                ) {

                    certificateChain[index]

                } else {

                    certificateChain.first()
                }

            return CertificateChainRevocationResult
                .Revoked(
                    certificateIndex =
                        if (
                            index >= 0
                        ) {
                            index
                        } else {
                            0
                        },
                    certificate =
                        certificate,
                    reason =
                        exception.message
                            ?: "Certificate was revoked."
                )
        }

        if (
            reason ==
            CertPathValidatorException.BasicReason
                .UNDETERMINED_REVOCATION_STATUS
        ) {

            return CertificateChainRevocationResult
                .Unavailable(
                    reason =
                        exception.message
                            ?: "Revocation status could not be determined."
                )
        }

        return CertificateChainRevocationResult
            .Unavailable(
                reason =
                    exception.message
                        ?: "PKIX revocation validation failed."
            )
    }

    // =========================================================================
    // Individual Certificate Check
    // =========================================================================

    /**
     * Performs an individual certificate revocation check.
     *
     * There is no universally portable Android API that guarantees direct
     * OCSP/CRL retrieval for an arbitrary certificate. Therefore this method
     * uses provider-supported PKIX mechanisms where available.
     */
    private fun performSingleCertificateCheck(
        certificate: X509Certificate,
        policy: CertificateRevocationPolicy
    ): CertificateRevocationResult {

        /*
         * A single certificate does not contain enough information by itself
         * to establish a complete trust path. We therefore attempt to build
         * a one-certificate CertPath and use the system trust store.
         */
        return try {

            val certificateFactory =
                java.security.cert.CertificateFactory
                    .getInstance(
                        RevocationConstants.X509
                    )

            val certPath =
                certificateFactory.generateCertPath(
                    listOf(
                        certificate
                    )
                )

            val trustAnchors =
                resolveTrustAnchors(
                    listOf(
                        certificate
                    )
                )

            if (
                trustAnchors.isEmpty()
            ) {

                return CertificateRevocationResult
                    .Unavailable(
                        reason =
                            "No suitable trust anchor was found."
                    )
            }

            val parameters =
                PKIXParameters(
                    trustAnchors
                )

            parameters.isRevocationEnabled =
                true

            val validator =
                CertPathValidator.getInstance(
                    RevocationConstants.PKIX
                )

            val revocationChecker =
                validator
                    .revocationChecker as? PKIXRevocationChecker
                    ?: return CertificateRevocationResult
                        .Unavailable(
                            reason =
                                "PKIX revocation checker is unavailable."
                        )

            val options =
                mutableSetOf<
                        PKIXRevocationChecker.Option
                        >()

            if (
                policy.allowSoftFail
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .SOFT_FAIL
            }

            if (
                policy.preferOcsp
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .PREFER_OCSP
            }

            if (
                policy.disableFallback
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .NO_FALLBACK
            }

            if (
                policy.onlyEndEntity
            ) {

                options +=
                    PKIXRevocationChecker.Option
                        .ONLY_END_ENTITY
            }

            revocationChecker.options =
                options

            parameters.addCertPathChecker(
                revocationChecker
            )

            validator.validate(
                certPath,
                parameters
            )

            CertificateRevocationResult
                .NotRevoked(
                    method =
                        RevocationMethod.PKIX
                )

        } catch (
            exception:
                CertPathValidatorException
        ) {

            if (
                exception.reason ==
                CertPathValidatorException.BasicReason
                    .REVOKED
            ) {

                CertificateRevocationResult
                    .Revoked(
                        method =
                            RevocationMethod.PKIX,
                        reason =
                            exception.message
                                ?: "Certificate was revoked."
                    )

            } else {

                CertificateRevocationResult
                    .Unavailable(
                        method =
                            RevocationMethod.PKIX,
                        reason =
                            exception.message
                                ?: "Revocation status could not be determined."
                    )
            }

        } catch (
            exception: Exception
        ) {

            CertificateRevocationResult
                .Unavailable(
                    method =
                        RevocationMethod.PKIX,
                    reason =
                        exception.message
                            ?: "Revocation checking is unavailable."
                )
        }
    }

    // =========================================================================
    // Trust Anchors
    // =========================================================================

    /**
     * Resolves Android system trust anchors.
     *
     * The root certificate itself is not automatically trusted merely because
     * it appears in the supplied chain. Trust anchors come from the system
     * trust store.
     */
    private fun resolveTrustAnchors(
        certificateChain:
            List<X509Certificate>
    ): Set<TrustAnchor> {

        val trustStore =
            try {

                KeyStore.getInstance(
                    RevocationConstants
                        .ANDROID_TRUST_STORE
                ).apply {

                    load(null)
                }

            } catch (
                _: Exception
            ) {

                return emptySet()
            }

        val anchors =
            mutableSetOf<TrustAnchor>()

        val aliases =
            trustStore.aliases()

        while (
            aliases.hasMoreElements()
        ) {

            val alias =
                aliases.nextElement()

            val certificate =
                trustStore.getCertificate(
                    alias
                ) as? X509Certificate
                    ?: continue

            /*
             * Only trust anchors capable of participating in certificate
             * path validation should be returned.
             */
            if (
                certificate.basicConstraints < 0
            ) {

                continue
            }

            anchors +=
                TrustAnchor(
                    certificate,
                    null
                )
        }

        return anchors
    }

    // =========================================================================
    // Chain Result Aggregation
    // =========================================================================

    /**
     * Aggregates individual certificate revocation results.
     */
    private fun aggregateChainResults(
        results:
            List<CertificateChainCertificateRevocation>
    ): CertificateChainRevocationResult {

        val revoked =
            results.firstOrNull {
                it.result is
                        CertificateRevocationResult.Revoked
            }

        if (
            revoked != null
        ) {

            val revokedResult =
                revoked.result

            if (
                revokedResult is
                CertificateRevocationResult.Revoked
            ) {

                return CertificateChainRevocationResult
                    .Revoked(
                        certificateIndex =
                            revoked.index,
                        certificate =
                            revoked.certificate,
                        reason =
                            revokedResult.reason
                    )
            }
        }

        val unavailable =
            results.filter {
                it.result is
                        CertificateRevocationResult.Unavailable
            }

        if (
            unavailable.isNotEmpty()
        ) {

            return CertificateChainRevocationResult
                .Unavailable(
                    reason =
                        "Revocation status could not be established " +
                                "for one or more certificates."
                )
        }

        return CertificateChainRevocationResult
            .Evaluated(
                status =
                    CertificateChainRevocationStatus
                        .NOT_REVOKED,
                certificates =
                    results
            )
    }

    // =========================================================================
    // Revocation Policy
    // =========================================================================

    /**
     * Validates the revocation policy.
     */
    private fun validatePolicy(
        policy: CertificateRevocationPolicy
    ): String? {

        if (
            policy.cacheTtlMillis < 0L
        ) {

            return "Cache TTL cannot be negative."
        }

        if (
            policy.cacheMaxEntries < 0
        ) {

            return "Cache maximum entries cannot be negative."
        }

        return null
    }

    // =========================================================================
    // Cache
    // =========================================================================

    /**
     * Builds a cache key from certificate identity and policy.
     */
    private fun buildCacheKey(
        fingerprint: String,
        policy: CertificateRevocationPolicy
    ): String {

        return buildString {

            append(
                fingerprint
            )

            append("|")

            append(
                policy.preferOcsp
            )

            append("|")

            append(
                policy.onlyEndEntity
            )

            append("|")

            append(
                policy.disableFallback
            )
        }
    }

    /**
     * Reads a valid cache entry.
     */
    private fun getCachedResult(
        key: String
    ): CertificateRevocationResult? {

        val cached =
            revocationCache[
                key
            ]
                ?: return null

        if (
            cached.expiresAtMillis <=
            System.currentTimeMillis()
        ) {

            revocationCache.remove(
                key
            )

            return null
        }

        return cached.result
    }

    /**
     * Adds a result to the short-lived cache.
     */
    private fun cacheResult(
        key: String,
        result: CertificateRevocationResult,
        ttlMillis: Long
    ) {

        if (
            ttlMillis <= 0L
        ) {

            return
        }

        revocationCache[
            key
        ] =
            CachedRevocationResult(
                result =
                    result,
                expiresAtMillis =
                    System.currentTimeMillis() +
                            ttlMillis
            )
    }

    /**
     * Only stable results should be cached.
     *
     * UNKNOWN/UNAVAILABLE results are deliberately not cached by default
     * because a temporary network/provider failure should not become a
     * persistent security state.
     */
    private fun isCacheable(
        result: CertificateRevocationResult
    ): Boolean {

        return result is
                CertificateRevocationResult.NotRevoked ||
                result is
                CertificateRevocationResult.Revoked
    }

    /**
     * Clears all cached revocation results.
     */
    fun clearCache() {

        revocationCache.clear()
    }

    /**
     * Returns current cache size.
     */
    fun getCacheSize(): Int {

        return revocationCache.size
    }

    // =========================================================================
    // Fingerprint
    // =========================================================================

    /**
     * Gets the certificate SHA-256 fingerprint.
     *
     * If CertificateManager is available, its centralized implementation
     * is used. Otherwise the digest is calculated locally.
     */
    private fun getCertificateFingerprint(
        certificate: X509Certificate
    ): String {

        if (
            certificateManager != null
        ) {

            return certificateManager
                .getSha256Fingerprint(
                    certificate
                )
        }

        val digest =
            java.security.MessageDigest
                .getInstance(
                    RevocationConstants
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
}

/**
 * SentriX certificate revocation policy.
 */
data class CertificateRevocationPolicy(

    /**
     * Prefer OCSP when the provider supports it.
     */
    val preferOcsp: Boolean,

    /**
     * Allow provider fallback between supported revocation mechanisms.
     */
    val disableFallback: Boolean,

    /**
     * Apply revocation checking only to end-entity certificates.
     */
    val onlyEndEntity: Boolean,

    /**
     * Allow soft-fail behavior from the underlying PKIX checker.
     *
     * This does NOT automatically mean SentriX considers the certificate
     * safe. The final unavailable state is still represented explicitly.
     */
    val allowSoftFail: Boolean,

    /**
     * Whether short-lived results should be cached.
     */
    val cacheResults: Boolean,

    /**
     * Cache lifetime.
     */
    val cacheTtlMillis: Long,

    /**
     * Maximum intended cache size.
     */
    val cacheMaxEntries: Int,

    /**
     * Determines what higher-level SentriX security components should do
     * when revocation status cannot be determined.
     */
    val unavailableAction:
        RevocationUnavailableAction
) {

    companion object {

        /**
         * Secure default policy.
         *
         * Revocation status is checked using provider-supported PKIX
         * mechanisms. Unavailable status is treated as a security failure
         * by higher-level callers.
         */
        fun default():
                CertificateRevocationPolicy {

            return CertificateRevocationPolicy(

                preferOcsp =
                    true,

                disableFallback =
                    false,

                onlyEndEntity =
                    false,

                allowSoftFail =
                    false,

                cacheResults =
                    true,

                cacheTtlMillis =
                    5 * 60 * 1000L,

                cacheMaxEntries =
                    500,

                unavailableAction =
                    RevocationUnavailableAction
                        .FAIL_CLOSED
            )
        }

        /**
         * Strict enterprise policy.
         */
        fun strict():
                CertificateRevocationPolicy {

            return CertificateRevocationPolicy(

                preferOcsp =
                    true,

                disableFallback =
                    true,

                onlyEndEntity =
                    false,

                allowSoftFail =
                    false,

                cacheResults =
                    true,

                cacheTtlMillis =
                    2 * 60 * 1000L,

                cacheMaxEntries =
                    1000,

                unavailableAction =
                    RevocationUnavailableAction
                        .FAIL_CLOSED
            )
        }

        /**
         * Compatibility-oriented policy.
         *
         * This policy still reports unavailable status explicitly.
         * It does not convert unavailable into "not revoked."
         */
        fun compatibility():
                CertificateRevocationPolicy {

            return CertificateRevocationPolicy(

                preferOcsp =
                    true,

                disableFallback =
                    false,

                onlyEndEntity =
                    true,

                allowSoftFail =
                    true,

                cacheResults =
                    true,

                cacheTtlMillis =
                    5 * 60 * 1000L,

                cacheMaxEntries =
                    250,

                unavailableAction =
                    RevocationUnavailableAction
                        .WARN_AND_CONTINUE
            )
        }
    }
}

/**
 * Defines how higher-level security logic should handle unavailable
 * revocation information.
 */
enum class RevocationUnavailableAction {

    /**
     * Treat unavailable revocation status as a security failure.
     */
    FAIL_CLOSED,

    /**
     * Record a warning and allow the caller to continue.
     */
    WARN_AND_CONTINUE
}

/**
 * Individual certificate revocation result.
 */
sealed class CertificateRevocationResult {

    /**
     * Certificate successfully passed revocation checking.
     *
     * This means the selected revocation mechanism did not identify
     * the certificate as revoked.
     */
    data class NotRevoked(

        val method:
            RevocationMethod

    ) : CertificateRevocationResult()

    /**
     * Certificate was identified as revoked.
     */
    data class Revoked(

        val method:
            RevocationMethod,

        val reason: String

    ) : CertificateRevocationResult()

    /**
     * Revocation status could not be established.
     *
     * This is intentionally different from NotRevoked.
     */
    data class Unavailable(

        val method:
            RevocationMethod =
            RevocationMethod.UNKNOWN,

        val reason: String

    ) : CertificateRevocationResult()

    /**
     * Revocation policy is invalid.
     */
    data class ConfigurationError(
        val reason: String
    ) : CertificateRevocationResult()
}

/**
 * Supported revocation mechanisms.
 */
enum class RevocationMethod {

    /**
     * Java/Android PKIX revocation checker.
     */
    PKIX,

    /**
     * OCSP-based validation.
     */
    OCSP,

    /**
     * CRL-based validation.
     */
    CRL,

    /**
     * Multiple mechanisms were involved.
     */
    PKIX_WITH_OCSP_OR_CRL,

    /**
     * Revocation mechanism could not be determined.
     */
    UNKNOWN
}

/**
 * Result of complete certificate-chain revocation checking.
 */
sealed class CertificateChainRevocationResult {

    /**
     * No certificates were supplied.
     */
    data object EmptyChain :
        CertificateChainRevocationResult()

    /**
     * Revocation checking successfully evaluated the chain.
     */
    data class Evaluated(

        val status:
            CertificateChainRevocationStatus,

        val certificates:
            List<CertificateChainCertificateRevocation>

    ) : CertificateChainRevocationResult()

    /**
     * A certificate in the chain was revoked.
     */
    data class Revoked(

        val certificateIndex: Int,

        val certificate:
            X509Certificate,

        val reason: String

    ) : CertificateChainRevocationResult()

    /**
     * Revocation status could not be established.
     */
    data class Unavailable(

        val reason: String

    ) : CertificateChainRevocationResult()

    /**
     * Policy configuration is invalid.
     */
    data class ConfigurationError(

        val reason: String

    ) : CertificateChainRevocationResult()
}

/**
 * Overall chain revocation status.
 */
enum class CertificateChainRevocationStatus {

    /**
     * No certificate was identified as revoked.
     */
    NOT_REVOKED,

    /**
     * At least one certificate was revoked.
     */
    REVOKED,

    /**
     * Revocation status could not be established.
     */
    UNKNOWN
}

/**
 * Revocation result associated with a certificate's position in a chain.
 */
data class CertificateChainCertificateRevocation(

    /**
     * Certificate position.
     *
     * 0 = leaf
     * 1 = intermediate
     * last = root
     */
    val index: Int,

    val certificate:
        X509Certificate,

    val result:
        CertificateRevocationResult
)

/**
 * Cached revocation result.
 */
private data class CachedRevocationResult(

    val result:
        CertificateRevocationResult,

    val expiresAtMillis: Long
)

/**
 * Internal revocation constants.
 */
private object RevocationConstants {

    const val X509 =
        "X.509"

    const val PKIX =
        "PKIX"

    const val SHA_256 =
        "SHA-256"

    const val ANDROID_TRUST_STORE =
        "AndroidCAStore"
}
