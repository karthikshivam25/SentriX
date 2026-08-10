package com.sentrix.security.sslpinning

import android.content.Context
import android.os.Build
import java.security.KeyStore
import java.security.Security
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * TrustManagerFactoryProvider
 *
 * Provides the Android/JVM platform TrustManagerFactory used by
 * SentriX SSL/TLS security components.
 *
 * Responsibilities:
 *
 * - Obtain the platform default TrustManagerFactory.
 * - Initialize it with the platform/system trust store.
 * - Expose the platform X509TrustManager.
 * - Validate that a suitable X509TrustManager exists.
 * - Provide trust-store metadata for diagnostics.
 * - Prevent accidental use of an empty/permissive trust store.
 *
 * IMPORTANT:
 *
 * This class deliberately does NOT implement a permissive
 * X509TrustManager.
 *
 * It does not:
 *
 * - accept all certificates.
 * - disable certificate-chain validation.
 * - disable hostname verification.
 * - bypass Android's trust store.
 * - create a "trust everything" SSL context.
 *
 * SSL pinning should work together with this normal trust manager.
 *
 * Architecture:
 *
 * Android System Trust Store
 *          ↓
 * TrustManagerFactory
 *          ↓
 * X509TrustManager
 *          ↓
 * TLS Certificate Validation
 *          ↓
 * CertificatePinner / SentriX Pinning
 */
class TrustManagerFactoryProvider(
    private val context: Context,
    private val configuration:
        TrustManagerFactoryProviderConfiguration =
        TrustManagerFactoryProviderConfiguration()
) {

    /**
     * Lazily created platform TrustManagerFactory.
     *
     * The factory is initialized only when required.
     */
    @Volatile
    private var trustManagerFactory:
        TrustManagerFactory? = null

    /**
     * Cached X509TrustManager.
     */
    @Volatile
    private var x509TrustManager:
        X509TrustManager? = null

    /**
     * Initializes the platform trust manager factory.
     */
    @Synchronized
    fun initialize():
            TrustManagerFactoryProviderResult {

        if (
            trustManagerFactory != null &&
            x509TrustManager != null
        ) {

            return TrustManagerFactoryProviderResult(
                success = true,
                initialized = true,
                message =
                    "Platform TrustManagerFactory is already initialized."
            )
        }

        return try {

            val factory =
                createPlatformTrustManagerFactory()

            val trustManager =
                extractX509TrustManager(
                    factory
                )

            trustManagerFactory =
                factory

            x509TrustManager =
                trustManager

            TrustManagerFactoryProviderResult(
                success = true,
                initialized = true,
                message =
                    "Platform TrustManagerFactory initialized successfully.",
                algorithm =
                    factory.algorithm,
                provider =
                    factory.provider.name
            )

        } catch (exception: Exception) {

            trustManagerFactory = null
            x509TrustManager = null

            TrustManagerFactoryProviderResult(
                success = false,
                initialized = false,
                message =
                    "Unable to initialize platform TrustManagerFactory.",
                errorType =
                    exception.javaClass.simpleName
            )
        }
    }

    /**
     * Returns the platform TrustManagerFactory.
     *
     * The factory is initialized before being returned.
     */
    @Synchronized
    fun getTrustManagerFactory():
            TrustManagerFactory {

        trustManagerFactory?.let {
            return it
        }

        val result =
            initialize()

        if (!result.success) {

            throw TrustManagerFactoryProviderException(
                result.message
            )
        }

        return trustManagerFactory
            ?: throw TrustManagerFactoryProviderException(
                "TrustManagerFactory initialization completed without a factory."
            )
    }

    /**
     * Returns the platform X509TrustManager.
     *
     * This is the trust manager responsible for normal certificate
     * chain validation.
     */
    @Synchronized
    fun getX509TrustManager():
            X509TrustManager {

        x509TrustManager?.let {
            return it
        }

        getTrustManagerFactory()

        return x509TrustManager
            ?: throw TrustManagerFactoryProviderException(
                "No X509TrustManager is available."
            )
    }

    /**
     * Returns all trust managers created by the platform factory.
     *
     * This is primarily useful for diagnostics and integration
     * with components that need to inspect the configured factory.
     */
    fun getTrustManagers():
            Array<TrustManager> {

        return getTrustManagerFactory()
            .trustManagers
            .clone()
    }

    /**
     * Returns the provider used by the TrustManagerFactory.
     */
    fun getProviderName(): String {

        return getTrustManagerFactory()
            .provider
            .name
    }

    /**
     * Returns the TrustManagerFactory algorithm.
     */
    fun getAlgorithm(): String {

        return getTrustManagerFactory()
            .algorithm
    }

    /**
     * Returns the Android API level.
     */
    fun getAndroidApiLevel(): Int {

        return Build.VERSION.SDK_INT
    }

    /**
     * Returns the package name of the application using SentriX.
     */
    fun getPackageName(): String {

        return context.packageName
    }

    /**
     * Performs a complete provider validation.
     *
     * The purpose is to verify that SentriX is using a real
     * platform X509TrustManager rather than a custom permissive
     * implementation.
     */
    fun validate():
            TrustManagerFactoryValidationResult {

        val findings =
            mutableListOf<TrustManagerValidationFinding>()

        var checksPerformed = 0
        var checksPassed = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * 1. Factory initialization
         * ---------------------------------------------------------
         */
        checksPerformed++

        val factoryResult =
            initialize()

        if (factoryResult.success) {

            checksPassed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.FACTORY_INITIALIZED,
                severity =
                    TrustManagerValidationSeverity.INFO,
                title =
                    "TrustManagerFactory initialized",
                description =
                    "The platform TrustManagerFactory was initialized successfully.",
                value =
                    factoryResult.algorithm,
                valid = true
            )

        } else {

            checksFailed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.FACTORY_INITIALIZATION_FAILED,
                severity =
                    TrustManagerValidationSeverity.CRITICAL,
                title =
                    "TrustManagerFactory initialization failed",
                description =
                    factoryResult.message,
                value =
                    factoryResult.errorType,
                valid = false
            )

            return TrustManagerFactoryValidationResult(
                valid = false,
                findings = findings,
                checksPerformed = checksPerformed,
                checksPassed = checksPassed,
                checksFailed = checksFailed,
                message =
                    "TrustManagerFactory validation could not continue."
            )
        }

        /**
         * ---------------------------------------------------------
         * 2. Trust manager availability
         * ---------------------------------------------------------
         */
        checksPerformed++

        val trustManagers =
            try {

                getTrustManagers()

            } catch (exception: Exception) {

                emptyArray()
            }

        if (
            trustManagers.isNotEmpty()
        ) {

            checksPassed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.TRUST_MANAGERS_AVAILABLE,
                severity =
                    TrustManagerValidationSeverity.INFO,
                title =
                    "Trust managers available",
                description =
                    "The platform factory returned one or more trust managers.",
                value =
                    trustManagers.size.toString(),
                valid = true
            )

        } else {

            checksFailed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.NO_TRUST_MANAGERS,
                severity =
                    TrustManagerValidationSeverity.CRITICAL,
                title =
                    "No trust managers available",
                description =
                    "The platform TrustManagerFactory returned no trust managers.",
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 3. X509TrustManager availability
         * ---------------------------------------------------------
         */
        checksPerformed++

        val trustManager =
            try {

                getX509TrustManager()

            } catch (_: Exception) {

                null
            }

        if (
            trustManager != null
        ) {

            checksPassed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.X509_TRUST_MANAGER_AVAILABLE,
                severity =
                    TrustManagerValidationSeverity.INFO,
                title =
                    "X509TrustManager available",
                description =
                    "A platform X509TrustManager is available for normal TLS certificate validation.",
                value =
                    trustManager.javaClass.name,
                valid = true
            )

        } else {

            checksFailed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.X509_TRUST_MANAGER_MISSING,
                severity =
                    TrustManagerValidationSeverity.CRITICAL,
                title =
                    "X509TrustManager unavailable",
                description =
                    "A suitable X509TrustManager could not be obtained.",
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 4. Factory provider
         * ---------------------------------------------------------
         */
        checksPerformed++

        try {

            val provider =
                getTrustManagerFactory()
                    .provider

            if (
                provider != null
            ) {

                checksPassed++

                findings += TrustManagerValidationFinding(
                    type =
                        TrustManagerValidationType.PROVIDER_AVAILABLE,
                    severity =
                        TrustManagerValidationSeverity.INFO,
                    title =
                        "Trust provider available",
                    description =
                        "The TrustManagerFactory has an active security provider.",
                    value =
                        provider.name,
                    valid = true
                )

            } else {

                checksFailed++

                findings += TrustManagerValidationFinding(
                    type =
                        TrustManagerValidationType.PROVIDER_MISSING,
                    severity =
                        TrustManagerValidationSeverity.HIGH,
                    title =
                        "Trust provider unavailable",
                    description =
                        "The TrustManagerFactory does not expose a security provider.",
                    valid = false
                )
            }

        } catch (exception: Exception) {

            checksFailed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.PROVIDER_CHECK_FAILED,
                severity =
                    TrustManagerValidationSeverity.HIGH,
                title =
                    "Trust provider check failed",
                description =
                    "The security provider could not be inspected.",
                value =
                    exception.javaClass.simpleName,
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 5. Android environment
         * ---------------------------------------------------------
         */
        checksPerformed++

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.N
        ) {

            checksPassed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.MODERN_ANDROID,
                severity =
                    TrustManagerValidationSeverity.INFO,
                title =
                    "Modern Android trust environment",
                description =
                    "The application is running on Android API 24 or newer.",
                value =
                    Build.VERSION.SDK_INT.toString(),
                valid = true
            )

        } else {

            checksFailed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.LEGACY_ANDROID,
                severity =
                    TrustManagerValidationSeverity.MEDIUM,
                title =
                    "Legacy Android environment",
                description =
                    "The application is running on an older Android API level.",
                value =
                    Build.VERSION.SDK_INT.toString(),
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * 6. Algorithm validation
         * ---------------------------------------------------------
         */
        checksPerformed++

        val algorithm =
            try {

                getAlgorithm()

            } catch (_: Exception) {

                null
            }

        if (
            !algorithm.isNullOrBlank()
        ) {

            checksPassed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.ALGORITHM_AVAILABLE,
                severity =
                    TrustManagerValidationSeverity.INFO,
                title =
                    "TrustManagerFactory algorithm available",
                description =
                    "The platform trust manager factory exposes a valid algorithm.",
                value =
                    algorithm,
                valid = true
            )

        } else {

            checksFailed++

            findings += TrustManagerValidationFinding(
                type =
                    TrustManagerValidationType.ALGORITHM_UNAVAILABLE,
                severity =
                    TrustManagerValidationSeverity.HIGH,
                title =
                    "TrustManagerFactory algorithm unavailable",
                description =
                    "No TrustManagerFactory algorithm could be identified.",
                valid = false
            )
        }

        /**
         * ---------------------------------------------------------
         * Final validation state
         * ---------------------------------------------------------
         */
        val valid =
            checksFailed == 0

        return TrustManagerFactoryValidationResult(
            valid = valid,
            findings = findings,
            checksPerformed = checksPerformed,
            checksPassed = checksPassed,
            checksFailed = checksFailed,
            message =
                if (valid) {
                    "Platform TrustManagerFactory validation succeeded."
                } else {
                    "Platform TrustManagerFactory validation completed with failures."
                }
        )
    }

    /**
     * Creates a platform TrustManagerFactory.
     *
     * When no explicit algorithm is configured, the JVM/Android
     * default algorithm is used.
     *
     * When a provider is explicitly configured, it must already
     * exist in the platform security provider registry.
     */
    private fun createPlatformTrustManagerFactory():
            TrustManagerFactory {

        val algorithm =
            configuration
                .algorithm
                ?: TrustManagerFactory
                    .getDefaultAlgorithm()

        val factory =
            if (
                configuration.providerName
                    .isNullOrBlank()
            ) {

                TrustManagerFactory
                    .getInstance(
                        algorithm
                    )

            } else {

                TrustManagerFactory
                    .getInstance(
                        algorithm,
                        configuration.providerName
                    )
            }

        /**
         * ---------------------------------------------------------
         * Use the platform/system trust store.
         * ---------------------------------------------------------
         *
         * Passing null causes the default trusted certificate
         * authorities to be used by the platform implementation.
         *
         * This is intentionally preferred over constructing an
         * empty KeyStore or accepting all certificates.
         */
        factory.init(
            null as KeyStore?
        )

        return factory
    }

    /**
     * Extracts an X509TrustManager from the factory.
     *
     * A platform TrustManagerFactory may technically expose more
     * than one TrustManager, so we explicitly search for an
     * X509TrustManager instead of blindly casting the first item.
     */
    private fun extractX509TrustManager(
        factory: TrustManagerFactory
    ): X509TrustManager {

        val managers =
            factory.trustManagers

        val x509Managers =
            managers
                .filterIsInstance<X509TrustManager>()

        if (
            x509Managers.isEmpty()
        ) {

            throw TrustManagerFactoryProviderException(
                "Platform TrustManagerFactory did not provide an X509TrustManager."
            )
        }

        if (
            x509Managers.size > 1
        ) {

            /**
             * Multiple X509TrustManagers are unusual.
             *
             * Prefer the first one returned by the platform rather
             * than inventing a trust-merging policy.
             */
            return x509Managers.first()
        }

        return x509Managers.first()
    }

    /**
     * Returns the names of all configured trust-manager classes.
     */
    fun getTrustManagerClassNames():
            List<String> {

        return getTrustManagers()
            .map {
                it.javaClass.name
            }
    }

    /**
     * Returns whether the provider has been initialized.
     */
    fun isInitialized(): Boolean {

        return trustManagerFactory != null &&
                x509TrustManager != null
    }

    /**
     * Clears cached references.
     *
     * The next access will recreate the platform factory.
     *
     * This does not modify the Android trust store.
     */
    @Synchronized
    fun reset() {

        trustManagerFactory = null
        x509TrustManager = null
    }

    /**
     * Returns security provider information.
     */
    fun getSecurityProviders():
            List<TrustProviderInfo> {

        return Security
            .getProviders()
            .map { provider ->

                TrustProviderInfo(
                    name =
                        provider.name,
                    version =
                        provider.versionStr,
                    info =
                        provider.info
                )
            }
    }

    /**
     * Returns the default TrustManagerFactory algorithm.
     */
    fun getDefaultAlgorithm(): String {

        return TrustManagerFactory
            .getDefaultAlgorithm()
    }
}

/**
 * Provider configuration.
 */
data class TrustManagerFactoryProviderConfiguration(

    /**
     * Optional TrustManagerFactory algorithm.
     *
     * If null, the platform default algorithm is used.
     */
    val algorithm: String? = null,

    /**
     * Optional provider name.
     *
     * If null, the platform chooses the provider.
     */
    val providerName: String? = null
)

/**
 * TrustManagerFactory initialization result.
 */
data class TrustManagerFactoryProviderResult(

    /**
     * Whether initialization succeeded.
     */
    val success: Boolean,

    /**
     * Current initialization state.
     */
    val initialized: Boolean,

    /**
     * Human-readable message.
     */
    val message: String,

    /**
     * TrustManagerFactory algorithm.
     */
    val algorithm: String? = null,

    /**
     * Security provider.
     */
    val provider: String? = null,

    /**
     * Error type when initialization fails.
     */
    val errorType: String? = null
)

/**
 * Complete TrustManagerFactory validation result.
 */
data class TrustManagerFactoryValidationResult(

    /**
     * Overall validation result.
     */
    val valid: Boolean,

    /**
     * Validation findings.
     */
    val findings:
        List<TrustManagerValidationFinding>,

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
     * Critical findings.
     */
    val criticalFindings:
        List<TrustManagerValidationFinding>
        get() =
            findings.filter {
                it.severity ==
                        TrustManagerValidationSeverity.CRITICAL
            }
}

/**
 * Individual trust-manager validation finding.
 */
data class TrustManagerValidationFinding(

    /**
     * Finding type.
     */
    val type:
        TrustManagerValidationType,

    /**
     * Severity.
     */
    val severity:
        TrustManagerValidationSeverity,

    /**
     * Finding title.
     */
    val title: String,

    /**
     * Description.
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
     * Whether this finding passed validation.
     */
    val valid: Boolean
)

/**
 * Trust-manager validation categories.
 */
enum class TrustManagerValidationType {

    /**
     * TrustManagerFactory successfully initialized.
     */
    FACTORY_INITIALIZED,

    /**
     * TrustManagerFactory initialization failed.
     */
    FACTORY_INITIALIZATION_FAILED,

    /**
     * Trust managers were returned.
     */
    TRUST_MANAGERS_AVAILABLE,

    /**
     * No trust managers were returned.
     */
    NO_TRUST_MANAGERS,

    /**
     * X509TrustManager available.
     */
    X509_TRUST_MANAGER_AVAILABLE,

    /**
     * X509TrustManager unavailable.
     */
    X509_TRUST_MANAGER_MISSING,

    /**
     * Security provider available.
     */
    PROVIDER_AVAILABLE,

    /**
     * Security provider unavailable.
     */
    PROVIDER_MISSING,

    /**
     * Provider inspection failed.
     */
    PROVIDER_CHECK_FAILED,

    /**
     * Modern Android API level.
     */
    MODERN_ANDROID,

    /**
     * Legacy Android API level.
     */
    LEGACY_ANDROID,

    /**
     * TrustManagerFactory algorithm available.
     */
    ALGORITHM_AVAILABLE,

    /**
     * TrustManagerFactory algorithm unavailable.
     */
    ALGORITHM_UNAVAILABLE
}

/**
 * Trust-manager validation severity.
 */
enum class TrustManagerValidationSeverity {

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
     * Critical security issue.
     */
    CRITICAL
}

/**
 * Security provider information.
 */
data class TrustProviderInfo(

    /**
     * Provider name.
     */
    val name: String,

    /**
     * Provider version.
     */
    val version: String,

    /**
     * Provider description.
     */
    val info: String
)

/**
 * Exception thrown when the platform trust-manager provider
 * cannot produce a usable X509TrustManager.
 */
class TrustManagerFactoryProviderException(
    message: String
) : IllegalStateException(
    message
)
