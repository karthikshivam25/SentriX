package com.sentrix.security.integrity

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * SentriX Integrity Manager
 *
 * Central coordinator for application and runtime integrity checks.
 *
 * Responsibilities:
 *
 * - Coordinate application integrity checks.
 * - Calculate application/package fingerprints.
 * - Validate APK file integrity.
 * - Validate installed application signatures.
 * - Detect unexpected package changes.
 * - Maintain trusted integrity baselines.
 * - Compare current integrity state against baselines.
 * - Detect basic runtime tampering indicators.
 * - Provide unified integrity risk assessments.
 * - Support integrity telemetry.
 *
 * This class intentionally acts as an orchestration layer.
 *
 * Specialized integrity logic can be implemented by:
 *
 *      IntegrityChecker
 *      SignatureIntegrityChecker
 *      FileIntegrityChecker
 *      ApkIntegrityChecker
 *      RuntimeIntegrityChecker
 *      IntegrityBaselineManager
 *
 * This class DOES NOT:
 *
 * - Guarantee that a device is uncompromised.
 * - Replace Android Verified Boot.
 * - Replace Play Integrity.
 * - Replace SELinux/device security mechanisms.
 * - Provide root detection by itself.
 * - Disable or bypass Android security controls.
 *
 * Important:
 *
 * Application integrity is one signal in the SentriX security engine.
 * A successful integrity check does not prove that the entire device is safe.
 *
 * Architecture:
 *
 *      IntegrityManager
 *             │
 *      ┌──────┼───────────┐
 *      ▼      ▼           ▼
 *   Package  Signature   Runtime
 *   Integrity Integrity  Integrity
 *      │      │           │
 *      └──────┼───────────┘
 *             ▼
 *       Baseline Comparison
 *             │
 *             ▼
 *       Integrity Assessment
 */
class IntegrityManager(
    private val context: Context
) {

    /**
     * Application context prevents accidental Activity/Service references
     * from being retained.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * In-memory trusted integrity baselines.
     *
     * The map is thread-safe because integrity checks can be initiated
     * from different background components.
     */
    private val baselines =
        ConcurrentHashMap<String, IntegrityBaseline>()

    /**
     * Last calculated integrity assessment per package.
     */
    private val assessmentCache =
        ConcurrentHashMap<String, IntegrityAssessment>()

    // =========================================================================
    // Main Integrity Assessment
    // =========================================================================

    /**
     * Performs the default SentriX integrity assessment for this application.
     */
    fun checkIntegrity(): IntegrityAssessment {

        return checkIntegrity(
            packageName =
                applicationContext.packageName,
            configuration =
                IntegrityConfiguration.default()
        )
    }

    /**
     * Performs an integrity assessment for a package.
     *
     * The package must be installed and accessible to the current application.
     */
    fun checkIntegrity(
        packageName: String,
        configuration: IntegrityConfiguration
    ): IntegrityAssessment {

        val normalizedPackage =
            packageName.trim()

        if (
            normalizedPackage.isBlank()
        ) {

            return IntegrityAssessment.configurationError(
                "Package name must not be blank."
            )
        }

        val packageInfo =
            getPackageInfo(
                normalizedPackage
            )
                ?: return IntegrityAssessment.failure(
                    normalizedPackage,
                    "Unable to retrieve package information."
                )

        val packageFingerprint =
            calculatePackageFingerprint(
                packageInfo
            )

        val signatureFingerprint =
            calculateSignatureFingerprint(
                packageInfo
            )

        val apkFingerprint =
            calculateApkFingerprint(
                packageInfo
            )

        val baseline =
            baselines[
                normalizedPackage
            ]

        val violations =
            mutableListOf<IntegrityViolation>()

        // ---------------------------------------------------------------------
        // Package existence
        // ---------------------------------------------------------------------

        if (
            configuration.requireInstalledPackage &&
            packageInfo.applicationInfo == null
        ) {

            violations +=
                IntegrityViolation.PackageInformationUnavailable
        }

        // ---------------------------------------------------------------------
        // Signature integrity
        // ---------------------------------------------------------------------

        if (
            configuration.checkSignatureIntegrity
        ) {

            if (
                signatureFingerprint == null
            ) {

                violations +=
                    IntegrityViolation.SignatureUnavailable
            }
        }

        // ---------------------------------------------------------------------
        // APK integrity
        // ---------------------------------------------------------------------

        if (
            configuration.checkApkIntegrity
        ) {

            if (
                apkFingerprint == null
            ) {

                violations +=
                    IntegrityViolation.ApkFingerprintUnavailable
            }
        }

        // ---------------------------------------------------------------------
        // Baseline comparison
        // ---------------------------------------------------------------------

        if (
            configuration.compareAgainstBaseline
        ) {

            if (
                baseline == null
            ) {

                if (
                    configuration.requireBaseline
                ) {

                    violations +=
                        IntegrityViolation.BaselineMissing
                }

            } else {

                violations +=
                    compareAgainstBaseline(
                        packageFingerprint =
                            packageFingerprint,
                        signatureFingerprint =
                            signatureFingerprint,
                        apkFingerprint =
                            apkFingerprint,
                        baseline =
                            baseline
                    )
            }
        }

        // ---------------------------------------------------------------------
        // Runtime indicators
        // ---------------------------------------------------------------------

        val runtimeIndicators =
            if (
                configuration.checkRuntimeIntegrity
            ) {

                collectRuntimeIndicators()

            } else {

                emptyList()
            }

        violations +=
            runtimeIndicators
                .filter {
                    it.severity ==
                            IntegritySeverity
                                .HIGH ||
                            it.severity ==
                            IntegritySeverity
                                .CRITICAL
                }
                .map {
                    IntegrityViolation.RuntimeIntegrityWarning
                }

        // ---------------------------------------------------------------------
        // Risk
        // ---------------------------------------------------------------------

        val risk =
            calculateRisk(
                violations =
                    violations,
                runtimeIndicators =
                    runtimeIndicators
            )

        // ---------------------------------------------------------------------
        // Decision
        // ---------------------------------------------------------------------

        val decision =
            determineDecision(
                risk =
                    risk,
                configuration =
                    configuration
            )

        val assessment =
            IntegrityAssessment(

                packageName =
                    normalizedPackage,

                packageFingerprint =
                    packageFingerprint,

                signatureFingerprint =
                    signatureFingerprint,

                apkFingerprint =
                    apkFingerprint,

                baselinePresent =
                    baseline != null,

                runtimeIndicators =
                    runtimeIndicators,

                violations =
                    violations.distinct(),

                risk =
                    risk,

                decision =
                    decision,

                checkedAtMillis =
                    System.currentTimeMillis()
            )

        assessmentCache[
            normalizedPackage
        ] =
            assessment

        return assessment
    }

    // =========================================================================
    // Package Information
    // =========================================================================

    /**
     * Retrieves package information using the appropriate Android API.
     */
    private fun getPackageInfo(
        packageName: String
    ): android.content.pm.PackageInfo? {

        return try {

            val packageManager =
                applicationContext
                    .packageManager

            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.TIRAMISU
            ) {

                packageManager.getPackageInfo(
                    packageName,
                    PackageManager
                        .PackageInfoFlags
                        .of(
                            0L
                        )
                )

            } else {

                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(
                    packageName,
                    0
                )
            }

        } catch (
            _: PackageManager.NameNotFoundException
        ) {

            null

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Package Fingerprint
    // =========================================================================

    /**
     * Calculates a deterministic fingerprint for the installed package.
     *
     * The fingerprint combines:
     *
     * - package name
     * - version code
     * - version name
     * - APK path
     *
     * This is an application identity fingerprint, not a cryptographic
     * signature replacement.
     */
    fun calculatePackageFingerprint(
        packageInfo:
            android.content.pm.PackageInfo
    ): String {

        val versionCode =
            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.P
            ) {

                packageInfo.longVersionCode

            } else {

                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            }

        val material =
            buildString {

                append(
                    packageInfo.packageName
                )

                append("|")

                append(
                    versionCode
                )

                append("|")

                append(
                    packageInfo.versionName
                        ?: ""
                )

                append("|")

                append(
                    packageInfo.applicationInfo
                        ?.sourceDir
                        ?: ""
                )
            }

        return sha256(
            material.toByteArray(
                Charsets.UTF_8
            )
        )
    }

    // =========================================================================
    // Signature Fingerprint
    // =========================================================================

    /**
     * Calculates a SHA-256 fingerprint of the application's signing
     * certificate(s).
     *
     * Multiple signers are sorted before hashing so that the result remains
     * deterministic.
     */
    fun calculateSignatureFingerprint(
        packageInfo:
            android.content.pm.PackageInfo
    ): String? {

        val signatures =
            try {

                if (
                    Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.P
                ) {

                    packageInfo.signingInfo
                        ?.let { signingInfo ->

                            if (
                                signingInfo.hasMultipleSigners()
                            ) {

                                signingInfo.apkContentsSigners

                            } else {

                                signingInfo
                                    .signingCertificateHistory
                            }
                        }

                } else {

                    @Suppress("DEPRECATION")
                    packageInfo.signatures

                }

            } catch (
                _: Exception
            ) {

                null
            }

        if (
            signatures.isNullOrEmpty()
        ) {

            return null
        }

        val fingerprints =
            signatures
                .map {
                    sha256(
                        it.toByteArray()
                    )
                }
                .sorted()

        return sha256(
            fingerprints.joinToString(
                "|"
            ).toByteArray(
                Charsets.UTF_8
            )
        )
    }

    /**
     * Returns the individual signing certificate fingerprints.
     */
    fun getSignatureFingerprints(
        packageName: String
    ): List<String> {

        val packageInfo =
            getPackageInfo(
                packageName
            )
                ?: return emptyList()

        val signatures =
            try {

                if (
                    Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.P
                ) {

                    packageInfo.signingInfo
                        ?.let { signingInfo ->

                            if (
                                signingInfo.hasMultipleSigners()
                            ) {

                                signingInfo.apkContentsSigners

                            } else {

                                signingInfo
                                    .signingCertificateHistory
                            }
                        }

                } else {

                    @Suppress("DEPRECATION")
                    packageInfo.signatures
                }

            } catch (
                _: Exception
            ) {

                null
            }

        return signatures
            ?.map {
                sha256(
                    it.toByteArray()
                )
            }
            ?.distinct()
            ?: emptyList()
    }

    // =========================================================================
    // APK Fingerprint
    // =========================================================================

    /**
     * Calculates a SHA-256 fingerprint of the installed APK.
     *
     * For very large APKs, the file is processed in chunks rather than
     * loading the entire file into memory.
     */
    fun calculateApkFingerprint(
        packageInfo:
            android.content.pm.PackageInfo
    ): String? {

        val apkPath =
            packageInfo
                .applicationInfo
                ?.sourceDir
                ?: return null

        return calculateFileSha256(
            File(
                apkPath
            )
        )
    }

    /**
     * Calculates SHA-256 for an APK file.
     */
    fun calculateApkFingerprint(
        apkFile: File
    ): String? {

        return calculateFileSha256(
            apkFile
        )
    }

    /**
     * Calculates SHA-256 over a file using a streaming input.
     */
    private fun calculateFileSha256(
        file: File
    ): String? {

        if (
            !file.exists() ||
            !file.isFile ||
            !file.canRead()
        ) {

            return null
        }

        return try {

            val digest =
                MessageDigest.getInstance(
                    "SHA-256"
                )

            file.inputStream()
                .buffered()
                .use { input ->

                    val buffer =
                        ByteArray(
                            8192
                        )

                    while (
                        true
                    ) {

                        val count =
                            input.read(
                                buffer
                            )

                        if (
                            count <= 0
                        ) {

                            break
                        }

                        digest.update(
                            buffer,
                            0,
                            count
                        )
                    }
                }

            digest.digest()
                .joinToString(":") {
                    "%02X".format(
                        it.toInt() and 0xFF
                    )
                }

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Baseline Management
    // =========================================================================

    /**
     * Creates an integrity baseline from the current application state.
     */
    fun createBaseline(
        packageName: String =
            applicationContext.packageName
    ): IntegrityBaseline? {

        val packageInfo =
            getPackageInfo(
                packageName
            )
                ?: return null

        val packageFingerprint =
            calculatePackageFingerprint(
                packageInfo
            )

        val signatureFingerprint =
            calculateSignatureFingerprint(
                packageInfo
            )

        val apkFingerprint =
            calculateApkFingerprint(
                packageInfo
            )

        val baseline =
            IntegrityBaseline(

                packageName =
                    packageName,

                packageFingerprint =
                    packageFingerprint,

                signatureFingerprint =
                    signatureFingerprint,

                apkFingerprint =
                    apkFingerprint,

                createdAtMillis =
                    System.currentTimeMillis()
            )

        baselines[
            packageName
        ] =
            baseline

        return baseline
    }

    /**
     * Registers a supplied baseline.
     */
    fun registerBaseline(
        baseline: IntegrityBaseline
    ) {

        baselines[
            baseline.packageName
        ] =
            baseline
    }

    /**
     * Gets the baseline for a package.
     */
    fun getBaseline(
        packageName: String
    ): IntegrityBaseline? {

        return baselines[
            packageName
        ]
    }

    /**
     * Determines whether a baseline exists.
     */
    fun hasBaseline(
        packageName: String
    ): Boolean {

        return baselines.containsKey(
            packageName
        )
    }

    /**
     * Removes a package baseline.
     */
    fun removeBaseline(
        packageName: String
    ): Boolean {

        return baselines.remove(
            packageName
        ) != null
    }

    /**
     * Removes all baselines.
     */
    fun clearBaselines() {

        baselines.clear()
    }

    /**
     * Returns all registered baselines.
     */
    fun getAllBaselines():
            List<IntegrityBaseline> {

        return baselines.values.toList()
    }

    // =========================================================================
    // Baseline Comparison
    // =========================================================================

    /**
     * Compares the current integrity state with a trusted baseline.
     */
    private fun compareAgainstBaseline(
        packageFingerprint: String?,
        signatureFingerprint: String?,
        apkFingerprint: String?,
        baseline: IntegrityBaseline
    ): List<IntegrityViolation> {

        val violations =
            mutableListOf<
                    IntegrityViolation
                    >()

        if (
            packageFingerprint !=
            baseline.packageFingerprint
        ) {

            violations +=
                IntegrityViolation
                    .PackageFingerprintMismatch
        }

        if (
            signatureFingerprint != null &&
            baseline.signatureFingerprint != null &&
            signatureFingerprint !=
            baseline.signatureFingerprint
        ) {

            violations +=
                IntegrityViolation
                    .SignatureFingerprintMismatch
        }

        if (
            apkFingerprint != null &&
            baseline.apkFingerprint != null &&
            apkFingerprint !=
            baseline.apkFingerprint
        ) {

            violations +=
                IntegrityViolation
                    .ApkFingerprintMismatch
        }

        return violations
    }

    /**
     * Public API for comparing a package against its registered baseline.
     */
    fun compareWithBaseline(
        packageName: String =
            applicationContext.packageName
    ): IntegrityBaselineComparison {

        val baseline =
            baselines[
                packageName
            ]

        if (
            baseline == null
        ) {

            return IntegrityBaselineComparison
                .BaselineMissing
        }

        val packageInfo =
            getPackageInfo(
                packageName
            )
                ?: return IntegrityBaselineComparison
                    .UnableToInspect

        val currentPackage =
            calculatePackageFingerprint(
                packageInfo
            )

        val currentSignature =
            calculateSignatureFingerprint(
                packageInfo
            )

        val currentApk =
            calculateApkFingerprint(
                packageInfo
            )

        val violations =
            compareAgainstBaseline(
                packageFingerprint =
                    currentPackage,
                signatureFingerprint =
                    currentSignature,
                apkFingerprint =
                    currentApk,
                baseline =
                    baseline
            )

        return if (
            violations.isEmpty()
        ) {

            IntegrityBaselineComparison
                .Match

        } else {

            IntegrityBaselineComparison
                .Mismatch(
                    violations
                )
        }
    }

    // =========================================================================
    // Runtime Integrity
    // =========================================================================

    /**
     * Collects basic runtime integrity indicators.
     *
     * These are indicators rather than definitive proof of compromise.
     */
    fun collectRuntimeIndicators():
            List<RuntimeIntegrityIndicator> {

        val indicators =
            mutableListOf<
                    RuntimeIntegrityIndicator
                    >()

        // ---------------------------------------------------------------------
        // Debugger indicator
        // ---------------------------------------------------------------------

        if (
            android.os.Debug.isDebuggerConnected()
        ) {

            indicators +=
                RuntimeIntegrityIndicator(

                    type =
                        RuntimeIntegrityIndicatorType
                            .DEBUGGER_CONNECTED,

                    severity =
                        IntegritySeverity
                            .HIGH,

                    description =
                        "A debugger is currently connected " +
                                "to the application process."
                )
        }

        // ---------------------------------------------------------------------
        // Debuggable application indicator
        // ---------------------------------------------------------------------

        val applicationInfo =
            applicationContext
                .applicationInfo

        if (
            applicationInfo.flags and
            android.content.pm.ApplicationInfo
                .FLAG_DEBUGGABLE != 0
        ) {

            indicators +=
                RuntimeIntegrityIndicator(

                    type =
                        RuntimeIntegrityIndicatorType
                            .DEBUGGABLE_APPLICATION,

                    severity =
                        IntegritySeverity
                            .MEDIUM,

                    description =
                        "The installed application is marked as debuggable."
                )
        }

        // ---------------------------------------------------------------------
        // Emulator indicator
        // ---------------------------------------------------------------------

        if (
            isLikelyEmulator()
        ) {

            indicators +=
                RuntimeIntegrityIndicator(

                    type =
                        RuntimeIntegrityIndicatorType
                            .LIKELY_EMULATOR,

                    severity =
                        IntegritySeverity
                            .LOW,

                    description =
                        "The runtime environment has emulator-like characteristics."
                )
        }

        return indicators
    }

    /**
     * Performs a lightweight emulator heuristic check.
     *
     * This is intentionally heuristic and should not be treated as
     * definitive emulator detection.
     */
    private fun isLikelyEmulator(): Boolean {

        val fingerprint =
            Build.FINGERPRINT.lowercase()

        val model =
            Build.MODEL.lowercase()

        val manufacturer =
            Build.MANUFACTURER.lowercase()

        val brand =
            Build.BRAND.lowercase()

        val product =
            Build.PRODUCT.lowercase()

        return fingerprint.contains(
            "generic"
        ) ||
                fingerprint.contains(
                    "emulator"
                ) ||
                fingerprint.contains(
                    "test-keys"
                ) ||
                model.contains(
                    "emulator"
                ) ||
                model.contains(
                    "android sdk"
                ) ||
                manufacturer.contains(
                    "genymotion"
                ) ||
                brand.startsWith(
                    "generic"
                ) ||
                product.contains(
                    "sdk"
                )
    }

    // =========================================================================
    // Cached Assessment
    // =========================================================================

    /**
     * Returns the most recent assessment for a package.
     */
    fun getLastAssessment(
        packageName: String =
            applicationContext.packageName
    ): IntegrityAssessment? {

        return assessmentCache[
            packageName
        ]
    }

    /**
     * Removes a cached assessment.
     */
    fun clearAssessment(
        packageName: String
    ) {

        assessmentCache.remove(
            packageName
        )
    }

    /**
     * Clears all cached assessments.
     */
    fun clearAssessments() {

        assessmentCache.clear()
    }

    // =========================================================================
    // Security State
    // =========================================================================

    /**
     * Determines whether the current application appears intact.
     */
    fun isIntegrityHealthy(): Boolean {

        val assessment =
            checkIntegrity()

        return assessment.decision ==
                IntegrityDecision.ALLOW &&
                assessment.risk ==
                IntegrityRisk.LOW
    }

    /**
     * Determines whether integrity violations require blocking.
     */
    fun shouldBlock(): Boolean {

        val assessment =
            checkIntegrity()

        return assessment.decision ==
                IntegrityDecision.BLOCK
    }

    /**
     * Determines whether the application should produce a warning.
     */
    fun shouldWarn(): Boolean {

        val assessment =
            checkIntegrity()

        return assessment.decision ==
                IntegrityDecision.WARN
    }

    /**
     * Returns the current integrity risk.
     */
    fun getCurrentRisk():
            IntegrityRisk {

        return checkIntegrity().risk
    }

    // =========================================================================
    // Risk Calculation
    // =========================================================================

    /**
     * Calculates the overall integrity risk.
     */
    private fun calculateRisk(
        violations:
            List<IntegrityViolation>,

        runtimeIndicators:
            List<RuntimeIntegrityIndicator>
    ): IntegrityRisk {

        if (
            violations.any {
                it.severity ==
                        IntegritySeverity
                            .CRITICAL
            }
        ) {

            return IntegrityRisk
                .CRITICAL
        }

        if (
            violations.any {
                it.severity ==
                        IntegritySeverity
                            .HIGH
            }
        ) {

            return IntegrityRisk
                .HIGH
        }

        if (
            runtimeIndicators.any {
                it.severity ==
                        IntegritySeverity
                            .HIGH
            }
        ) {

            return IntegrityRisk
                .HIGH
        }

        if (
            violations.any {
                it.severity ==
                        IntegritySeverity
                            .MEDIUM
            }
        ) {

            return IntegrityRisk
                .MEDIUM
        }

        if (
            runtimeIndicators.any {
                it.severity ==
                        IntegritySeverity
                            .MEDIUM
            }
        ) {

            return IntegrityRisk
                .MEDIUM
        }

        if (
            violations.any {
                it.severity ==
                        IntegritySeverity
                            .LOW
            } ||
            runtimeIndicators.any {
                it.severity ==
                        IntegritySeverity
                            .LOW
            }
        ) {

            return IntegrityRisk
                .LOW
        }

        return IntegrityRisk
            .SAFE
    }

    // =========================================================================
    // Security Decision
    // =========================================================================

    /**
     * Converts risk into a final integrity decision.
     */
    private fun determineDecision(
        risk: IntegrityRisk,
        configuration: IntegrityConfiguration
    ): IntegrityDecision {

        return when (
            risk
        ) {

            IntegrityRisk.CRITICAL ->
                IntegrityDecision.BLOCK

            IntegrityRisk.HIGH ->

                if (
                    configuration.blockHighRisk
                ) {

                    IntegrityDecision.BLOCK

                } else {

                    IntegrityDecision.WARN
                }

            IntegrityRisk.MEDIUM ->
                IntegrityDecision.WARN

            IntegrityRisk.LOW ->
                IntegrityDecision.ALLOW

            IntegrityRisk.SAFE ->
                IntegrityDecision.ALLOW
        }
    }

    // =========================================================================
    // Hash Utility
    // =========================================================================

    /**
     * Calculates SHA-256 over arbitrary byte data.
     */
    private fun sha256(
        data: ByteArray
    ): String {

        val digest =
            MessageDigest.getInstance(
                "SHA-256"
            )

        return digest
            .digest(
                data
            )
            .joinToString(":") {
                "%02X".format(
                    it.toInt() and 0xFF
                )
            }
    }
}

/**
 * SentriX integrity configuration.
 */
data class IntegrityConfiguration(

    /**
     * Require the package to be installed and inspectable.
     */
    val requireInstalledPackage: Boolean = true,

    /**
     * Check signing certificate integrity.
     */
    val checkSignatureIntegrity: Boolean = true,

    /**
     * Check installed APK integrity.
     */
    val checkApkIntegrity: Boolean = true,

    /**
     * Compare current state with a trusted baseline.
     */
    val compareAgainstBaseline: Boolean = true,

    /**
     * Require a baseline to exist.
     */
    val requireBaseline: Boolean = false,

    /**
     * Collect runtime integrity indicators.
     */
    val checkRuntimeIntegrity: Boolean = true,

    /**
     * Block high-risk integrity states.
     */
    val blockHighRisk: Boolean = true
) {

    companion object {

        /**
         * Default SentriX configuration.
         */
        fun default():
                IntegrityConfiguration {

            return IntegrityConfiguration()
        }

        /**
         * Strict integrity configuration.
         */
        fun strict():
                IntegrityConfiguration {

            return IntegrityConfiguration(

                requireInstalledPackage =
                    true,

                checkSignatureIntegrity =
                    true,

                checkApkIntegrity =
                    true,

                compareAgainstBaseline =
                    true,

                requireBaseline =
                    true,

                checkRuntimeIntegrity =
                    true,

                blockHighRisk =
                    true
            )
        }

        /**
         * Monitoring-only configuration.
         */
        fun monitoring():
                IntegrityConfiguration {

            return IntegrityConfiguration(

                requireInstalledPackage =
                    true,

                checkSignatureIntegrity =
                    true,

                checkApkIntegrity =
                    true,

                compareAgainstBaseline =
                    true,

                requireBaseline =
                    false,

                checkRuntimeIntegrity =
                    true,

                blockHighRisk =
                    false
            )
        }
    }
}

/**
 * Trusted integrity baseline.
 */
data class IntegrityBaseline(

    val packageName: String,

    val packageFingerprint: String,

    val signatureFingerprint: String?,

    val apkFingerprint: String?,

    val createdAtMillis: Long
)

/**
 * Complete SentriX integrity assessment.
 */
data class IntegrityAssessment(

    val packageName: String,

    val packageFingerprint: String?,

    val signatureFingerprint: String?,

    val apkFingerprint: String?,

    val baselinePresent: Boolean,

    val runtimeIndicators:
        List<RuntimeIntegrityIndicator>,

    val violations:
        List<IntegrityViolation>,

    val risk:
        IntegrityRisk,

    val decision:
        IntegrityDecision,

    val checkedAtMillis: Long
) {

    companion object {

        /**
         * Creates a configuration-error assessment.
         */
        fun configurationError(
            reason: String
        ): IntegrityAssessment {

            return IntegrityAssessment(

                packageName =
                    "",

                packageFingerprint =
                    null,

                signatureFingerprint =
                    null,

                apkFingerprint =
                    null,

                baselinePresent =
                    false,

                runtimeIndicators =
                    emptyList(),

                violations =
                    listOf(
                        IntegrityViolation
                            .ConfigurationError(
                                reason
                            )
                    ),

                risk =
                    IntegrityRisk
                        .CRITICAL,

                decision =
                    IntegrityDecision
                        .BLOCK,

                checkedAtMillis =
                    System.currentTimeMillis()
            )
        }

        /**
         * Creates an inspection-failure assessment.
         */
        fun failure(
            packageName: String,
            reason: String
        ): IntegrityAssessment {

            return IntegrityAssessment(

                packageName =
                    packageName,

                packageFingerprint =
                    null,

                signatureFingerprint =
                    null,

                apkFingerprint =
                    null,

                baselinePresent =
                    false,

                runtimeIndicators =
                    emptyList(),

                violations =
                    listOf(
                        IntegrityViolation
                            .InspectionFailure(
                                reason
                            )
                    ),

                risk =
                    IntegrityRisk
                        .CRITICAL,

                decision =
                    IntegrityDecision
                        .BLOCK,

                checkedAtMillis =
                    System.currentTimeMillis()
            )
        }
    }
}

/**
 * Overall integrity risk.
 */
enum class IntegrityRisk(
    val priority: Int
) {

    SAFE(
        priority = 0
    ),

    LOW(
        priority = 1
    ),

    MEDIUM(
        priority = 2
    ),

    HIGH(
        priority = 3
    ),

    CRITICAL(
        priority = 4
    )
}

/**
 * Final integrity security decision.
 */
enum class IntegrityDecision {

    ALLOW,

    WARN,

    BLOCK
}

/**
 * Severity of an integrity issue.
 */
enum class IntegritySeverity(
    val priority: Int
) {

    LOW(
        priority = 1
    ),

    MEDIUM(
        priority = 2
    ),

    HIGH(
        priority = 3
    ),

    CRITICAL(
        priority = 4
    )
}

/**
 * Integrity violations detected by SentriX.
 */
sealed class IntegrityViolation(

    val severity:
        IntegritySeverity
) {

    data object PackageInformationUnavailable :
        IntegrityViolation(
            IntegritySeverity.HIGH
        )

    data object SignatureUnavailable :
        IntegrityViolation(
            IntegritySeverity.HIGH
        )

    data object ApkFingerprintUnavailable :
        IntegrityViolation(
            IntegritySeverity.HIGH
        )

    data object BaselineMissing :
        IntegrityViolation(
            IntegritySeverity.MEDIUM
        )

    data object PackageFingerprintMismatch :
        IntegrityViolation(
            IntegritySeverity.HIGH
        )

    data object SignatureFingerprintMismatch :
        IntegrityViolation(
            IntegritySeverity.CRITICAL
        )

    data object ApkFingerprintMismatch :
        IntegrityViolation(
            IntegritySeverity.CRITICAL
        )

    data object RuntimeIntegrityWarning :
        IntegrityViolation(
            IntegritySeverity.HIGH
        )

    data object ConfigurationError :
        IntegrityViolation(
            IntegritySeverity.CRITICAL
        ) {

        constructor(
            reason: String
        ) : this()
    }

    data class InspectionFailure(
        val reason: String
    ) : IntegrityViolation(
        IntegritySeverity.CRITICAL
    )
}

/**
 * Runtime integrity indicator.
 */
data class RuntimeIntegrityIndicator(

    val type:
        RuntimeIntegrityIndicatorType,

    val severity:
        IntegritySeverity,

    val description: String
)

/**
 * Runtime integrity indicators.
 *
 * These are heuristic signals, not definitive proof of compromise.
 */
enum class RuntimeIntegrityIndicatorType {

    DEBUGGER_CONNECTED,

    DEBUGGABLE_APPLICATION,

    LIKELY_EMULATOR
}

/**
 * Result of comparing current application state against a baseline.
 */
sealed class IntegrityBaselineComparison {

    data object Match :
        IntegrityBaselineComparison()

    data object BaselineMissing :
        IntegrityBaselineComparison()

    data object UnableToInspect :
        IntegrityBaselineComparison()

    data class Mismatch(
        val violations:
            List<IntegrityViolation>
    ) : IntegrityBaselineComparison()
}
