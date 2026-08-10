package com.sentrix.security.antitamper

import android.content.Context
import android.os.Build
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * CodeTamperDetector
 *
 * Detects potential modification of the application's compiled
 * executable code.
 *
 * Primary targets:
 *
 * - Base APK
 * - Split APKs
 * - DEX files contained inside APKs
 * - Runtime application code locations
 *
 * Responsibilities:
 *
 * - Discover application APK locations.
 * - Calculate cryptographic hashes of APK/DEX content.
 * - Compare hashes against trusted configuration.
 * - Produce structured code-integrity evidence.
 *
 * This class does NOT:
 *
 * - modify application code
 * - repair modified files
 * - delete suspicious files
 * - execute dynamically supplied code
 * - terminate the application
 * - perform the final tampering verdict
 *
 * Architecture:
 *
 * AntiTamperManager
 *        ↓
 * CodeTamperDetector
 *        ↓
 * CodeIntegrityEvidence
 *        ↓
 * AntiTamperEvidenceCollector
 *        ↓
 * AntiTamperValidator
 *
 * IMPORTANT:
 *
 * A code hash is meaningful only when compared against a trusted
 * value. A locally stored expected hash that can itself be modified
 * by an attacker is not a reliable trust anchor.
 *
 * For production SentriX, trusted values should preferably be
 * provisioned through protected build configuration and/or verified
 * server-side/attestation mechanisms.
 */
class CodeTamperDetector(
    private val context: Context,
    private val configuration: CodeTamperConfiguration =
        CodeTamperConfiguration()
) {

    /**
     * Maximum file size that can be processed by this detector.
     *
     * This protects the detection operation from unexpectedly
     * processing extremely large files.
     */
    private val maxHashableFileSizeBytes =
        200L * 1024L * 1024L

    /**
     * Performs a complete compiled-code integrity assessment.
     */
    fun detect(): CodeTamperResult {

        val evidence =
            mutableListOf<CodeTamperEvidence>()

        var filesChecked = 0
        var filesHashed = 0
        var checksFailed = 0

        /**
         * ---------------------------------------------------------
         * Discover application APK locations
         * ---------------------------------------------------------
         */
        val apkPaths =
            try {

                getApplicationApkPaths()

            } catch (_: Exception) {

                checksFailed++

                emptyList()
            }

        if (apkPaths.isEmpty()) {

            evidence += CodeTamperEvidence(
                type = CodeTamperEvidenceType.APK_PATH_UNAVAILABLE,
                source = "ApplicationInfo",
                path = null,
                description =
                    "No application APK paths could be identified.",
                severity = CodeTamperSeverity.HIGH,
                confidence = 0.70
            )
        }

        /**
         * ---------------------------------------------------------
         * Hash APK files
         * ---------------------------------------------------------
         */
        apkPaths.forEach { path ->

            val file =
                File(path)

            filesChecked++

            if (!file.exists()) {

                evidence += CodeTamperEvidence(
                    type = CodeTamperEvidenceType.FILE_MISSING,
                    source = "APK",
                    path = path,
                    description =
                        "An expected application APK file could not be found.",
                    severity = CodeTamperSeverity.HIGH,
                    confidence = 0.90
                )

                return@forEach
            }

            if (!file.isFile) {

                evidence += CodeTamperEvidence(
                    type = CodeTamperEvidenceType.INVALID_FILE,
                    source = "APK",
                    path = path,
                    description =
                        "The discovered APK path is not a regular file.",
                    severity = CodeTamperSeverity.MEDIUM,
                    confidence = 0.80
                )

                return@forEach
            }

            if (
                file.length() >
                maxHashableFileSizeBytes
            ) {

                evidence += CodeTamperEvidence(
                    type = CodeTamperEvidenceType.FILE_TOO_LARGE,
                    source = "APK",
                    path = path,
                    description =
                        "APK exceeds the configured hashing size limit.",
                    severity = CodeTamperSeverity.MEDIUM,
                    confidence = 1.0
                )

                return@forEach
            }

            try {

                val hash =
                    calculateSha256(file)

                filesHashed++

                evidence += CodeTamperEvidence(
                    type = CodeTamperEvidenceType.APK_HASH,
                    source = "APK",
                    path = path,
                    description =
                        "SHA-256 hash of the installed APK.",
                    value = hash,
                    severity = CodeTamperSeverity.INFO,
                    confidence = 1.0
                )

                compareTrustedApkHash(
                    path = path,
                    actualHash = hash,
                    evidence = evidence
                )

            } catch (_: Exception) {

                checksFailed++

                evidence += CodeTamperEvidence(
                    type = CodeTamperEvidenceType.HASH_FAILED,
                    source = "APK",
                    path = path,
                    description =
                        "The APK could not be cryptographically hashed.",
                    severity = CodeTamperSeverity.MEDIUM,
                    confidence = 0.60
                )
            }
        }

        /**
         * ---------------------------------------------------------
         * Inspect DEX entries inside APKs
         * ---------------------------------------------------------
         *
         * APK files are ZIP containers. We inspect DEX entries
         * without extracting or executing them.
         */
        apkPaths.forEach { path ->

            val apkFile =
                File(path)

            if (!apkFile.exists() ||
                !apkFile.isFile
            ) {
                return@forEach
            }

            try {

                inspectDexEntries(
                    apkFile = apkFile,
                    evidence = evidence
                )

            } catch (_: Exception) {

                checksFailed++

                evidence += CodeTamperEvidence(
                    type = CodeTamperEvidenceType.DEX_INSPECTION_FAILED,
                    source = "DEX",
                    path = path,
                    description =
                        "DEX entries could not be inspected.",
                    severity = CodeTamperSeverity.MEDIUM,
                    confidence = 0.60
                )
            }
        }

        /**
         * ---------------------------------------------------------
         * Determine overall detector state
         * ---------------------------------------------------------
         */
        val tamperIndicators =
            evidence.count {
                it.severity == CodeTamperSeverity.HIGH ||
                        it.severity == CodeTamperSeverity.CRITICAL
            }

        val status =
            when {

                evidence.any {
                    it.type ==
                            CodeTamperEvidenceType.HASH_MISMATCH
                } ->
                    CodeTamperStatus.CODE_TAMPER_DETECTED

                tamperIndicators > 0 ->
                    CodeTamperStatus.SUSPICIOUS

                checksFailed > 0 ->
                    CodeTamperStatus.CHECK_INCOMPLETE

                else ->
                    CodeTamperStatus.NO_CODE_TAMPER_DETECTED
            }

        return CodeTamperResult(
            status = status,
            evidence = evidence,
            filesChecked = filesChecked,
            filesHashed = filesHashed,
            checksFailed = checksFailed,
            detectionCompleted =
                checksFailed == 0 &&
                        apkPaths.isNotEmpty(),
            detectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Returns all APK paths associated with the current
     * application.
     *
     * Android may use:
     *
     * - Base APK
     * - Split APKs
     *
     * Therefore sourceDir alone is not sufficient for all
     * installation configurations.
     */
    private fun getApplicationApkPaths(): List<String> {

        val paths =
            mutableListOf<String>()

        val applicationInfo =
            context.applicationInfo

        applicationInfo.sourceDir
            ?.takeIf { it.isNotBlank() }
            ?.let {
                paths += it
            }

        applicationInfo.splitSourceDirs
            ?.filter {
                it.isNotBlank()
            }
            ?.let {
                paths += it
            }

        return paths.distinct()
    }

    /**
     * Compares an installed APK hash against the configured
     * trusted hash.
     */
    private fun compareTrustedApkHash(
        path: String,
        actualHash: String,
        evidence: MutableList<CodeTamperEvidence>
    ) {

        val normalizedPath =
            normalizePath(path)

        val expectedHash =
            configuration
                .trustedApkSha256ByPath[normalizedPath]

        /**
         * If no trusted value is configured, the hash remains
         * informational rather than being classified as a mismatch.
         */
        if (expectedHash.isNullOrBlank()) {

            return
        }

        val normalizedExpected =
            normalizeHash(expectedHash)

        val normalizedActual =
            normalizeHash(actualHash)

        if (normalizedExpected ==
            normalizedActual
        ) {

            evidence += CodeTamperEvidence(
                type = CodeTamperEvidenceType.HASH_MATCH,
                source = "APK",
                path = path,
                description =
                    "Installed APK hash matches the trusted hash.",
                value = actualHash,
                expectedValue = expectedHash,
                severity = CodeTamperSeverity.INFO,
                confidence = 1.0
            )

        } else {

            evidence += CodeTamperEvidence(
                type = CodeTamperEvidenceType.HASH_MISMATCH,
                source = "APK",
                path = path,
                description =
                    "Installed APK hash differs from the trusted hash.",
                value = actualHash,
                expectedValue = expectedHash,
                severity = CodeTamperSeverity.CRITICAL,
                confidence = 1.0
            )
        }
    }

    /**
     * Inspects DEX entries contained inside an APK.
     *
     * No DEX file is extracted to disk and nothing is executed.
     */
    private fun inspectDexEntries(
        apkFile: File,
        evidence: MutableList<CodeTamperEvidence>
    ) {

        java.util.zip.ZipFile(apkFile).use { zipFile ->

            val entries =
                zipFile.entries()

            while (entries.hasMoreElements()) {

                val entry =
                    entries.nextElement()

                if (
                    entry.isDirectory ||
                    !isDexEntry(entry.name)
                ) {
                    continue
                }

                /**
                 * Read the DEX stream directly from the APK.
                 */
                val digest =
                    MessageDigest.getInstance(
                        "SHA-256"
                    )

                zipFile
                    .getInputStream(entry)
                    .use { inputStream ->

                        val buffer =
                            ByteArray(
                                HASH_BUFFER_SIZE
                            )

                        var totalRead = 0L

                        while (true) {

                            val bytesRead =
                                inputStream.read(buffer)

                            if (bytesRead <= 0) {
                                break
                            }

                            totalRead +=
                                bytesRead.toLong()

                            /**
                             * Prevent unexpectedly large DEX
                             * streams from consuming excessive
                             * resources.
                             */
                            if (
                                totalRead >
                                maxHashableFileSizeBytes
                            ) {

                                throw IllegalStateException(
                                    "DEX entry exceeds hashing limit."
                                )
                            }

                            digest.update(
                                buffer,
                                0,
                                bytesRead
                            )
                        }
                    }

                val hash =
                    digest
                        .digest()
                        .joinToString("") {
                            "%02X".format(it)
                        }

                evidence += CodeTamperEvidence(
                    type = CodeTamperEvidenceType.DEX_HASH,
                    source = "DEX",
                    path = "${apkFile.absolutePath}!/${entry.name}",
                    description =
                        "SHA-256 hash of a DEX entry contained in the APK.",
                    value = hash,
                    severity = CodeTamperSeverity.INFO,
                    confidence = 1.0
                )

                compareTrustedDexHash(
                    apkPath = apkFile.absolutePath,
                    dexName = entry.name,
                    actualHash = hash,
                    evidence = evidence
                )
            }
        }
    }

    /**
     * Determines whether a ZIP/APK entry represents compiled
     * Dalvik bytecode.
     */
    private fun isDexEntry(
        entryName: String
    ): Boolean {

        return entryName == "classes.dex" ||
                entryName.matches(
                    Regex(
                        """classes\d+\.dex"""
                    )
                )
    }

    /**
     * Compares a DEX hash with trusted configuration.
     */
    private fun compareTrustedDexHash(
        apkPath: String,
        dexName: String,
        actualHash: String,
        evidence: MutableList<CodeTamperEvidence>
    ) {

        val key =
            buildDexConfigurationKey(
                apkPath = apkPath,
                dexName = dexName
            )

        val expectedHash =
            configuration
                .trustedDexSha256ByEntry[key]
                ?: return

        val normalizedActual =
            normalizeHash(actualHash)

        val normalizedExpected =
            normalizeHash(expectedHash)

        if (
            normalizedActual ==
            normalizedExpected
        ) {

            evidence += CodeTamperEvidence(
                type = CodeTamperEvidenceType.DEX_HASH_MATCH,
                source = "DEX",
                path = "$apkPath!/$dexName",
                description =
                    "DEX hash matches the configured trusted hash.",
                value = actualHash,
                expectedValue = expectedHash,
                severity = CodeTamperSeverity.INFO,
                confidence = 1.0
            )

        } else {

            evidence += CodeTamperEvidence(
                type = CodeTamperEvidenceType.DEX_HASH_MISMATCH,
                source = "DEX",
                path = "$apkPath!/$dexName",
                description =
                    "DEX hash differs from the configured trusted hash.",
                value = actualHash,
                expectedValue = expectedHash,
                severity = CodeTamperSeverity.CRITICAL,
                confidence = 1.0
            )
        }
    }

    /**
     * Calculates SHA-256 for a file using a streaming approach.
     *
     * The entire file is never loaded into memory.
     */
    private fun calculateSha256(
        file: File
    ): String {

        if (!file.exists()) {
            throw IllegalArgumentException(
                "File does not exist."
            )
        }

        if (!file.isFile) {
            throw IllegalArgumentException(
                "Path is not a regular file."
            )
        }

        if (
            file.length() >
            maxHashableFileSizeBytes
        ) {
            throw IllegalArgumentException(
                "File exceeds hashing size limit."
            )
        }

        val digest =
            MessageDigest.getInstance(
                "SHA-256"
            )

        FileInputStream(file).use { inputStream ->

            val buffer =
                ByteArray(
                    HASH_BUFFER_SIZE
                )

            while (true) {

                val bytesRead =
                    inputStream.read(buffer)

                if (bytesRead <= 0) {
                    break
                }

                digest.update(
                    buffer,
                    0,
                    bytesRead
                )
            }
        }

        return digest
            .digest()
            .joinToString("") {
                "%02X".format(it)
            }
    }

    /**
     * Normalizes a cryptographic hash for comparison.
     */
    private fun normalizeHash(
        hash: String
    ): String {

        return hash
            .replace(":", "")
            .replace(" ", "")
            .trim()
            .uppercase()
    }

    /**
     * Normalizes an APK path for configuration lookup.
     *
     * The actual production configuration can use the exact
     * package installation paths observed at runtime.
     */
    private fun normalizePath(
        path: String
    ): String {

        return path.trim()
    }

    /**
     * Creates a stable configuration key for a DEX entry.
     */
    private fun buildDexConfigurationKey(
        apkPath: String,
        dexName: String
    ): String {

        return "${normalizePath(apkPath)}!/$dexName"
    }

    /**
     * Returns true if the detector found a confirmed code-hash
     * mismatch.
     */
    fun hasCodeTampering(): Boolean {

        return detect()
            .evidence
            .any {
                it.type ==
                        CodeTamperEvidenceType.HASH_MISMATCH ||
                        it.type ==
                        CodeTamperEvidenceType.DEX_HASH_MISMATCH
            }
    }

    /**
     * Returns all detected hash mismatches.
     */
    fun getHashMismatches():
            List<CodeTamperEvidence> {

        return detect()
            .evidence
            .filter {
                it.type ==
                        CodeTamperEvidenceType.HASH_MISMATCH ||
                        it.type ==
                        CodeTamperEvidenceType.DEX_HASH_MISMATCH
            }
    }

    /**
     * Returns all collected code-integrity evidence.
     */
    fun getEvidence():
            List<CodeTamperEvidence> {

        return detect().evidence
    }

    /**
     * Returns all application APK paths visible to Android.
     */
    fun getApplicationApkPathsForDiagnostics():
            List<String> {

        return getApplicationApkPaths()
    }

    companion object {

        /**
         * Streaming hash buffer size.
         */
        private const val HASH_BUFFER_SIZE =
            8192
    }
}

/**
 * Trusted code-integrity configuration.
 *
 * The configuration supports:
 *
 * - Base/split APK SHA-256 hashes.
 * - Individual DEX SHA-256 hashes.
 *
 * Multiple trusted values can be represented by multiple entries.
 */
data class CodeTamperConfiguration(

    /**
     * Trusted APK SHA-256 values indexed by normalized APK path.
     */
    val trustedApkSha256ByPath:
        Map<String, String> = emptyMap(),

    /**
     * Trusted DEX SHA-256 values indexed by:
     *
     *     <apkPath>!/classes.dex
     */
    val trustedDexSha256ByEntry:
        Map<String, String> = emptyMap()
)

/**
 * Result produced by CodeTamperDetector.
 */
data class CodeTamperResult(

    /**
     * Overall code-integrity status.
     */
    val status: CodeTamperStatus,

    /**
     * Collected code-integrity evidence.
     */
    val evidence: List<CodeTamperEvidence>,

    /**
     * Number of APK/code files inspected.
     */
    val filesChecked: Int,

    /**
     * Number of files successfully hashed.
     */
    val filesHashed: Int,

    /**
     * Number of failed checks.
     */
    val checksFailed: Int,

    /**
     * Whether the detector completed successfully.
     */
    val detectionCompleted: Boolean,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long
) {

    /**
     * Indicates whether a confirmed code-integrity mismatch exists.
     */
    val hasCodeTampering: Boolean
        get() = evidence.any {
            it.type ==
                    CodeTamperEvidenceType.HASH_MISMATCH ||
                    it.type ==
                    CodeTamperEvidenceType.DEX_HASH_MISMATCH
        }

    /**
     * Returns all mismatches.
     */
    val mismatches: List<CodeTamperEvidence>
        get() = evidence.filter {
            it.type ==
                    CodeTamperEvidenceType.HASH_MISMATCH ||
                    it.type ==
                    CodeTamperEvidenceType.DEX_HASH_MISMATCH
        }

    /**
     * Returns the strongest observed severity.
     */
    val highestSeverity: CodeTamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: CodeTamperSeverity.INFO

    private fun severityWeight(
        severity: CodeTamperSeverity
    ): Int {

        return when (severity) {

            CodeTamperSeverity.INFO -> 0
            CodeTamperSeverity.LOW -> 1
            CodeTamperSeverity.MEDIUM -> 2
            CodeTamperSeverity.HIGH -> 3
            CodeTamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Overall code-tampering state.
 */
enum class CodeTamperStatus {

    /**
     * No configured code-integrity mismatch was found.
     */
    NO_CODE_TAMPER_DETECTED,

    /**
     * Suspicious code-integrity evidence exists.
     */
    SUSPICIOUS,

    /**
     * A trusted hash mismatch was detected.
     */
    CODE_TAMPER_DETECTED,

    /**
     * The assessment could not be completed fully.
     */
    CHECK_INCOMPLETE
}

/**
 * Individual code-integrity evidence.
 */
data class CodeTamperEvidence(

    /**
     * Evidence category.
     */
    val type: CodeTamperEvidenceType,

    /**
     * Source of the evidence.
     */
    val source: String,

    /**
     * File or APK entry associated with the evidence.
     */
    val path: String?,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Observed value.
     */
    val value: String? = null,

    /**
     * Expected trusted value.
     */
    val expectedValue: String? = null,

    /**
     * Evidence severity.
     */
    val severity: CodeTamperSeverity,

    /**
     * Confidence in the observation.
     *
     * This is not the probability that tampering occurred.
     */
    val confidence: Double
)

/**
 * Code-integrity evidence categories.
 */
enum class CodeTamperEvidenceType {

    /**
     * Application APK path could not be identified.
     */
    APK_PATH_UNAVAILABLE,

    /**
     * APK file is missing.
     */
    FILE_MISSING,

    /**
     * Discovered path is not a regular file.
     */
    INVALID_FILE,

    /**
     * File exceeds the configured hashing limit.
     */
    FILE_TOO_LARGE,

    /**
     * APK SHA-256 hash.
     */
    APK_HASH,

    /**
     * APK hash matches trusted configuration.
     */
    HASH_MATCH,

    /**
     * APK hash differs from trusted configuration.
     */
    HASH_MISMATCH,

    /**
     * APK hashing failed.
     */
    HASH_FAILED,

    /**
     * DEX SHA-256 hash.
     */
    DEX_HASH,

    /**
     * DEX hash matches trusted configuration.
     */
    DEX_HASH_MATCH,

    /**
     * DEX hash differs from trusted configuration.
     */
    DEX_HASH_MISMATCH,

    /**
     * DEX inspection failed.
     */
    DEX_INSPECTION_FAILED
}

/**
 * Severity of code-integrity evidence.
 */
enum class CodeTamperSeverity {

    /**
     * Informational.
     */
    INFO,

    /**
     * Weak indicator.
     */
    LOW,

    /**
     * Moderate indicator.
     */
    MEDIUM,

    /**
     * Strong indicator.
     */
    HIGH,

    /**
     * Critical integrity mismatch.
     */
    CRITICAL
}
