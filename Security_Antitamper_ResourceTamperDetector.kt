package com.sentrix.security.antitamper

import android.content.Context
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * ResourceTamperDetector
 *
 * Detects potential modification of application resources packaged
 * inside the installed APK.
 *
 * Resources can include:
 *
 * - XML resources
 * - JSON configuration files
 * - Images
 * - Fonts
 * - Raw resources
 * - Assets
 * - Resource table information
 *
 * Responsibilities:
 *
 * - Locate the installed application APK.
 * - Inspect resource-related APK entries.
 * - Calculate SHA-256 hashes for selected resources.
 * - Compare resource hashes against trusted configuration.
 * - Produce structured resource-integrity evidence.
 *
 * This class does NOT:
 *
 * - modify resources
 * - extract resources to disk
 * - execute resource contents
 * - alter application state
 * - perform final tamper classification
 *
 * Architecture:
 *
 * AntiTamperManager
 *        ↓
 * ResourceTamperDetector
 *        ↓
 * ResourceTamperEvidence
 *        ↓
 * AntiTamperEvidenceCollector
 *        ↓
 * AntiTamperValidator
 *
 * IMPORTANT:
 *
 * Only trusted resource hashes should be treated as authoritative.
 * A locally stored configuration that can be modified together with
 * the application cannot serve as a strong trust anchor.
 */
class ResourceTamperDetector(
    private val context: Context,
    private val configuration: ResourceTamperConfiguration =
        ResourceTamperConfiguration()
) {

    /**
     * Maximum resource entry size that can be hashed.
     *
     * This prevents an unexpected APK entry from consuming
     * excessive resources during integrity analysis.
     */
    private val maxResourceSizeBytes =
        100L * 1024L * 1024L

    /**
     * Performs the complete resource-integrity assessment.
     */
    fun detect(): ResourceTamperResult {

        val evidence =
            mutableListOf<ResourceTamperEvidence>()

        var apkFilesChecked = 0
        var resourcesChecked = 0
        var resourcesHashed = 0
        var checksFailed = 0

        val apkPaths =
            try {
                getApplicationApkPaths()
            } catch (_: Exception) {
                checksFailed++
                emptyList()
            }

        if (apkPaths.isEmpty()) {

            evidence += ResourceTamperEvidence(
                type =
                    ResourceTamperEvidenceType.APK_UNAVAILABLE,
                source = "ApplicationInfo",
                resourcePath = null,
                description =
                    "Application APK could not be located.",
                severity = ResourceTamperSeverity.HIGH,
                confidence = 0.70
            )
        }

        apkPaths.forEach { apkPath ->

            val apkFile =
                File(apkPath)

            apkFilesChecked++

            if (!apkFile.exists()) {

                checksFailed++

                evidence += ResourceTamperEvidence(
                    type =
                        ResourceTamperEvidenceType.APK_MISSING,
                    source = "APK",
                    resourcePath = apkPath,
                    description =
                        "Application APK does not exist.",
                    severity = ResourceTamperSeverity.HIGH,
                    confidence = 0.90
                )

                return@forEach
            }

            if (!apkFile.isFile) {

                checksFailed++

                evidence += ResourceTamperEvidence(
                    type =
                        ResourceTamperEvidenceType.INVALID_APK,
                    source = "APK",
                    resourcePath = apkPath,
                    description =
                        "Application APK path is not a regular file.",
                    severity = ResourceTamperSeverity.MEDIUM,
                    confidence = 0.80
                )

                return@forEach
            }

            try {

                val result =
                    inspectApkResources(
                        apkFile = apkFile,
                        evidence = evidence
                    )

                resourcesChecked +=
                    result.resourcesChecked

                resourcesHashed +=
                    result.resourcesHashed

                checksFailed +=
                    result.checksFailed

            } catch (_: Exception) {

                checksFailed++

                evidence += ResourceTamperEvidence(
                    type =
                        ResourceTamperEvidenceType.APK_INSPECTION_FAILED,
                    source = "APK",
                    resourcePath = apkPath,
                    description =
                        "APK resource inspection failed.",
                    severity = ResourceTamperSeverity.MEDIUM,
                    confidence = 0.60
                )
            }
        }

        val status =
            determineStatus(
                evidence = evidence,
                checksFailed = checksFailed
            )

        return ResourceTamperResult(
            status = status,
            evidence = evidence,
            apkFilesChecked = apkFilesChecked,
            resourcesChecked = resourcesChecked,
            resourcesHashed = resourcesHashed,
            checksFailed = checksFailed,
            detectionCompleted =
                checksFailed == 0 &&
                        apkPaths.isNotEmpty(),
            detectedAt = System.currentTimeMillis()
        )
    }

    /**
     * Inspects resource entries within one APK.
     *
     * The APK is treated as a ZIP archive. Entries are inspected
     * directly without extracting them to the filesystem.
     */
    private fun inspectApkResources(
        apkFile: File,
        evidence: MutableList<ResourceTamperEvidence>
    ): ResourceInspectionSummary {

        var resourcesChecked = 0
        var resourcesHashed = 0
        var checksFailed = 0

        ZipFile(apkFile).use { zipFile ->

            val entries =
                zipFile.entries()

            while (entries.hasMoreElements()) {

                val entry =
                    entries.nextElement()

                if (entry.isDirectory) {
                    continue
                }

                if (!isResourceEntry(entry)) {
                    continue
                }

                resourcesChecked++

                val entrySize =
                    entrySizeSafely(entry)

                if (
                    entrySize >
                    maxResourceSizeBytes
                ) {

                    evidence += ResourceTamperEvidence(
                        type =
                            ResourceTamperEvidenceType.RESOURCE_TOO_LARGE,
                        source = "APK",
                        resourcePath =
                            "${apkFile.absolutePath}!/${entry.name}",
                        description =
                            "Resource exceeds the configured hashing limit.",
                        value = entrySize.toString(),
                        severity = ResourceTamperSeverity.MEDIUM,
                        confidence = 1.0
                    )

                    continue
                }

                try {

                    val hash =
                        calculateEntrySha256(
                            zipFile = zipFile,
                            entry = entry
                        )

                    resourcesHashed++

                    val resourcePath =
                        buildResourcePath(
                            apkFile = apkFile,
                            entryName = entry.name
                        )

                    evidence += ResourceTamperEvidence(
                        type =
                            ResourceTamperEvidenceType.RESOURCE_HASH,
                        source = "APK_RESOURCE",
                        resourcePath = resourcePath,
                        description =
                            "SHA-256 hash of an application resource.",
                        value = hash,
                        severity = ResourceTamperSeverity.INFO,
                        confidence = 1.0
                    )

                    compareTrustedHash(
                        resourcePath = resourcePath,
                        entryName = entry.name,
                        actualHash = hash,
                        evidence = evidence
                    )

                } catch (_: Exception) {

                    checksFailed++

                    evidence += ResourceTamperEvidence(
                        type =
                            ResourceTamperEvidenceType.RESOURCE_HASH_FAILED,
                        source = "APK_RESOURCE",
                        resourcePath =
                            "${apkFile.absolutePath}!/${entry.name}",
                        description =
                            "Resource hash calculation failed.",
                        severity = ResourceTamperSeverity.MEDIUM,
                        confidence = 0.60
                    )
                }
            }
        }

        return ResourceInspectionSummary(
            resourcesChecked = resourcesChecked,
            resourcesHashed = resourcesHashed,
            checksFailed = checksFailed
        )
    }

    /**
     * Determines whether an APK entry should be considered a
     * resource for this detector.
     *
     * Code entries such as classes.dex are intentionally excluded.
     */
    private fun isResourceEntry(
        entry: ZipEntry
    ): Boolean {

        val name =
            entry.name

        /**
         * Resource table.
         */
        if (name == "resources.arsc") {
            return configuration.includeResourceTable
        }

        /**
         * Android resource directory.
         */
        if (name.startsWith("res/")) {
            return true
        }

        /**
         * Application assets.
         */
        if (name.startsWith("assets/")) {
            return true
        }

        /**
         * Native libraries and compiled code are intentionally
         * handled by other integrity components.
         */
        if (name.startsWith("lib/")) {
            return false
        }

        /**
         * META-INF contains signing/package metadata and should
         * not be treated as application resources here.
         */
        if (name.startsWith("META-INF/")) {
            return false
        }

        /**
         * DEX files are code, not resources.
         */
        if (name == "classes.dex") {
            return false
        }

        if (
            name.matches(
                Regex(
                    """classes\d+\.dex"""
                )
            )
        ) {
            return false
        }

        /**
         * Include explicitly configured resource paths.
         */
        return configuration
            .additionalResourcePrefixes
            .any { prefix ->
                name.startsWith(prefix)
            }
    }

    /**
     * Calculates SHA-256 directly from an APK ZIP entry.
     */
    private fun calculateEntrySha256(
        zipFile: ZipFile,
        entry: ZipEntry
    ): String {

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

                    if (
                        totalRead >
                        maxResourceSizeBytes
                    ) {

                        throw IllegalStateException(
                            "Resource exceeds hashing limit."
                        )
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
     * Compares an observed resource hash against the trusted
     * configuration.
     *
     * A resource without a configured expected hash is still
     * reported as informational evidence.
     */
    private fun compareTrustedHash(
        resourcePath: String,
        entryName: String,
        actualHash: String,
        evidence: MutableList<ResourceTamperEvidence>
    ) {

        val expectedHash =
            configuration
                .trustedResourceSha256ByPath[
                    resourcePath
                ]
                ?: configuration
                    .trustedResourceSha256ByEntry[
                        entryName
                    ]
                ?: return

        val normalizedActual =
            normalizeHash(actualHash)

        val normalizedExpected =
            normalizeHash(expectedHash)

        if (
            normalizedActual ==
            normalizedExpected
        ) {

            evidence += ResourceTamperEvidence(
                type =
                    ResourceTamperEvidenceType.HASH_MATCH,
                source = "TrustedResourceHash",
                resourcePath = resourcePath,
                description =
                    "Resource hash matches the trusted configuration.",
                value = actualHash,
                expectedValue = expectedHash,
                severity = ResourceTamperSeverity.INFO,
                confidence = 1.0
            )

        } else {

            evidence += ResourceTamperEvidence(
                type =
                    ResourceTamperEvidenceType.HASH_MISMATCH,
                source = "TrustedResourceHash",
                resourcePath = resourcePath,
                description =
                    "Resource hash differs from the trusted configuration.",
                value = actualHash,
                expectedValue = expectedHash,
                severity = ResourceTamperSeverity.CRITICAL,
                confidence = 1.0
            )
        }
    }

    /**
     * Returns all APK paths associated with the application.
     */
    private fun getApplicationApkPaths(): List<String> {

        val paths =
            mutableListOf<String>()

        val applicationInfo =
            context.applicationInfo

        applicationInfo.sourceDir
            ?.takeIf {
                it.isNotBlank()
            }
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
     * Builds a stable resource identifier.
     */
    private fun buildResourcePath(
        apkFile: File,
        entryName: String
    ): String {

        return "${apkFile.absolutePath}!/$entryName"
    }

    /**
     * Safely obtains ZIP entry size.
     *
     * Some ZIP entries may not provide a known size.
     */
    private fun entrySizeSafely(
        entry: ZipEntry
    ): Long {

        val size =
            entry.size

        return if (size >= 0L) {
            size
        } else {
            0L
        }
    }

    /**
     * Normalizes a SHA-256 value for comparison.
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
     * Determines the overall detector state.
     */
    private fun determineStatus(
        evidence: List<ResourceTamperEvidence>,
        checksFailed: Int
    ): ResourceTamperStatus {

        val mismatchDetected =
            evidence.any {
                it.type ==
                        ResourceTamperEvidenceType.HASH_MISMATCH
            }

        if (mismatchDetected) {
            return ResourceTamperStatus.RESOURCE_TAMPER_DETECTED
        }

        val strongEvidence =
            evidence.any {
                it.severity == ResourceTamperSeverity.HIGH ||
                        it.severity == ResourceTamperSeverity.CRITICAL
            }

        if (strongEvidence) {
            return ResourceTamperStatus.SUSPICIOUS
        }

        if (checksFailed > 0) {
            return ResourceTamperStatus.CHECK_INCOMPLETE
        }

        return ResourceTamperStatus.NO_RESOURCE_TAMPER_DETECTED
    }

    /**
     * Returns true when a trusted resource hash mismatch exists.
     */
    fun hasResourceTampering(): Boolean {

        return detect()
            .evidence
            .any {
                it.type ==
                        ResourceTamperEvidenceType.HASH_MISMATCH
            }
    }

    /**
     * Returns all resource hash mismatches.
     */
    fun getHashMismatches():
            List<ResourceTamperEvidence> {

        return detect()
            .evidence
            .filter {
                it.type ==
                        ResourceTamperEvidenceType.HASH_MISMATCH
            }
    }

    /**
     * Returns all resource integrity evidence.
     */
    fun getEvidence():
            List<ResourceTamperEvidence> {

        return detect().evidence
    }

    companion object {

        /**
         * Streaming hash buffer.
         */
        private const val HASH_BUFFER_SIZE =
            8192
    }
}

/**
 * Trusted resource-integrity configuration.
 */
data class ResourceTamperConfiguration(

    /**
     * Trusted SHA-256 hashes indexed by complete runtime resource
     * path.
     */
    val trustedResourceSha256ByPath:
        Map<String, String> = emptyMap(),

    /**
     * Trusted SHA-256 hashes indexed by APK entry name.
     *
     * Example:
     *
     * res/layout/activity_main.xml
     * assets/security_rules.json
     */
    val trustedResourceSha256ByEntry:
        Map<String, String> = emptyMap(),

    /**
     * Whether resources.arsc should be included.
     */
    val includeResourceTable: Boolean = true,

    /**
     * Additional APK entry prefixes that should be treated as
     * resources.
     */
    val additionalResourcePrefixes:
        Set<String> = emptySet()
)

/**
 * Internal summary of one APK resource inspection.
 */
private data class ResourceInspectionSummary(

    val resourcesChecked: Int,

    val resourcesHashed: Int,

    val checksFailed: Int
)

/**
 * Complete resource tamper result.
 */
data class ResourceTamperResult(

    /**
     * Overall resource-integrity state.
     */
    val status: ResourceTamperStatus,

    /**
     * Collected evidence.
     */
    val evidence: List<ResourceTamperEvidence>,

    /**
     * Number of APK files inspected.
     */
    val apkFilesChecked: Int,

    /**
     * Number of resource entries inspected.
     */
    val resourcesChecked: Int,

    /**
     * Number of resource entries successfully hashed.
     */
    val resourcesHashed: Int,

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
     * True when a trusted resource mismatch was detected.
     */
    val hasResourceTampering: Boolean
        get() = evidence.any {
            it.type ==
                    ResourceTamperEvidenceType.HASH_MISMATCH
        }

    /**
     * Returns all mismatches.
     */
    val mismatches:
            List<ResourceTamperEvidence>
        get() = evidence.filter {
            it.type ==
                    ResourceTamperEvidenceType.HASH_MISMATCH
        }

    /**
     * Returns the strongest evidence severity.
     */
    val highestSeverity: ResourceTamperSeverity
        get() =
            evidence
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: ResourceTamperSeverity.INFO

    private fun severityWeight(
        severity: ResourceTamperSeverity
    ): Int {

        return when (severity) {

            ResourceTamperSeverity.INFO -> 0
            ResourceTamperSeverity.LOW -> 1
            ResourceTamperSeverity.MEDIUM -> 2
            ResourceTamperSeverity.HIGH -> 3
            ResourceTamperSeverity.CRITICAL -> 4
        }
    }
}

/**
 * Individual resource-integrity evidence.
 */
data class ResourceTamperEvidence(

    /**
     * Evidence type.
     */
    val type: ResourceTamperEvidenceType,

    /**
     * Source of the evidence.
     */
    val source: String,

    /**
     * APK/resource path associated with the evidence.
     */
    val resourcePath: String?,

    /**
     * Human-readable description.
     */
    val description: String,

    /**
     * Observed value.
     */
    val value: String? = null,

    /**
     * Trusted expected value.
     */
    val expectedValue: String? = null,

    /**
     * Security severity.
     */
    val severity: ResourceTamperSeverity,

    /**
     * Confidence in the observation.
     *
     * This is not the probability that tampering occurred.
     */
    val confidence: Double
)

/**
 * Resource tamper evidence categories.
 */
enum class ResourceTamperEvidenceType {

    /**
     * Application APK could not be located.
     */
    APK_UNAVAILABLE,

    /**
     * APK does not exist.
     */
    APK_MISSING,

    /**
     * APK path is invalid.
     */
    INVALID_APK,

    /**
     * APK resource inspection failed.
     */
    APK_INSPECTION_FAILED,

    /**
     * Resource is too large to hash.
     */
    RESOURCE_TOO_LARGE,

    /**
     * SHA-256 hash of a resource.
     */
    RESOURCE_HASH,

    /**
     * Resource hash matches trusted configuration.
     */
    HASH_MATCH,

    /**
     * Resource hash differs from trusted configuration.
     */
    HASH_MISMATCH,

    /**
     * Resource hashing failed.
     */
    RESOURCE_HASH_FAILED
}

/**
 * Severity of resource-integrity evidence.
 */
enum class ResourceTamperSeverity {

    /**
     * Normal informational observation.
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

/**
 * Overall resource-tamper state.
 */
enum class ResourceTamperStatus {

    /**
     * No trusted resource mismatch detected.
     */
    NO_RESOURCE_TAMPER_DETECTED,

    /**
     * Suspicious resource-integrity evidence exists.
     */
    SUSPICIOUS,

    /**
     * A trusted resource hash mismatch was detected.
     */
    RESOURCE_TAMPER_DETECTED,

    /**
     * The resource scan could not fully complete.
     */
    CHECK_INCOMPLETE
}
