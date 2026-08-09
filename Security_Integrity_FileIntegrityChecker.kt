package com.sentrix.security.integrity

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * SentriX File Integrity Checker
 *
 * Performs cryptographic and metadata-based integrity verification
 * for files used by the SentriX application.
 *
 * Responsibilities:
 *
 * - Calculate cryptographic file hashes.
 * - Verify files against trusted hashes.
 * - Create file integrity baselines.
 * - Compare files against previously trusted baselines.
 * - Detect file modification.
 * - Detect file deletion.
 * - Detect unexpected file creation.
 * - Inspect file metadata.
 * - Support batch file integrity verification.
 *
 * Supported algorithms:
 *
 * - SHA-256
 * - SHA-512
 *
 * Architecture:
 *
 *                 FileIntegrityChecker
 *                         │
 *             ┌───────────┼───────────┐
 *             ▼           ▼           ▼
 *         File Hash   Metadata     Baseline
 *             │           │           │
 *             └───────────┼───────────┘
 *                         ▼
 *                  FileIntegrityResult
 *                         │
 *                         ▼
 *                  IntegrityValidator
 *
 * Security note:
 *
 * A cryptographic hash detects content changes, but a hash alone does not
 * establish that the file is trustworthy. The expected hash must itself
 * originate from a trusted source.
 */
class FileIntegrityChecker {

    /**
     * Trusted file baselines maintained in memory.
     *
     * The map is thread-safe because file checks may be triggered from
     * background security workers.
     */
    private val baselines =
        ConcurrentHashMap<String, FileIntegrityBaseline>()

    // =========================================================================
    // Main File Check
    // =========================================================================

    /**
     * Checks a single file using SHA-256.
     */
    fun check(
        file: File
    ): FileIntegrityResult {

        return check(
            file = file,
            algorithm = FileHashAlgorithm.SHA_256
        )
    }

    /**
     * Checks a file using the requested cryptographic hash algorithm.
     */
    fun check(
        file: File,
        algorithm: FileHashAlgorithm
    ): FileIntegrityResult {

        if (
            !file.exists()
        ) {

            return FileIntegrityResult.Failed(
                path =
                    file.absolutePath,
                reason =
                    "File does not exist."
            )
        }

        if (
            !file.isFile
        ) {

            return FileIntegrityResult.Failed(
                path =
                    file.absolutePath,
                reason =
                    "Path does not reference a regular file."
            )
        }

        if (
            !file.canRead()
        ) {

            return FileIntegrityResult.Failed(
                path =
                    file.absolutePath,
                reason =
                    "File is not readable."
            )
        }

        val hash =
            calculateHash(
                file = file,
                algorithm = algorithm
            )

        if (
            hash == null
        ) {

            return FileIntegrityResult.Failed(
                path =
                    file.absolutePath,
                reason =
                    "Unable to calculate file hash."
            )
        }

        val metadata =
            collectMetadata(
                file
            )

        val baseline =
            baselines[
                file.absolutePath
            ]

        val comparison =
            if (
                baseline != null
            ) {

                compareWithBaseline(
                    file = file,
                    currentHash = hash,
                    baseline = baseline
                )

            } else {

                FileIntegrityComparison
                    .NoBaseline
            }

        val status =
            determineStatus(
                comparison =
                    comparison
            )

        return FileIntegrityResult.Checked(

            path =
                file.absolutePath,

            algorithm =
                algorithm,

            hash =
                hash,

            metadata =
                metadata,

            baselinePresent =
                baseline != null,

            comparison =
                comparison,

            status =
                status,

            checkedAtMillis =
                System.currentTimeMillis()
        )
    }

    // =========================================================================
    // Hash Calculation
    // =========================================================================

    /**
     * Calculates a cryptographic hash for a file.
     *
     * The file is processed as a stream rather than being loaded entirely
     * into memory.
     */
    fun calculateHash(
        file: File,
        algorithm: FileHashAlgorithm
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
                    algorithm.jcaName
                )

            FileInputStream(
                file
            )
                .buffered()
                .use { input ->

                    val buffer =
                        ByteArray(
                            DEFAULT_BUFFER_SIZE
                        )

                    while (
                        true
                    ) {

                        val bytesRead =
                            input.read(
                                buffer
                            )

                        if (
                            bytesRead <= 0
                        ) {

                            break
                        }

                        digest.update(
                            buffer,
                            0,
                            bytesRead
                        )
                    }
                }

            formatHash(
                digest.digest()
            )

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Calculates a SHA-256 hash for a file.
     */
    fun calculateSha256(
        file: File
    ): String? {

        return calculateHash(
            file = file,
            algorithm =
                FileHashAlgorithm.SHA_256
        )
    }

    /**
     * Calculates a SHA-512 hash for a file.
     */
    fun calculateSha512(
        file: File
    ): String? {

        return calculateHash(
            file = file,
            algorithm =
                FileHashAlgorithm.SHA_512
        )
    }

    // =========================================================================
    // Expected Hash Verification
    // =========================================================================

    /**
     * Verifies a file against an expected SHA-256 hash.
     */
    fun verifySha256(
        file: File,
        expectedHash: String
    ): FileHashVerificationResult {

        return verify(
            file =
                file,
            expectedHash =
                expectedHash,
            algorithm =
                FileHashAlgorithm.SHA_256
        )
    }

    /**
     * Verifies a file against an expected SHA-512 hash.
     */
    fun verifySha512(
        file: File,
        expectedHash: String
    ): FileHashVerificationResult {

        return verify(
            file =
                file,
            expectedHash =
                expectedHash,
            algorithm =
                FileHashAlgorithm.SHA_512
        )
    }

    /**
     * Verifies a file against an expected cryptographic hash.
     */
    fun verify(
        file: File,
        expectedHash: String,
        algorithm: FileHashAlgorithm
    ): FileHashVerificationResult {

        val normalizedExpected =
            normalizeHash(
                expectedHash
            )

        if (
            normalizedExpected.isBlank()
        ) {

            return FileHashVerificationResult
                .InvalidExpectedHash(
                    reason =
                        "Expected hash is empty."
                )
        }

        if (
            !isValidHashFormat(
                normalizedExpected,
                algorithm
            )
        ) {

            return FileHashVerificationResult
                .InvalidExpectedHash(
                    reason =
                        "Expected hash does not match the " +
                                "${algorithm.displayName} format."
                )
        }

        val actualHash =
            calculateHash(
                file =
                    file,
                algorithm =
                    algorithm
            )

        if (
            actualHash == null
        ) {

            return FileHashVerificationResult
                .UnableToCalculateHash
        }

        val matches =
            secureHashEquals(
                actualHash,
                normalizedExpected
            )

        return if (
            matches
        ) {

            FileHashVerificationResult
                .Match(
                    actualHash =
                        actualHash
                )

        } else {

            FileHashVerificationResult
                .Mismatch(
                    expectedHash =
                        normalizedExpected,
                    actualHash =
                        actualHash
                )
        }
    }

    // =========================================================================
    // Baseline Management
    // =========================================================================

    /**
     * Creates a trusted baseline from the current file.
     *
     * The caller is responsible for ensuring that the file is trusted before
     * creating the baseline.
     */
    fun createBaseline(
        file: File,
        algorithm: FileHashAlgorithm =
            FileHashAlgorithm.SHA_256
    ): FileIntegrityBaseline? {

        val hash =
            calculateHash(
                file =
                    file,
                algorithm =
                    algorithm
            )
                ?: return null

        val metadata =
            collectMetadata(
                file
            )
                ?: return null

        val baseline =
            FileIntegrityBaseline(

                path =
                    file.absolutePath,

                algorithm =
                    algorithm,

                expectedHash =
                    hash,

                expectedSize =
                    metadata.size,

                expectedLastModified =
                    metadata.lastModified,

                createdAtMillis =
                    System.currentTimeMillis()
            )

        baselines[
            file.absolutePath
        ] =
            baseline

        return baseline
    }

    /**
     * Registers an externally supplied trusted baseline.
     */
    fun registerBaseline(
        baseline: FileIntegrityBaseline
    ) {

        baselines[
            baseline.path
        ] =
            baseline
    }

    /**
     * Gets a baseline for a file.
     */
    fun getBaseline(
        file: File
    ): FileIntegrityBaseline? {

        return baselines[
            file.absolutePath
        ]
    }

    /**
     * Gets a baseline by absolute path.
     */
    fun getBaseline(
        path: String
    ): FileIntegrityBaseline? {

        return baselines[
            File(
                path
            ).absolutePath
        ]
    }

    /**
     * Determines whether a baseline exists.
     */
    fun hasBaseline(
        file: File
    ): Boolean {

        return baselines.containsKey(
            file.absolutePath
        )
    }

    /**
     * Removes a file baseline.
     */
    fun removeBaseline(
        file: File
    ): Boolean {

        return baselines.remove(
            file.absolutePath
        ) != null
    }

    /**
     * Removes all file baselines.
     */
    fun clearBaselines() {

        baselines.clear()
    }

    /**
     * Returns all registered baselines.
     */
    fun getAllBaselines():
            List<FileIntegrityBaseline> {

        return baselines.values.toList()
    }

    // =========================================================================
    // Baseline Verification
    // =========================================================================

    /**
     * Checks a file against its registered baseline.
     */
    fun verifyAgainstBaseline(
        file: File
    ): FileIntegrityComparison {

        val baseline =
            getBaseline(
                file
            )
                ?: return FileIntegrityComparison
                    .NoBaseline

        if (
            !file.exists()
        ) {

            return FileIntegrityComparison
                .FileDeleted
        }

        if (
            !file.isFile
        ) {

            return FileIntegrityComparison
                .InvalidFileType
        }

        val currentHash =
            calculateHash(
                file =
                    file,
                algorithm =
                    baseline.algorithm
            )
                ?: return FileIntegrityComparison
                    .UnableToCalculateHash

        return compareWithBaseline(
            file =
                file,
            currentHash =
                currentHash,
            baseline =
                baseline
        )
    }

    /**
     * Compares current file state with a supplied baseline.
     */
    private fun compareWithBaseline(
        file: File,
        currentHash: String,
        baseline: FileIntegrityBaseline
    ): FileIntegrityComparison {

        if (
            !file.exists()
        ) {

            return FileIntegrityComparison
                .FileDeleted
        }

        if (
            !file.isFile
        ) {

            return FileIntegrityComparison
                .InvalidFileType
        }

        val hashMatches =
            secureHashEquals(
                currentHash,
                baseline.expectedHash
            )

        val currentMetadata =
            collectMetadata(
                file
            )

        if (
            currentMetadata == null
        ) {

            return FileIntegrityComparison
                .MetadataUnavailable
        }

        /*
         * Cryptographic hash is the primary integrity signal.
         *
         * Metadata changes alone are not considered content tampering because
         * file timestamps can legitimately change without file contents
         * changing.
         */
        return if (
            hashMatches
        ) {

            FileIntegrityComparison
                .Match

        } else {

            FileIntegrityComparison
                .HashMismatch
        }
    }

    // =========================================================================
    // Metadata
    // =========================================================================

    /**
     * Collects file metadata.
     */
    fun collectMetadata(
        file: File
    ): FileIntegrityMetadata? {

        if (
            !file.exists()
        ) {

            return null
        }

        return try {

            FileIntegrityMetadata(

                path =
                    file.absolutePath,

                name =
                    file.name,

                size =
                    file.length(),

                lastModified =
                    file.lastModified(),

                isFile =
                    file.isFile,

                isDirectory =
                    file.isDirectory,

                canRead =
                    file.canRead(),

                canWrite =
                    file.canWrite(),

                canExecute =
                    file.canExecute()
            )

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Checks whether file metadata is consistent with a baseline.
     *
     * Metadata differences are reported separately from cryptographic
     * content changes.
     */
    fun checkMetadata(
        file: File,
        baseline: FileIntegrityBaseline
    ): FileMetadataComparison {

        if (
            !file.exists()
        ) {

            return FileMetadataComparison
                .FileDeleted
        }

        val metadata =
            collectMetadata(
                file
            )
                ?: return FileMetadataComparison
                    .Unavailable

        val sizeChanged =
            metadata.size !=
                    baseline.expectedSize

        val modifiedChanged =
            metadata.lastModified !=
                    baseline.expectedLastModified

        return when {

            sizeChanged &&
                    modifiedChanged ->

                FileMetadataComparison
                    .SizeAndTimestampChanged

            sizeChanged ->

                FileMetadataComparison
                    .SizeChanged

            modifiedChanged ->

                FileMetadataComparison
                    .TimestampChanged

            else ->

                FileMetadataComparison
                    .Unchanged
        }
    }

    // =========================================================================
    // Directory Checks
    // =========================================================================

    /**
     * Recursively checks all regular files inside a directory.
     *
     * Only files with registered baselines are validated.
     *
     * Unexpected files can optionally be reported.
     */
    fun checkDirectory(
        directory: File,
        reportUnexpectedFiles: Boolean = true
    ): DirectoryIntegrityResult {

        if (
            !directory.exists()
        ) {

            return DirectoryIntegrityResult
                .Failed(
                    reason =
                        "Directory does not exist."
                )
        }

        if (
            !directory.isDirectory
        ) {

            return DirectoryIntegrityResult
                .Failed(
                    reason =
                        "Path does not reference a directory."
                )
        }

        val files =
            try {

                directory
                    .walkTopDown()
                    .filter {
                        it.isFile
                    }
                    .toList()

            } catch (
                _: Exception
            ) {

                return DirectoryIntegrityResult
                    .Failed(
                        reason =
                            "Unable to enumerate directory."
                    )
            }

        val checked =
            mutableListOf<FileIntegrityResult>()

        val unexpected =
            mutableListOf<File>()

        files.forEach {
            file ->

            val baseline =
                getBaseline(
                    file
                )

            if (
                baseline != null
            ) {

                checked +=
                    check(
                        file
                    )

            } else if (
                reportUnexpectedFiles
            ) {

                unexpected +=
                    file
            }
        }

        val modified =
            checked.filter {
                result ->

                result is
                        FileIntegrityResult.Checked &&
                        result.status ==
                        FileIntegrityStatus
                            .MODIFIED
            }

        val missingBaselines =
            checked.filter {
                result ->

                result is
                        FileIntegrityResult.Checked &&
                        result.status ==
                        FileIntegrityStatus
                            .NO_BASELINE
            }

        return DirectoryIntegrityResult.Checked(

            directory =
                directory.absolutePath,

            filesScanned =
                files.size,

            filesChecked =
                checked,

            modifiedFiles =
                modified,

            unexpectedFiles =
                unexpected,

            noBaselineFiles =
                missingBaselines
        )
    }

    // =========================================================================
    // Batch Checks
    // =========================================================================

    /**
     * Checks multiple files.
     */
    fun checkFiles(
        files: Collection<File>
    ): List<FileIntegrityResult> {

        return files.map {
            file ->
            check(
                file
            )
        }
    }

    /**
     * Verifies multiple files against expected hashes.
     */
    fun verifyFiles(
        expectedHashes:
            Map<File, String>,
        algorithm:
            FileHashAlgorithm =
            FileHashAlgorithm.SHA_256
    ): List<FileHashVerificationResult> {

        return expectedHashes.map {
            (file, expectedHash) ->

            verify(
                file =
                    file,
                expectedHash =
                    expectedHash,
                algorithm =
                    algorithm
            )
        }
    }

    // =========================================================================
    // Status
    // =========================================================================

    /**
     * Converts baseline comparison into a high-level file status.
     */
    private fun determineStatus(
        comparison:
            FileIntegrityComparison
    ): FileIntegrityStatus {

        return when (
            comparison
        ) {

            FileIntegrityComparison.Match ->
                FileIntegrityStatus
                    .INTACT

            FileIntegrityComparison.HashMismatch ->
                FileIntegrityStatus
                    .MODIFIED

            FileIntegrityComparison.FileDeleted ->
                FileIntegrityStatus
                    .DELETED

            FileIntegrityComparison.InvalidFileType ->
                FileIntegrityStatus
                    .INVALID

            FileIntegrityComparison.MetadataUnavailable,
            FileIntegrityComparison.UnableToCalculateHash ->
                FileIntegrityStatus
                    .UNVERIFIABLE

            FileIntegrityComparison.NoBaseline ->
                FileIntegrityStatus
                    .NO_BASELINE
        }
    }

    // =========================================================================
    // Hash Validation
    // =========================================================================

    /**
     * Validates the expected hash format.
     */
    fun isValidHashFormat(
        hash: String,
        algorithm: FileHashAlgorithm
    ): Boolean {

        val normalized =
            normalizeHash(
                hash
            )

        val expectedLength =
            when (
                algorithm
            ) {

                FileHashAlgorithm.SHA_256 ->
                    64

                FileHashAlgorithm.SHA_512 ->
                    128
            }

        if (
            normalized.length !=
            expectedLength
        ) {

            return false
        }

        return normalized.all {
            character ->
            character in '0'..'9' ||
                    character in 'A'..'F'
        }
    }

    /**
     * Normalizes a hash for comparison.
     */
    fun normalizeHash(
        hash: String
    ): String {

        return hash
            .trim()
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
            .uppercase()
    }

    /**
     * Constant-time hash comparison.
     */
    private fun secureHashEquals(
        first: String,
        second: String
    ): Boolean {

        val firstNormalized =
            normalizeHash(
                first
            )

        val secondNormalized =
            normalizeHash(
                second
            )

        if (
            firstNormalized.length !=
            secondNormalized.length
        ) {

            return false
        }

        var difference =
            0

        for (
            index in
                firstNormalized.indices
        ) {

            difference =
                difference or
                        (
                            firstNormalized[index].code xor
                                    secondNormalized[index].code
                            )
        }

        return difference == 0
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /**
     * Returns true when a file currently matches its trusted baseline.
     */
    fun isIntact(
        file: File
    ): Boolean {

        return verifyAgainstBaseline(
            file
        ) ==
                FileIntegrityComparison.Match
    }

    /**
     * Returns true when a file has changed compared with its baseline.
     */
    fun isModified(
        file: File
    ): Boolean {

        return verifyAgainstBaseline(
            file
        ) ==
                FileIntegrityComparison.HashMismatch
    }

    /**
     * Returns true when a file has been deleted.
     */
    fun isDeleted(
        file: File
    ): Boolean {

        return verifyAgainstBaseline(
            file
        ) ==
                FileIntegrityComparison.FileDeleted
    }
}

// =============================================================================
// Hash Algorithm
// =============================================================================

/**
 * Supported cryptographic file-hashing algorithms.
 */
enum class FileHashAlgorithm(
    val jcaName: String,
    val displayName: String
) {

    SHA_256(
        jcaName =
            "SHA-256",
        displayName =
            "SHA-256"
    ),

    SHA_512(
        jcaName =
            "SHA-512",
        displayName =
            "SHA-512"
    )
}

// =============================================================================
// File Integrity Result
// =============================================================================

/**
 * Result of inspecting a file.
 */
sealed class FileIntegrityResult {

    /**
     * File was successfully inspected.
     */
    data class Checked(

        val path: String,

        val algorithm:
            FileHashAlgorithm,

        val hash: String,

        val metadata:
            FileIntegrityMetadata?,

        val baselinePresent: Boolean,

        val comparison:
            FileIntegrityComparison,

        val status:
            FileIntegrityStatus,

        val checkedAtMillis: Long

    ) : FileIntegrityResult()

    /**
     * File could not be inspected.
     */
    data class Failed(

        val path: String,

        val reason: String

    ) : FileIntegrityResult()
}

/**
 * High-level file integrity state.
 */
enum class FileIntegrityStatus {

    /**
     * File matches the trusted baseline.
     */
    INTACT,

    /**
     * File contents differ from the trusted baseline.
     */
    MODIFIED,

    /**
     * File no longer exists.
     */
    DELETED,

    /**
     * Path is not a valid regular file.
     */
    INVALID,

    /**
     * File could not be cryptographically verified.
     */
    UNVERIFIABLE,

    /**
     * No trusted baseline exists.
     */
    NO_BASELINE
}

// =============================================================================
// Baseline
// =============================================================================

/**
 * Trusted file integrity baseline.
 *
 * The expected hash is the primary security value.
 */
data class FileIntegrityBaseline(

    val path: String,

    val algorithm:
        FileHashAlgorithm,

    val expectedHash: String,

    val expectedSize: Long,

    val expectedLastModified: Long,

    val createdAtMillis: Long
)

// =============================================================================
// Baseline Comparison
// =============================================================================

/**
 * Detailed comparison result.
 */
enum class FileIntegrityComparison {

    /**
     * File contents match the trusted hash.
     */
    Match,

    /**
     * File contents differ from the trusted hash.
     */
    HashMismatch,

    /**
     * File no longer exists.
     */
    FileDeleted,

    /**
     * Path is not a regular file.
     */
    InvalidFileType,

    /**
     * File metadata could not be retrieved.
     */
    MetadataUnavailable,

    /**
     * Cryptographic hash could not be calculated.
     */
    UnableToCalculateHash,

    /**
     * No trusted baseline was registered.
     */
    NoBaseline
}

// =============================================================================
// Hash Verification
// =============================================================================

/**
 * Direct expected-hash verification result.
 */
sealed class FileHashVerificationResult {

    /**
     * Actual hash equals expected hash.
     */
    data class Match(
        val actualHash: String
    ) : FileHashVerificationResult()

    /**
     * Actual hash differs from expected hash.
     */
    data class Mismatch(
        val expectedHash: String,
        val actualHash: String
    ) : FileHashVerificationResult()

    /**
     * Expected hash is malformed.
     */
    data class InvalidExpectedHash(
        val reason: String
    ) : FileHashVerificationResult()

    /**
     * File hash could not be calculated.
     */
    data object UnableToCalculateHash :
        FileHashVerificationResult
}

// =============================================================================
// File Metadata
// =============================================================================

/**
 * File metadata captured during integrity inspection.
 *
 * Metadata is supplementary evidence. The cryptographic hash remains the
 * primary content-integrity signal.
 */
data class FileIntegrityMetadata(

    val path: String,

    val name: String,

    val size: Long,

    val lastModified: Long,

    val isFile: Boolean,

    val isDirectory: Boolean,

    val canRead: Boolean,

    val canWrite: Boolean,

    val canExecute: Boolean
)

// =============================================================================
// Metadata Comparison
// =============================================================================

/**
 * Comparison of file metadata against a trusted baseline.
 */
enum class FileMetadataComparison {

    Unchanged,

    TimestampChanged,

    SizeChanged,

    SizeAndTimestampChanged,

    FileDeleted,

    Unavailable
}

// =============================================================================
// Directory Result
// =============================================================================

/**
 * Result of checking a directory tree.
 */
sealed class DirectoryIntegrityResult {

    /**
     * Directory was successfully scanned.
     */
    data class Checked(

        val directory: String,

        val filesScanned: Int,

        val filesChecked:
            List<FileIntegrityResult>,

        val modifiedFiles:
            List<FileIntegrityResult>,

        val unexpectedFiles:
            List<File>,

        val noBaselineFiles:
            List<FileIntegrityResult>

    ) : DirectoryIntegrityResult()

    /**
     * Directory could not be inspected.
     */
    data class Failed(
        val reason: String
    ) : DirectoryIntegrityResult()
}
