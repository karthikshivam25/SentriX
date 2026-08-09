package com.sentrix.security.integrity

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * SentriX Checksum Manager
 *
 * Centralized manager for generating and validating cryptographic checksums.
 *
 * Supported algorithms:
 *
 * - MD5
 * - SHA-1
 * - SHA-256
 * - SHA-512
 *
 * Security recommendation:
 *
 * MD5 and SHA-1 are retained only for compatibility and legacy detection.
 * They MUST NOT be used as the primary security checksum for SentriX
 * integrity decisions.
 *
 * Recommended algorithms:
 *
 *     SHA-256
 *     SHA-512
 *
 * Responsibilities:
 *
 * - Generate checksums for byte arrays.
 * - Generate checksums for strings.
 * - Generate checksums for files.
 * - Verify data against expected checksums.
 * - Normalize checksum representations.
 * - Validate checksum format.
 * - Maintain trusted checksum entries.
 * - Compare current checksums with trusted values.
 * - Perform batch checksum operations.
 * - Provide constant-time checksum comparison.
 *
 * Architecture:
 *
 *              ChecksumManager
 *                     │
 *       ┌─────────────┼─────────────┐
 *       ▼             ▼             ▼
 *     Bytes         String         File
 *       │             │             │
 *       └─────────────┼─────────────┘
 *                     ▼
 *              MessageDigest
 *                     │
 *                     ▼
 *                 Checksum
 *                     │
 *             ┌───────┴────────┐
 *             ▼                ▼
 *         Generate          Verify
 *             │                │
 *             └───────┬────────┘
 *                     ▼
 *              Integrity Layer
 */
class ChecksumManager {

    /**
     * In-memory trusted checksum registry.
     *
     * This registry is intended for runtime integrity workflows.
     *
     * For production persistence, SentriX should eventually place trusted
     * integrity metadata behind a secure storage mechanism.
     */
    private val trustedChecksums =
        ConcurrentHashMap<String, TrustedChecksum>()

    // =========================================================================
    // Default Algorithm
    // =========================================================================

    /**
     * SentriX's recommended default checksum algorithm.
     */
    val defaultAlgorithm:
        ChecksumAlgorithm =
            ChecksumAlgorithm.SHA_256

    // =========================================================================
    // Byte Array Checksums
    // =========================================================================

    /**
     * Generates a SHA-256 checksum for arbitrary bytes.
     */
    fun sha256(
        data: ByteArray
    ): String {

        return calculate(
            data =
                data,
            algorithm =
                ChecksumAlgorithm.SHA_256
        )
    }

    /**
     * Generates a SHA-512 checksum for arbitrary bytes.
     */
    fun sha512(
        data: ByteArray
    ): String {

        return calculate(
            data =
                data,
            algorithm =
                ChecksumAlgorithm.SHA_512
        )
    }

    /**
     * Generates a checksum using the specified algorithm.
     */
    fun calculate(
        data: ByteArray,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): String {

        val digest =
            MessageDigest.getInstance(
                algorithm.jcaName
            )

        return formatChecksum(
            digest.digest(
                data
            )
        )
    }

    // =========================================================================
    // String Checksums
    // =========================================================================

    /**
     * Generates a checksum for a UTF-8 string.
     */
    fun calculate(
        value: String,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): String {

        return calculate(
            data =
                value.toByteArray(
                    Charsets.UTF_8
                ),
            algorithm =
                algorithm
        )
    }

    /**
     * Generates SHA-256 checksum for a string.
     */
    fun sha256(
        value: String
    ): String {

        return calculate(
            value =
                value,
            algorithm =
                ChecksumAlgorithm.SHA_256
        )
    }

    /**
     * Generates SHA-512 checksum for a string.
     */
    fun sha512(
        value: String
    ): String {

        return calculate(
            value =
                value,
            algorithm =
                ChecksumAlgorithm.SHA_512
        )
    }

    // =========================================================================
    // File Checksums
    // =========================================================================

    /**
     * Calculates a checksum for a file.
     *
     * The file is processed as a stream to prevent large files from being
     * loaded completely into memory.
     */
    fun calculate(
        file: File,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
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
                            BUFFER_SIZE
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

            formatChecksum(
                digest.digest()
            )

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Calculates SHA-256 checksum for a file.
     */
    fun calculateSha256(
        file: File
    ): String? {

        return calculate(
            file =
                file,
            algorithm =
                ChecksumAlgorithm.SHA_256
        )
    }

    /**
     * Calculates SHA-512 checksum for a file.
     */
    fun calculateSha512(
        file: File
    ): String? {

        return calculate(
            file =
                file,
            algorithm =
                ChecksumAlgorithm.SHA_512
        )
    }

    // =========================================================================
    // Generic Verification
    // =========================================================================

    /**
     * Verifies byte data against an expected checksum.
     */
    fun verify(
        data: ByteArray,
        expectedChecksum: String,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): ChecksumVerificationResult {

        val normalizedExpected =
            normalize(
                expectedChecksum
            )

        if (
            !isValidChecksum(
                normalizedExpected,
                algorithm
            )
        ) {

            return ChecksumVerificationResult.InvalidExpectedChecksum
        }

        val actualChecksum =
            calculate(
                data =
                    data,
                algorithm =
                    algorithm
            )

        return if (
            secureEquals(
                actualChecksum,
                normalizedExpected
            )
        ) {

            ChecksumVerificationResult.Match(
                actualChecksum =
                    actualChecksum
            )

        } else {

            ChecksumVerificationResult.Mismatch(
                expectedChecksum =
                    normalizedExpected,
                actualChecksum =
                    actualChecksum
            )
        }
    }

    /**
     * Verifies a string against an expected checksum.
     */
    fun verify(
        value: String,
        expectedChecksum: String,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): ChecksumVerificationResult {

        return verify(
            data =
                value.toByteArray(
                    Charsets.UTF_8
                ),
            expectedChecksum =
                expectedChecksum,
            algorithm =
                algorithm
        )
    }

    /**
     * Verifies a file against an expected checksum.
     */
    fun verify(
        file: File,
        expectedChecksum: String,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): ChecksumVerificationResult {

        val normalizedExpected =
            normalize(
                expectedChecksum
            )

        if (
            !isValidChecksum(
                normalizedExpected,
                algorithm
            )
        ) {

            return ChecksumVerificationResult.InvalidExpectedChecksum
        }

        val actualChecksum =
            calculate(
                file =
                    file,
                algorithm =
                    algorithm
            )

            ?: return ChecksumVerificationResult
                .UnableToCalculate

        return if (
            secureEquals(
                actualChecksum,
                normalizedExpected
            )
        ) {

            ChecksumVerificationResult.Match(
                actualChecksum =
                    actualChecksum
            )

        } else {

            ChecksumVerificationResult.Mismatch(
                expectedChecksum =
                    normalizedExpected,
                actualChecksum =
                    actualChecksum
            )
        }
    }

    // =========================================================================
    // SHA-256 Verification Convenience Methods
    // =========================================================================

    /**
     * Verifies a file using SHA-256.
     */
    fun verifySha256(
        file: File,
        expectedChecksum: String
    ): Boolean {

        return verify(
            file =
                file,
            expectedChecksum =
                expectedChecksum,
            algorithm =
                ChecksumAlgorithm.SHA_256
        ) is ChecksumVerificationResult.Match
    }

    /**
     * Verifies a byte array using SHA-256.
     */
    fun verifySha256(
        data: ByteArray,
        expectedChecksum: String
    ): Boolean {

        return verify(
            data =
                data,
            expectedChecksum =
                expectedChecksum,
            algorithm =
                ChecksumAlgorithm.SHA_256
        ) is ChecksumVerificationResult.Match
    }

    /**
     * Verifies a string using SHA-256.
     */
    fun verifySha256(
        value: String,
        expectedChecksum: String
    ): Boolean {

        return verify(
            value =
                value,
            expectedChecksum =
                expectedChecksum,
            algorithm =
                ChecksumAlgorithm.SHA_256
        ) is ChecksumVerificationResult.Match
    }

    /**
     * Verifies a file using SHA-512.
     */
    fun verifySha512(
        file: File,
        expectedChecksum: String
    ): Boolean {

        return verify(
            file =
                file,
            expectedChecksum =
                expectedChecksum,
            algorithm =
                ChecksumAlgorithm.SHA_512
        ) is ChecksumVerificationResult.Match
    }

    // =========================================================================
    // Trusted Checksum Registry
    // =========================================================================

    /**
     * Registers a trusted checksum for an identifier.
     *
     * Example identifiers:
     *
     *     "sentrix_database"
     *     "security_config"
     *     "threat_rules"
     *     "app_config"
     */
    fun registerTrustedChecksum(
        identifier: String,
        checksum: String,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): Boolean {

        val normalizedIdentifier =
            identifier.trim()

        val normalizedChecksum =
            normalize(
                checksum
            )

        if (
            normalizedIdentifier.isBlank()
        ) {

            return false
        }

        if (
            !isValidChecksum(
                normalizedChecksum,
                algorithm
            )
        ) {

            return false
        }

        trustedChecksums[
            normalizedIdentifier
        ] =
            TrustedChecksum(

                identifier =
                    normalizedIdentifier,

                checksum =
                    normalizedChecksum,

                algorithm =
                    algorithm,

                registeredAtMillis =
                    System.currentTimeMillis()
            )

        return true
    }

    /**
     * Registers a trusted checksum for a file.
     */
    fun registerTrustedFile(
        identifier: String,
        file: File,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): Boolean {

        val checksum =
            calculate(
                file =
                    file,
                algorithm =
                    algorithm
            )
                ?: return false

        return registerTrustedChecksum(
            identifier =
                identifier,
            checksum =
                checksum,
            algorithm =
                algorithm
        )
    }

    /**
     * Retrieves a trusted checksum.
     */
    fun getTrustedChecksum(
        identifier: String
    ): TrustedChecksum? {

        return trustedChecksums[
            identifier.trim()
        ]
    }

    /**
     * Determines whether a trusted checksum exists.
     */
    fun hasTrustedChecksum(
        identifier: String
    ): Boolean {

        return trustedChecksums.containsKey(
            identifier.trim()
        )
    }

    /**
     * Removes a trusted checksum.
     */
    fun removeTrustedChecksum(
        identifier: String
    ): Boolean {

        return trustedChecksums.remove(
            identifier.trim()
        ) != null
    }

    /**
     * Clears all trusted checksums.
     */
    fun clearTrustedChecksums() {

        trustedChecksums.clear()
    }

    /**
     * Returns all registered trusted checksums.
     */
    fun getAllTrustedChecksums():
            List<TrustedChecksum> {

        return trustedChecksums.values
            .toList()
    }

    // =========================================================================
    // Trusted Checksum Verification
    // =========================================================================

    /**
     * Verifies arbitrary data against a registered trusted checksum.
     */
    fun verifyTrusted(
        identifier: String,
        data: ByteArray
    ): ChecksumVerificationResult {

        val trusted =
            getTrustedChecksum(
                identifier
            )
                ?: return ChecksumVerificationResult
                    .NoTrustedChecksum

        return verify(
            data =
                data,
            expectedChecksum =
                trusted.checksum,
            algorithm =
                trusted.algorithm
        )
    }

    /**
     * Verifies a string against a registered trusted checksum.
     */
    fun verifyTrusted(
        identifier: String,
        value: String
    ): ChecksumVerificationResult {

        val trusted =
            getTrustedChecksum(
                identifier
            )
                ?: return ChecksumVerificationResult
                    .NoTrustedChecksum

        return verify(
            value =
                value,
            expectedChecksum =
                trusted.checksum,
            algorithm =
                trusted.algorithm
        )
    }

    /**
     * Verifies a file against a registered trusted checksum.
     */
    fun verifyTrusted(
        identifier: String,
        file: File
    ): ChecksumVerificationResult {

        val trusted =
            getTrustedChecksum(
                identifier
            )
                ?: return ChecksumVerificationResult
                    .NoTrustedChecksum

        return verify(
            file =
                file,
            expectedChecksum =
                trusted.checksum,
            algorithm =
                trusted.algorithm
        )
    }

    // =========================================================================
    // Batch Operations
    // =========================================================================

    /**
     * Calculates checksums for multiple files.
     *
     * The result map contains only files for which checksum generation
     * succeeded.
     */
    fun calculateFiles(
        files: Collection<File>,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): Map<File, String> {

        val results =
            mutableMapOf<File, String>()

        files.forEach {
            file ->

            val checksum =
                calculate(
                    file =
                        file,
                    algorithm =
                        algorithm
                )

            if (
                checksum != null
            ) {

                results[
                    file
                ] =
                    checksum
            }
        }

        return results
    }

    /**
     * Verifies multiple files against expected checksums.
     */
    fun verifyFiles(
        expectedChecksums:
            Map<File, String>,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): Map<File, ChecksumVerificationResult> {

        return expectedChecksums.mapValues {
            (file, expectedChecksum) ->

            verify(
                file =
                    file,
                expectedChecksum =
                    expectedChecksum,
                algorithm =
                    algorithm
            )
        }
    }

    /**
     * Verifies a group of identifiers against the trusted registry.
     */
    fun verifyTrustedFiles(
        files:
            Map<String, File>
    ): Map<String, ChecksumVerificationResult> {

        return files.mapValues {
            (identifier, file) ->

            verifyTrusted(
                identifier =
                    identifier,
                file =
                    file
            )
        }
    }

    // =========================================================================
    // Directory Checksums
    // =========================================================================

    /**
     * Generates deterministic checksums for all regular files in a directory.
     *
     * The resulting directory checksum is based on:
     *
     *     relative path + file checksum
     *
     * This allows SentriX to detect changes to both file contents and the
     * directory's file set.
     */
    fun calculateDirectoryChecksum(
        directory: File,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): String? {

        if (
            !directory.exists() ||
            !directory.isDirectory
        ) {

            return null
        }

        return try {

            val root =
                directory
                    .canonicalFile

            val entries =
                root
                    .walkTopDown()
                    .filter {
                        it.isFile
                    }
                    .mapNotNull {
                        file ->

                        val checksum =
                            calculate(
                                file =
                                    file,
                                algorithm =
                                    algorithm
                            )
                                ?: return@mapNotNull null

                        val relativePath =
                            try {

                                root
                                    .toPath()
                                    .relativize(
                                        file
                                            .canonicalFile
                                            .toPath()
                                    )
                                    .toString()

                            } catch (
                                _: Exception
                            ) {

                                file.name
                            }

                        "$relativePath|$checksum"
                    }
                    .sorted()
                    .toList()

            if (
                entries.isEmpty()
            ) {

                return calculate(
                    data =
                        ByteArray(0),
                    algorithm =
                        algorithm
                )
            }

            calculate(
                value =
                    entries.joinToString(
                        separator = "\n"
                    ),
                algorithm =
                    algorithm
            )

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Checksum Validation
    // =========================================================================

    /**
     * Validates whether a checksum has the correct format for an algorithm.
     */
    fun isValidChecksum(
        checksum: String,
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): Boolean {

        val normalized =
            normalize(
                checksum
            )

        if (
            normalized.length !=
            algorithm.hexLength
        ) {

            return false
        }

        return normalized.all {
            it in '0'..'9' ||
                    it in 'A'..'F'
        }
    }

    /**
     * Normalizes a checksum.
     *
     * Supports:
     *
     * AA:BB:CC
     * AA-BB-CC
     * AABBCC
     */
    fun normalize(
        checksum: String
    ): String {

        return checksum
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
     * Returns the expected hexadecimal length for an algorithm.
     */
    fun expectedHexLength(
        algorithm: ChecksumAlgorithm =
            defaultAlgorithm
    ): Int {

        return algorithm.hexLength
    }

    // =========================================================================
    // Security Utilities
    // =========================================================================

    /**
     * Constant-time checksum comparison.
     *
     * This prevents straightforward timing differences from revealing
     * whether an expected checksum partially matches the calculated value.
     */
    fun secureEquals(
        first: String,
        second: String
    ): Boolean {

        val firstNormalized =
            normalize(
                first
            )

        val secondNormalized =
            normalize(
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

    /**
     * Determines whether two checksums are equal after normalization.
     */
    fun areEqual(
        first: String,
        second: String
    ): Boolean {

        return secureEquals(
            first,
            second
        )
    }

    // =========================================================================
    // Algorithm Security Classification
    // =========================================================================

    /**
     * Determines whether an algorithm is recommended for security-sensitive
     * SentriX integrity decisions.
     */
    fun isSecurityRecommended(
        algorithm: ChecksumAlgorithm
    ): Boolean {

        return when (
            algorithm
        ) {

            ChecksumAlgorithm.SHA_256,
            ChecksumAlgorithm.SHA_512 ->
                true

            ChecksumAlgorithm.MD5,
            ChecksumAlgorithm.SHA_1 ->
                false
        }
    }

    /**
     * Determines whether an algorithm should be considered legacy.
     */
    fun isLegacyAlgorithm(
        algorithm: ChecksumAlgorithm
    ): Boolean {

        return !isSecurityRecommended(
            algorithm
        )
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /**
     * Returns the number of registered trusted checksums.
     */
    fun getTrustedChecksumCount(): Int {

        return trustedChecksums.size
    }

    /**
     * Returns whether the manager currently has no trusted checksums.
     */
    fun isTrustedChecksumRegistryEmpty(): Boolean {

        return trustedChecksums.isEmpty()
    }

    companion object {

        /**
         * Streaming buffer size.
         *
         * 16 KB provides a reasonable balance between memory usage and
         * filesystem throughput on Android devices.
         */
        private const val BUFFER_SIZE =
            16 * 1024
    }
}

// =============================================================================
// Checksum Algorithms
// =============================================================================

/**
 * Cryptographic checksum algorithms supported by SentriX.
 */
enum class ChecksumAlgorithm(

    /**
     * Java Cryptography Architecture algorithm name.
     */
    val jcaName: String,

    /**
     * Number of hexadecimal characters produced by the algorithm.
     */
    val hexLength: Int,

    /**
     * Whether the algorithm is recommended for security-sensitive
     * integrity verification.
     */
    val securityRecommended: Boolean

) {

    /**
     * Legacy MD5 checksum.
     *
     * Not suitable as the primary security integrity mechanism.
     */
    MD5(
        jcaName =
            "MD5",
        hexLength =
            32,
        securityRecommended =
            false
    ),

    /**
     * Legacy SHA-1 checksum.
     *
     * Not suitable as the primary security integrity mechanism.
     */
    SHA_1(
        jcaName =
            "SHA-1",
        hexLength =
            40,
        securityRecommended =
            false
    ),

    /**
     * Recommended general-purpose integrity checksum.
     */
    SHA_256(
        jcaName =
            "SHA-256",
        hexLength =
            64,
        securityRecommended =
            true
    ),

    /**
     * Stronger checksum for situations where a longer digest is desirable.
     */
    SHA_512(
        jcaName =
            "SHA-512",
        hexLength =
            128,
        securityRecommended =
            true
    )
}

// =============================================================================
// Verification Result
// =============================================================================

/**
 * Result of checksum verification.
 */
sealed class ChecksumVerificationResult {

    /**
     * Calculated checksum matches the expected checksum.
     */
    data class Match(

        val actualChecksum: String

    ) : ChecksumVerificationResult()

    /**
     * Calculated checksum differs from the expected checksum.
     */
    data class Mismatch(

        val expectedChecksum: String,

        val actualChecksum: String

    ) : ChecksumVerificationResult()

    /**
     * The supplied expected checksum is malformed.
     */
    data object InvalidExpectedChecksum :
        ChecksumVerificationResult()

    /**
     * The checksum could not be generated.
     */
    data object UnableToCalculate :
        ChecksumVerificationResult()

    /**
     * No trusted checksum exists for the requested identifier.
     */
    data object NoTrustedChecksum :
        ChecksumVerificationResult()
}

// =============================================================================
// Trusted Checksum
// =============================================================================

/**
 * Trusted checksum registered in the SentriX checksum registry.
 *
 * IMPORTANT:
 *
 * The checksum value itself should originate from a trusted source.
 * Merely storing a checksum in the same potentially compromised storage
 * as the file being protected does not establish trust.
 */
data class TrustedChecksum(

    /**
     * Logical identifier for the protected resource.
     */
    val identifier: String,

    /**
     * Expected normalized checksum.
     */
    val checksum: String,

    /**
     * Algorithm used to generate the checksum.
     */
    val algorithm:
        ChecksumAlgorithm,

    /**
     * Registration timestamp.
     */
    val registeredAtMillis: Long
)
