package com.sentrix.security.integrity

import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.concurrent.ConcurrentHashMap

/**
 * SentriX Hash Manager
 *
 * Centralized cryptographic hashing engine for the SentriX integrity layer.
 *
 * Responsibilities:
 *
 * - Generate cryptographic hashes for byte arrays.
 * - Generate cryptographic hashes for strings.
 * - Generate cryptographic hashes for files.
 * - Generate cryptographic hashes for InputStreams.
 * - Support SHA-256 and SHA-512.
 * - Support legacy MD5 and SHA-1 when explicitly requested.
 * - Normalize hash representations.
 * - Validate hash formats.
 * - Compare hashes securely.
 * - Generate deterministic composite hashes.
 * - Provide batch file hashing.
 * - Maintain reusable hashing operations without loading large files
 *   completely into memory.
 *
 * Security guidance:
 *
 * SHA-256 is the default algorithm for SentriX security decisions.
 *
 * MD5 and SHA-1 are supported only for compatibility and identification
 * purposes. They should not be used as the primary integrity mechanism.
 *
 * Architecture:
 *
 *                    HashManager
 *                        │
 *        ┌───────────────┼────────────────┐
 *        ▼               ▼                ▼
 *      Bytes           String            File
 *        │               │                │
 *        └───────────────┼────────────────┘
 *                        ▼
 *                 MessageDigest
 *                        │
 *              ┌─────────┴─────────┐
 *              ▼                   ▼
 *          SHA-256              SHA-512
 *              │                   │
 *              └─────────┬─────────┘
 *                        ▼
 *                 HashValue
 *
 * This component is intentionally lower-level than:
 *
 * - FileIntegrityChecker
 * - DatabaseIntegrityChecker
 * - AppIntegrityChecker
 * - ChecksumManager
 */
class HashManager {

    /**
     * Default algorithm recommended for SentriX integrity operations.
     */
    val defaultAlgorithm:
        HashAlgorithm =
            HashAlgorithm.SHA_256

    /**
     * Cache for algorithm availability.
     *
     * Java's MessageDigest providers are queried only once per algorithm.
     */
    private val algorithmAvailability =
        ConcurrentHashMap<
                HashAlgorithm,
                Boolean
                >()

    // =========================================================================
    // Byte Array Hashing
    // =========================================================================

    /**
     * Calculates a hash for arbitrary binary data.
     */
    fun hash(
        data: ByteArray,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): String {

        val digest =
            createDigest(
                algorithm
            )

        return formatHash(
            digest.digest(
                data
            )
        )
    }

    /**
     * Calculates SHA-256 for arbitrary binary data.
     */
    fun sha256(
        data: ByteArray
    ): String {

        return hash(
            data =
                data,
            algorithm =
                HashAlgorithm.SHA_256
        )
    }

    /**
     * Calculates SHA-512 for arbitrary binary data.
     */
    fun sha512(
        data: ByteArray
    ): String {

        return hash(
            data =
                data,
            algorithm =
                HashAlgorithm.SHA_512
        )
    }

    /**
     * Calculates MD5 for legacy compatibility.
     *
     * This should not be used as the primary security integrity hash.
     */
    fun md5(
        data: ByteArray
    ): String {

        return hash(
            data =
                data,
            algorithm =
                HashAlgorithm.MD5
        )
    }

    /**
     * Calculates SHA-1 for legacy compatibility.
     *
     * This should not be used as the primary security integrity hash.
     */
    fun sha1(
        data: ByteArray
    ): String {

        return hash(
            data =
                data,
            algorithm =
                HashAlgorithm.SHA_1
        )
    }

    // =========================================================================
    // String Hashing
    // =========================================================================

    /**
     * Calculates a hash from a UTF-8 string.
     */
    fun hash(
        value: String,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): String {

        return hash(
            data =
                value.toByteArray(
                    Charsets.UTF_8
                ),
            algorithm =
                algorithm
        )
    }

    /**
     * Calculates SHA-256 for a UTF-8 string.
     */
    fun sha256(
        value: String
    ): String {

        return hash(
            value =
                value,
            algorithm =
                HashAlgorithm.SHA_256
        )
    }

    /**
     * Calculates SHA-512 for a UTF-8 string.
     */
    fun sha512(
        value: String
    ): String {

        return hash(
            value =
                value,
            algorithm =
                HashAlgorithm.SHA_512
        )
    }

    /**
     * Calculates MD5 for a string.
     */
    fun md5(
        value: String
    ): String {

        return hash(
            value =
                value,
            algorithm =
                HashAlgorithm.MD5
        )
    }

    /**
     * Calculates SHA-1 for a string.
     */
    fun sha1(
        value: String
    ): String {

        return hash(
            value =
                value,
            algorithm =
                HashAlgorithm.SHA_1
        )
    }

    // =========================================================================
    // File Hashing
    // =========================================================================

    /**
     * Calculates a hash for a file.
     *
     * The file is streamed in chunks so large files do not consume excessive
     * memory.
     */
    fun hash(
        file: File,
        algorithm: HashAlgorithm =
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

            FileInputStream(
                file
            )
                .buffered()
                .use { input ->

                    hash(
                        inputStream =
                            input,
                        algorithm =
                            algorithm
                    )
                }

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Calculates SHA-256 for a file.
     */
    fun sha256(
        file: File
    ): String? {

        return hash(
            file =
                file,
            algorithm =
                HashAlgorithm.SHA_256
        )
    }

    /**
     * Calculates SHA-512 for a file.
     */
    fun sha512(
        file: File
    ): String? {

        return hash(
            file =
                file,
            algorithm =
                HashAlgorithm.SHA_512
        )
    }

    /**
     * Calculates MD5 for a file.
     *
     * Only intended for legacy compatibility.
     */
    fun md5(
        file: File
    ): String? {

        return hash(
            file =
                file,
            algorithm =
                HashAlgorithm.MD5
        )
    }

    /**
     * Calculates SHA-1 for a file.
     *
     * Only intended for legacy compatibility.
     */
    fun sha1(
        file: File
    ): String? {

        return hash(
            file =
                file,
            algorithm =
                HashAlgorithm.SHA_1
        )
    }

    // =========================================================================
    // InputStream Hashing
    // =========================================================================

    /**
     * Calculates a hash from an InputStream.
     *
     * The caller retains ownership of the InputStream.
     *
     * This method does NOT close the supplied stream.
     */
    fun hash(
        inputStream: InputStream,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): String {

        val digest =
            createDigest(
                algorithm
            )

        val buffer =
            ByteArray(
                BUFFER_SIZE
            )

        while (
            true
        ) {

            val bytesRead =
                inputStream.read(
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

        return formatHash(
            digest.digest()
        )
    }

    /**
     * Safely hashes an InputStream and closes it afterward.
     */
    fun hashAndClose(
        inputStream: InputStream,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): String {

        return inputStream.use {
            hash(
                inputStream =
                    it,
                algorithm =
                    algorithm
            )
        }
    }

    // =========================================================================
    // File Hash Details
    // =========================================================================

    /**
     * Returns detailed hash information for a file.
     */
    fun hashFileDetailed(
        file: File,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): FileHashResult {

        if (
            !file.exists()
        ) {

            return FileHashResult.Failed(
                path =
                    file.absolutePath,
                reason =
                    "File does not exist."
            )
        }

        if (
            !file.isFile
        ) {

            return FileHashResult.Failed(
                path =
                    file.absolutePath,
                reason =
                    "Path does not reference a regular file."
            )
        }

        if (
            !file.canRead()
        ) {

            return FileHashResult.Failed(
                path =
                    file.absolutePath,
                reason =
                    "File is not readable."
            )
        }

        val startTime =
            System.nanoTime()

        return try {

            val hash =
                hash(
                    file =
                        file,
                    algorithm =
                        algorithm
                )
                    ?: return FileHashResult.Failed(
                        path =
                            file.absolutePath,
                        reason =
                            "Hash calculation failed."
                    )

            val elapsedMillis =
                (
                    System.nanoTime() -
                            startTime
                    ) /
                        1_000_000L

            FileHashResult.Success(

                path =
                    file.absolutePath,

                fileSize =
                    file.length(),

                algorithm =
                    algorithm,

                hash =
                    hash,

                calculatedAtMillis =
                    System.currentTimeMillis(),

                calculationDurationMillis =
                    elapsedMillis
            )

        } catch (
            exception: Exception
        ) {

            FileHashResult.Failed(

                path =
                    file.absolutePath,

                reason =
                    exception.message
                        ?: "Hash calculation failed."
            )
        }
    }

    // =========================================================================
    // Hash Comparison
    // =========================================================================

    /**
     * Compares two hashes using constant-time comparison.
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
     * Standard normalized hash comparison.
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

    /**
     * Verifies data against an expected hash.
     */
    fun verify(
        data: ByteArray,
        expectedHash: String,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): HashVerificationResult {

        val normalizedExpected =
            normalize(
                expectedHash
            )

        if (
            !isValidHash(
                normalizedExpected,
                algorithm
            )
        ) {

            return HashVerificationResult
                .InvalidExpectedHash
        }

        val actualHash =
            hash(
                data =
                    data,
                algorithm =
                    algorithm
            )

        return createVerificationResult(
            expectedHash =
                normalizedExpected,
            actualHash =
                actualHash
        )
    }

    /**
     * Verifies a string against an expected hash.
     */
    fun verify(
        value: String,
        expectedHash: String,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): HashVerificationResult {

        return verify(
            data =
                value.toByteArray(
                    Charsets.UTF_8
                ),
            expectedHash =
                expectedHash,
            algorithm =
                algorithm
        )
    }

    /**
     * Verifies a file against an expected hash.
     */
    fun verify(
        file: File,
        expectedHash: String,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): HashVerificationResult {

        val normalizedExpected =
            normalize(
                expectedHash
            )

        if (
            !isValidHash(
                normalizedExpected,
                algorithm
            )
        ) {

            return HashVerificationResult
                .InvalidExpectedHash
        }

        val actualHash =
            hash(
                file =
                    file,
                algorithm =
                    algorithm
            )
                ?: return HashVerificationResult
                    .UnableToCalculate

        return createVerificationResult(
            expectedHash =
                normalizedExpected,
            actualHash =
                actualHash
        )
    }

    /**
     * Creates a hash-verification result.
     */
    private fun createVerificationResult(
        expectedHash: String,
        actualHash: String
    ): HashVerificationResult {

        return if (
            secureEquals(
                expectedHash,
                actualHash
            )
        ) {

            HashVerificationResult.Match(
                actualHash =
                    actualHash
            )

        } else {

            HashVerificationResult.Mismatch(

                expectedHash =
                    expectedHash,

                actualHash =
                    actualHash
            )
        }
    }

    // =========================================================================
    // Hash Validation
    // =========================================================================

    /**
     * Validates a hexadecimal hash against its expected algorithm length.
     */
    fun isValidHash(
        hash: String,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): Boolean {

        val normalized =
            normalize(
                hash
            )

        if (
            normalized.length !=
            algorithm.hexLength
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
     * Normalizes a hash representation.
     *
     * Supports:
     *
     * AA:BB:CC
     * AA-BB-CC
     * AABBCC
     * aa:bb:cc
     */
    fun normalize(
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
     * Formats raw digest bytes into uppercase hexadecimal notation.
     *
     * Example:
     *
     * AA:BB:CC:DD
     */
    fun formatHash(
        bytes: ByteArray
    ): String {

        return bytes.joinToString(":") {
            "%02X".format(
                it.toInt() and 0xFF
            )
        }
    }

    /**
     * Returns the hexadecimal hash without separators.
     */
    fun formatCompactHash(
        bytes: ByteArray
    ): String {

        return bytes.joinToString("") {
            "%02X".format(
                it.toInt() and 0xFF
            )
        }
    }

    // =========================================================================
    // Composite Hashing
    // =========================================================================

    /**
     * Creates a deterministic hash from multiple hashable values.
     *
     * The values are sorted before hashing so the result does not depend
     * on their original order.
     */
    fun compositeHash(
        values: Collection<String>,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): String {

        val normalizedValues =
            values
                .map {
                    it.trim()
                }
                .sorted()

        val material =
            normalizedValues
                .joinToString(
                    separator = "|"
                )

        return hash(
            value =
                material,
            algorithm =
                algorithm
        )
    }

    /**
     * Creates a deterministic hash from file path + file hash pairs.
     *
     * Useful when constructing a directory integrity fingerprint.
     */
    fun compositeFileHash(
        files: Collection<File>,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): String? {

        if (
            files.isEmpty()
        ) {

            return hash(
                data =
                    ByteArray(0),
                algorithm =
                    algorithm
            )
        }

        val entries =
            files
                .filter {
                    it.isFile
                }
                .mapNotNull {
                    file ->

                    val fileHash =
                        hash(
                            file =
                                file,
                            algorithm =
                                algorithm
                        )
                            ?: return@mapNotNull null

                    "${file.absolutePath}|$fileHash"
                }
                .sorted()

        if (
            entries.size !=
            files.count {
                it.isFile
            }
        ) {

            return null
        }

        return compositeHash(
            values =
                entries,
            algorithm =
                algorithm
        )
    }

    // =========================================================================
    // Batch Hashing
    // =========================================================================

    /**
     * Calculates hashes for multiple files.
     */
    fun hashFiles(
        files: Collection<File>,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): Map<File, String> {

        val result =
            LinkedHashMap<File, String>()

        files.forEach {
            file ->

            val hash =
                hash(
                    file =
                        file,
                    algorithm =
                        algorithm
                )

            if (
                hash != null
            ) {

                result[
                    file
                ] =
                    hash
            }
        }

        return result
    }

    /**
     * Calculates hashes for multiple strings.
     */
    fun hashStrings(
        values: Collection<String>,
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): Map<String, String> {

        return values.associateWith {
            value ->

            hash(
                value =
                    value,
                algorithm =
                    algorithm
            )
        }
    }

    // =========================================================================
    // Directory Hashing
    // =========================================================================

    /**
     * Calculates a deterministic hash representing the contents of a
     * directory tree.
     *
     * Both relative paths and file hashes are included.
     */
    fun hashDirectory(
        directory: File,
        algorithm: HashAlgorithm =
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
                directory.canonicalFile

            val entries =
                root
                    .walkTopDown()
                    .filter {
                        it.isFile
                    }
                    .mapNotNull {
                        file ->

                        val fileHash =
                            hash(
                                file =
                                    file,
                                algorithm =
                                    algorithm
                            )
                                ?: return@mapNotNull null

                        val relativePath =
                            root
                                .toPath()
                                .relativize(
                                    file
                                        .canonicalFile
                                        .toPath()
                                )
                                .toString()

                        "$relativePath|$fileHash"
                    }
                    .sorted()
                    .toList()

            if (
                entries.isEmpty()
            ) {

                return hash(
                    data =
                        ByteArray(0),
                    algorithm =
                        algorithm
                )
            }

            hash(
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
    // Algorithm Management
    // =========================================================================

    /**
     * Determines whether the requested hashing algorithm is available.
     */
    fun isAlgorithmAvailable(
        algorithm: HashAlgorithm
    ): Boolean {

        return algorithmAvailability.getOrPut(
            algorithm
        ) {

            try {

                MessageDigest.getInstance(
                    algorithm.jcaName
                )

                true

            } catch (
                _: NoSuchAlgorithmException
            ) {

                false
            }
        }
    }

    /**
     * Returns all algorithms currently available from the installed
     * cryptographic providers.
     */
    fun getAvailableAlgorithms():
            List<HashAlgorithm> {

        return HashAlgorithm
            .entries
            .filter {
                isAlgorithmAvailable(
                    it
                )
            }
    }

    /**
     * Returns whether an algorithm is suitable for SentriX security
     * integrity decisions.
     */
    fun isSecurityRecommended(
        algorithm: HashAlgorithm
    ): Boolean {

        return algorithm.securityRecommended
    }

    /**
     * Returns whether an algorithm is considered legacy.
     */
    fun isLegacyAlgorithm(
        algorithm: HashAlgorithm
    ): Boolean {

        return !algorithm.securityRecommended
    }

    // =========================================================================
    // Digest Creation
    // =========================================================================

    /**
     * Creates a new MessageDigest instance.
     */
    private fun createDigest(
        algorithm: HashAlgorithm
    ): MessageDigest {

        return try {

            MessageDigest.getInstance(
                algorithm.jcaName
            )

        } catch (
            exception: NoSuchAlgorithmException
        ) {

            throw IllegalStateException(
                "Hash algorithm ${algorithm.jcaName} " +
                        "is not available on this Android runtime.",
                exception
            )
        }
    }

    // =========================================================================
    // Security Metadata
    // =========================================================================

    /**
     * Returns the digest length in bytes.
     */
    fun digestLengthBytes(
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): Int {

        return algorithm.digestLengthBytes
    }

    /**
     * Returns the digest length in hexadecimal characters.
     */
    fun digestLengthHex(
        algorithm: HashAlgorithm =
            defaultAlgorithm
    ): Int {

        return algorithm.hexLength
    }

    /**
     * Returns a human-readable algorithm description.
     */
    fun getAlgorithmDescription(
        algorithm: HashAlgorithm
    ): String {

        return when (
            algorithm
        ) {

            HashAlgorithm.MD5 ->
                "MD5 - legacy, not recommended for security integrity."

            HashAlgorithm.SHA_1 ->
                "SHA-1 - legacy, not recommended for security integrity."

            HashAlgorithm.SHA_256 ->
                "SHA-256 - recommended SentriX integrity algorithm."

            HashAlgorithm.SHA_512 ->
                "SHA-512 - recommended for higher digest strength."
        }
    }

    companion object {

        /**
         * Streaming read buffer.
         */
        private const val BUFFER_SIZE =
            16 * 1024
    }
}

// =============================================================================
// Hash Algorithms
// =============================================================================

/**
 * Hash algorithms supported by SentriX.
 */
enum class HashAlgorithm(

    /**
     * Java Cryptography Architecture name.
     */
    val jcaName: String,

    /**
     * Digest size in bytes.
     */
    val digestLengthBytes: Int,

    /**
     * Digest size represented as hexadecimal characters.
     */
    val hexLength: Int,

    /**
     * Whether the algorithm is appropriate for modern security-sensitive
     * integrity decisions.
     */
    val securityRecommended: Boolean

) {

    /**
     * MD5.
     *
     * Supported only for legacy compatibility and identification.
     */
    MD5(
        jcaName =
            "MD5",
        digestLengthBytes =
            16,
        hexLength =
            32,
        securityRecommended =
            false
    ),

    /**
     * SHA-1.
     *
     * Supported only for legacy compatibility and identification.
     */
    SHA_1(
        jcaName =
            "SHA-1",
        digestLengthBytes =
            20,
        hexLength =
            40,
        securityRecommended =
            false
    ),

    /**
     * SHA-256.
     *
     * Primary SentriX integrity hashing algorithm.
     */
    SHA_256(
        jcaName =
            "SHA-256",
        digestLengthBytes =
            32,
        hexLength =
            64,
        securityRecommended =
            true
    ),

    /**
     * SHA-512.
     *
     * Stronger digest option for situations requiring a larger hash.
     */
    SHA_512(
        jcaName =
            "SHA-512",
        digestLengthBytes =
            64,
        hexLength =
            128,
        securityRecommended =
            true
    )
}

// =============================================================================
// Hash Result
// =============================================================================

/**
 * Detailed result of hashing a file.
 */
sealed class FileHashResult {

    /**
     * File hash successfully calculated.
     */
    data class Success(

        val path: String,

        val fileSize: Long,

        val algorithm:
            HashAlgorithm,

        val hash: String,

        val calculatedAtMillis: Long,

        val calculationDurationMillis: Long

    ) : FileHashResult()

    /**
     * File hash calculation failed.
     */
    data class Failed(

        val path: String,

        val reason: String

    ) : FileHashResult()
}

// =============================================================================
// Verification Result
// =============================================================================

/**
 * Result of comparing calculated and expected hashes.
 */
sealed class HashVerificationResult {

    /**
     * Calculated hash matches expected hash.
     */
    data class Match(

        val actualHash: String

    ) : HashVerificationResult()

    /**
     * Calculated hash differs from expected hash.
     */
    data class Mismatch(

        val expectedHash: String,

        val actualHash: String

    ) : HashVerificationResult()

    /**
     * Expected hash has an invalid format.
     */
    data object InvalidExpectedHash :
        HashVerificationResult()

    /**
     * Hash calculation failed.
     */
    data object UnableToCalculate :
        HashVerificationResult()
}
