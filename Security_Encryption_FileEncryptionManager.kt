package com.sentrix.security.encryption

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * SentriX File Encryption Manager
 *
 * Provides secure file-level encryption and decryption for the SentriX
 * security subsystem.
 *
 * Responsibilities:
 *
 * - Encrypt files using AES-256-GCM.
 * - Decrypt encrypted files.
 * - Stream large files without loading them completely into memory.
 * - Generate a unique IV for every file encryption operation.
 * - Store the IV with the encrypted file.
 * - Validate encrypted file headers.
 * - Perform atomic output-file replacement.
 * - Clean up temporary files after failed operations.
 *
 * Architecture:
 *
 *      Repository / UseCase
 *              │
 *              ▼
 *      FileEncryptionManager
 *              │
 *              ├──────────────► EncryptionKeyManager
 *              │                       │
 *              │                       ▼
 *              │                Android Keystore
 *              │
 *              ▼
 *          AES-256-GCM
 *
 * File format:
 *
 *      ┌───────────────────────────────────────────┐
 *      │ Version        1 byte                     │
 *      │ IV             12 bytes                   │
 *      │ Encrypted Data Variable length            │
 *      │ Authentication Tag 16 bytes               │
 *      └───────────────────────────────────────────┘
 *
 * The authentication tag is appended automatically by AES-GCM when the
 * CipherOutputStream is finalized.
 *
 * IMPORTANT:
 *
 * - The AES key is never stored in the file.
 * - The AES key is never written to disk by this class.
 * - The IV is not secret and is stored in the file header.
 * - A new IV is generated for every encryption operation.
 * - Decryption verifies the GCM authentication tag.
 *
 * Large-file handling:
 *
 * Files are processed using buffered streams, so the entire file does
 * not need to fit into application memory.
 */
object FileEncryptionManager {

    // -------------------------------------------------------------------------
    // Cryptographic Configuration
    // -------------------------------------------------------------------------

    /**
     * AES-GCM transformation.
     */
    private const val TRANSFORMATION =
        "AES/GCM/NoPadding"

    /**
     * AES-GCM IV size.
     *
     * 12 bytes is the recommended GCM nonce size.
     */
    private const val IV_SIZE = 12

    /**
     * Authentication tag size.
     */
    private const val GCM_TAG_LENGTH = 128

    /**
     * Current SentriX encrypted-file format version.
     */
    private const val FILE_FORMAT_VERSION: Byte = 1

    /**
     * Number of bytes used by the format version.
     */
    private const val VERSION_SIZE = 1

    /**
     * Buffer size used for file streaming.
     *
     * 64 KiB provides a reasonable balance between I/O performance
     * and memory usage.
     */
    private const val BUFFER_SIZE = 64 * 1024

    /**
     * Temporary-file suffix.
     *
     * Encryption/decryption is first written to a temporary file.
     * The destination is replaced only after successful completion.
     */
    private const val TEMP_FILE_SUFFIX =
        ".sentrix.tmp"

    /**
     * Secure random generator used for GCM IV generation.
     */
    private val secureRandom = SecureRandom()

    // -------------------------------------------------------------------------
    // Public Encryption API
    // -------------------------------------------------------------------------

    /**
     * Encrypts a source file into a destination file.
     *
     * Example:
     *
     *      FileEncryptionManager.encryptFile(
     *          sourceFile = originalFile,
     *          destinationFile = encryptedFile
     *      )
     *
     * The source file is not modified.
     *
     * @param sourceFile Original plaintext file.
     * @param destinationFile Destination encrypted file.
     *
     * @return FileEncryptionResult describing the operation.
     */
    suspend fun encryptFile(
        sourceFile: File,
        destinationFile: File
    ): FileEncryptionResult =
        withContext(Dispatchers.IO) {

            try {

                validateSourceFile(
                    sourceFile
                )

                validateDestination(
                    sourceFile,
                    destinationFile
                )

                val key =
                    EncryptionKeyManager
                        .ensureMasterKey()

                val temporaryFile =
                    createTemporaryFile(
                        destinationFile
                    )

                try {

                    encryptToTemporaryFile(
                        sourceFile = sourceFile,
                        temporaryFile = temporaryFile,
                        secretKey = key
                    )

                    commitTemporaryFile(
                        temporaryFile = temporaryFile,
                        destinationFile = destinationFile
                    )

                    FileEncryptionResult.Success(
                        file = destinationFile
                    )

                } catch (exception: Exception) {

                    safelyDelete(
                        temporaryFile
                    )

                    throw exception
                }

            } catch (exception: Exception) {

                FileEncryptionResult.Failure(
                    message = "File encryption failed.",
                    cause = exception
                )
            }
        }

    // -------------------------------------------------------------------------
    // Public Decryption API
    // -------------------------------------------------------------------------

    /**
     * Decrypts an encrypted SentriX file into a destination file.
     *
     * The encrypted source file is not modified.
     *
     * @param encryptedFile Encrypted SentriX file.
     * @param destinationFile Destination plaintext file.
     *
     * @return FileEncryptionResult describing the operation.
     */
    suspend fun decryptFile(
        encryptedFile: File,
        destinationFile: File
    ): FileEncryptionResult =
        withContext(Dispatchers.IO) {

            try {

                validateSourceFile(
                    encryptedFile
                )

                validateDestination(
                    encryptedFile,
                    destinationFile
                )

                val key =
                    EncryptionKeyManager
                        .getMasterKey()

                val temporaryFile =
                    createTemporaryFile(
                        destinationFile
                    )

                try {

                    decryptToTemporaryFile(
                        encryptedFile = encryptedFile,
                        temporaryFile = temporaryFile,
                        secretKey = key
                    )

                    commitTemporaryFile(
                        temporaryFile = temporaryFile,
                        destinationFile = destinationFile
                    )

                    FileEncryptionResult.Success(
                        file = destinationFile
                    )

                } catch (exception: Exception) {

                    safelyDelete(
                        temporaryFile
                    )

                    throw exception
                }

            } catch (exception: Exception) {

                FileEncryptionResult.Failure(
                    message = "File decryption failed.",
                    cause = exception
                )
            }
        }

    // -------------------------------------------------------------------------
    // Encryption Implementation
    // -------------------------------------------------------------------------

    /**
     * Performs streaming AES-GCM encryption.
     *
     * The resulting file format is:
     *
     *      [Version][IV][Ciphertext + Authentication Tag]
     *
     * CipherOutputStream automatically finalizes the GCM operation when
     * it is closed, causing the authentication tag to be written.
     */
    private fun encryptToTemporaryFile(
        sourceFile: File,
        temporaryFile: File,
        secretKey: SecretKey
    ) {

        val iv = generateIv()

        val cipher =
            Cipher.getInstance(
                TRANSFORMATION
            )

        val gcmParameterSpec =
            GCMParameterSpec(
                GCM_TAG_LENGTH,
                iv
            )

        cipher.init(
            Cipher.ENCRYPT_MODE,
            secretKey,
            gcmParameterSpec
        )

        BufferedInputStream(
            FileInputStream(
                sourceFile
            ),
            BUFFER_SIZE
        ).use { input ->

            BufferedOutputStream(
                FileOutputStream(
                    temporaryFile
                ),
                BUFFER_SIZE
            ).use { output ->

                /**
                 * Write the file format version.
                 */
                output.write(
                    FILE_FORMAT_VERSION.toInt()
                )

                /**
                 * Write the IV.
                 *
                 * The IV is intentionally stored alongside the
                 * ciphertext because it is not secret.
                 */
                output.write(
                    iv
                )

                /**
                 * CipherOutputStream performs AES-GCM encryption
                 * while the source file is streamed through it.
                 */
                CipherOutputStream(
                    output,
                    cipher
                ).use { cipherOutput ->

                    copyStream(
                        input = input,
                        output = cipherOutput
                    )
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Decryption Implementation
    // -------------------------------------------------------------------------

    /**
     * Performs streaming AES-GCM decryption.
     *
     * The version and IV are read from the encrypted file before
     * CipherInputStream is created.
     *
     * AES-GCM authentication is verified as the encrypted stream is
     * finalized.
     */
    private fun decryptToTemporaryFile(
        encryptedFile: File,
        temporaryFile: File,
        secretKey: SecretKey
    ) {

        FileInputStream(
            encryptedFile
        ).use { fileInput ->

            BufferedInputStream(
                fileInput,
                BUFFER_SIZE
            ).use { input ->

                /**
                 * Read and validate the SentriX file format version.
                 */
                val version =
                    input.read()

                require(
                    version >= 0
                ) {
                    "Encrypted file is empty."
                }

                validateFileVersion(
                    version.toByte()
                )

                /**
                 * Read the 12-byte GCM IV.
                 */
                val iv =
                    ByteArray(
                        IV_SIZE
                    )

                readFully(
                    input = input,
                    buffer = iv
                )

                val cipher =
                    Cipher.getInstance(
                        TRANSFORMATION
                    )

                val gcmParameterSpec =
                    GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        iv
                    )

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    secretKey,
                    gcmParameterSpec
                )

                BufferedOutputStream(
                    FileOutputStream(
                        temporaryFile
                    ),
                    BUFFER_SIZE
                ).use { output ->

                    CipherInputStream(
                        input,
                        cipher
                    ).use { cipherInput ->

                        copyStream(
                            input = cipherInput,
                            output = output
                        )
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Stream Operations
    // -------------------------------------------------------------------------

    /**
     * Copies data from one stream to another using a fixed-size buffer.
     *
     * The complete file is never loaded into memory.
     */
    private fun copyStream(
        input: java.io.InputStream,
        output: java.io.OutputStream
    ) {

        val buffer =
            ByteArray(
                BUFFER_SIZE
            )

        while (true) {

            val bytesRead =
                input.read(
                    buffer
                )

            if (bytesRead == -1) {
                break
            }

            if (bytesRead > 0) {

                output.write(
                    buffer,
                    0,
                    bytesRead
                )
            }
        }

        output.flush()
    }

    /**
     * Reads exactly the requested number of bytes.
     *
     * Prevents incomplete IV/header reads.
     */
    private fun readFully(
        input: java.io.InputStream,
        buffer: ByteArray
    ) {

        var offset = 0

        while (offset < buffer.size) {

            val bytesRead =
                input.read(
                    buffer,
                    offset,
                    buffer.size - offset
                )

            if (bytesRead == -1) {

                throw IOException(
                    "Unexpected end of encrypted file."
                )
            }

            offset += bytesRead
        }
    }

    // -------------------------------------------------------------------------
    // IV Generation
    // -------------------------------------------------------------------------

    /**
     * Generates a fresh cryptographically secure IV.
     *
     * The same IV must NEVER be reused with the same AES-GCM key.
     */
    private fun generateIv(): ByteArray {

        return ByteArray(
            IV_SIZE
        ).also {

            secureRandom.nextBytes(
                it
            )
        }
    }

    // -------------------------------------------------------------------------
    // File Validation
    // -------------------------------------------------------------------------

    /**
     * Validates that a source file exists and is readable.
     */
    private fun validateSourceFile(
        file: File
    ) {

        require(file.exists()) {
            "Source file does not exist: ${file.absolutePath}"
        }

        require(file.isFile) {
            "Source path is not a regular file."
        }

        require(file.canRead()) {
            "Source file cannot be read."
        }
    }

    /**
     * Validates the destination file.
     */
    private fun validateDestination(
        sourceFile: File,
        destinationFile: File
    ) {

        require(
            sourceFile.canonicalFile !=
                    destinationFile.canonicalFile
        ) {
            "Source and destination files must be different."
        }

        val parent =
            destinationFile.parentFile

        if (parent != null) {

            if (!parent.exists()) {

                require(
                    parent.mkdirs()
                ) {
                    "Unable to create destination directory."
                }
            }

            require(parent.isDirectory) {
                "Destination parent is not a directory."
            }

            require(parent.canWrite()) {
                "Destination directory is not writable."
            }
        }
    }

    /**
     * Validates the SentriX encrypted-file version.
     */
    private fun validateFileVersion(
        version: Byte
    ) {

        require(
            version == FILE_FORMAT_VERSION
        ) {
            "Unsupported SentriX encrypted-file version: $version"
        }
    }

    /**
     * Checks whether a file appears to contain a valid SentriX
     * encrypted-file header.
     *
     * This does not prove that the file is authentic.
     */
    suspend fun isEncryptedFile(
        file: File
    ): Boolean = withContext(Dispatchers.IO) {

        if (!file.exists() || !file.isFile) {
            return@withContext false
        }

        if (
            file.length() <
            VERSION_SIZE + IV_SIZE + 1
        ) {
            return@withContext false
        }

        return@withContext try {

            FileInputStream(
                file
            ).use { input ->

                val version =
                    input.read()

                if (
                    version !=
                    FILE_FORMAT_VERSION.toInt()
                ) {
                    return@withContext false
                }

                val iv =
                    ByteArray(
                        IV_SIZE
                    )

                readFully(
                    input = input,
                    buffer = iv
                )

                true
            }

        } catch (_: Exception) {

            false
        }
    }

    // -------------------------------------------------------------------------
    // Temporary File Handling
    // -------------------------------------------------------------------------

    /**
     * Creates a temporary file beside the destination.
     *
     * Keeping the temporary file in the same directory allows the final
     * move to be performed more safely because both files are on the
     * same filesystem in normal Android storage configurations.
     */
    private fun createTemporaryFile(
        destinationFile: File
    ): File {

        val parent =
            destinationFile.parentFile
                ?: throw IOException(
                    "Destination directory unavailable."
                )

        if (!parent.exists()) {

            require(
                parent.mkdirs()
            ) {
                "Unable to create destination directory."
            }
        }

        val temporaryFile =
            File(
                parent,
                destinationFile.name +
                        TEMP_FILE_SUFFIX
            )

        /**
         * Avoid accidentally reusing stale temporary data.
         */
        safelyDelete(
            temporaryFile
        )

        if (
            temporaryFile.exists()
        ) {
            throw IOException(
                "Unable to create temporary encryption file."
            )
        }

        return temporaryFile
    }

    /**
     * Commits a successfully encrypted/decrypted temporary file.
     *
     * Existing destination data is removed only after the temporary
     * operation has completed successfully.
     */
    private fun commitTemporaryFile(
        temporaryFile: File,
        destinationFile: File
    ) {

        require(
            temporaryFile.exists()
        ) {
            "Temporary file does not exist."
        }

        require(
            temporaryFile.isFile
        ) {
            "Temporary path is not a regular file."
        }

        /**
         * If a destination already exists, delete it only now.
         *
         * The sensitive operation itself has already completed.
         */
        if (destinationFile.exists()) {

            require(
                destinationFile.delete()
            ) {
                "Unable to replace destination file."
            }
        }

        /**
         * renameTo() is generally atomic when source and destination
         * reside on the same filesystem, but Android does not provide
         * a universal atomic-move guarantee through java.io.File.
         *
         * Therefore failure is explicitly checked.
         */
        require(
            temporaryFile.renameTo(
                destinationFile
            )
        ) {
            "Unable to commit temporary encrypted file."
        }
    }

    /**
     * Best-effort temporary-file cleanup.
     */
    private fun safelyDelete(
        file: File
    ) {

        try {

            if (file.exists()) {
                file.delete()
            }

        } catch (_: Exception) {
            // Intentionally ignored during cleanup.
        }
    }

    // -------------------------------------------------------------------------
    // File Information
    // -------------------------------------------------------------------------

    /**
     * Returns the current SentriX encrypted-file format version.
     */
    fun getFileFormatVersion(): Int {
        return FILE_FORMAT_VERSION.toInt()
    }

    /**
     * Returns the configured streaming buffer size.
     */
    fun getBufferSize(): Int {
        return BUFFER_SIZE
    }

    /**
     * Returns the encrypted-file header size.
     *
     * Header:
     *
     *      Version + IV
     */
    fun getHeaderSize(): Int {
        return VERSION_SIZE + IV_SIZE
    }

    /**
     * Returns whether the required encryption key is available.
     */
    fun isEncryptionAvailable(): Boolean {

        return try {

            EncryptionKeyManager
                .validateMasterKey() is
                    KeyValidationResult.Valid

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Initializes the encryption subsystem.
     */
    fun initialize() {

        EncryptionKeyManager.ensureMasterKey()
    }
}

/**
 * Result returned by file encryption/decryption operations.
 */
sealed class FileEncryptionResult {

    /**
     * Operation completed successfully.
     */
    data class Success(
        val file: File
    ) : FileEncryptionResult()

    /**
     * Operation failed.
     *
     * The underlying cause is retained for internal diagnostics.
     * It should not be displayed directly to end users.
     */
    data class Failure(
        val message: String,
        val cause: Throwable? = null
    ) : FileEncryptionResult()
}
