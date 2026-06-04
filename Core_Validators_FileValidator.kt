package com.sentrix.core.validators

import com.sentrix.core.exceptions.InvalidFileException
import com.sentrix.core.exceptions.RequiredFieldException
import java.io.File

/**
 * FileValidator
 *
 * Responsibilities:
 * - File existence validation
 * - File size validation
 * - Extension validation
 * - Readability checks
 * - Security validation
 */
object FileValidator {

    private const val MAX_FILE_SIZE_MB = 1024L

    /**
     * Validate file.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidFileException::class
    )
    fun validate(
        file: File?
    ): Boolean {

        if (file == null) {
            throw RequiredFieldException(
                "File"
            )
        }

        if (!file.exists()) {
            throw InvalidFileException(
                "File does not exist."
            )
        }

        if (!file.isFile) {
            throw InvalidFileException(
                "Invalid file."
            )
        }

        if (
            file.length() <= 0
        ) {
            throw InvalidFileException(
                "File is empty."
            )
        }

        if (
            getSizeInMB(file) >
            MAX_FILE_SIZE_MB
        ) {
            throw InvalidFileException(
                "File exceeds maximum allowed size."
            )
        }

        if (!file.canRead()) {
            throw InvalidFileException(
                "File cannot be read."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        file: File?
    ): Boolean {

        return try {

            validate(file)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Validate extension.
     */
    fun validateExtension(
        file: File,
        allowedExtensions: Set<String>
    ): Boolean {

        val extension =
            file.extension.lowercase()

        return allowedExtensions.contains(
            extension
        )
    }

    /**
     * Get file size in MB.
     */
    fun getSizeInMB(
        file: File
    ): Long {

        return file.length() /
                (1024 * 1024)
    }

    /**
     * Get file size in KB.
     */
    fun getSizeInKB(
        file: File
    ): Long {

        return file.length() /
                1024
    }

    /**
     * Get file extension.
     */
    fun getExtension(
        file: File
    ): String {

        return file.extension
            .lowercase()
    }

    /**
     * Check hidden file.
     */
    fun isHidden(
        file: File
    ): Boolean {

        return file.isHidden
    }

    /**
     * Check executable file.
     */
    fun isExecutable(
        file: File
    ): Boolean {

        return file.canExecute()
    }

    /**
     * Generate file summary.
     */
    fun getSummary(
        file: File
    ): String {

        return buildString {

            appendLine(
                "Name: ${file.name}"
            )

            appendLine(
                "Extension: ${getExtension(file)}"
            )

            appendLine(
                "Size: ${getSizeInMB(file)} MB"
            )

            appendLine(
                "Readable: ${file.canRead()}"
            )

            appendLine(
                "Executable: ${file.canExecute()}"
            )
        }
    }
}
