package com.sentrix.core.extensions

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.text.DecimalFormat
import java.util.Date

/**
 * File Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Existence & Validation
 * ------------------------------------------------------------------------- */

fun File.existsSafe(): Boolean {
    return exists() && canRead()
}

fun File.isReadable(): Boolean {
    return exists() && canRead()
}

fun File.isWritable(): Boolean {
    return exists() && canWrite()
}

fun File.isEmptyFile(): Boolean {
    return length() <= 0
}

fun File.isLargeFile(
    maxSizeBytes: Long = 100 * 1024 * 1024 // 100 MB
): Boolean {
    return length() > maxSizeBytes
}

/* -------------------------------------------------------------------------
 * File Information
 * ------------------------------------------------------------------------- */

fun File.fileName(): String = name

fun File.fileExtension(): String = extension

fun File.fileNameWithoutExtension(): String =
    nameWithoutExtension

fun File.fileSize(): Long = length()

fun File.lastModifiedDate(): Date =
    Date(lastModified())

fun File.creationTimestamp(): Long =
    lastModified()

/* -------------------------------------------------------------------------
 * File Size Formatting
 * ------------------------------------------------------------------------- */

fun File.readableSize(): String {

    if (!exists()) return "0 B"

    val units = arrayOf(
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    )

    var size = length().toDouble()
    var unitIndex = 0

    while (size >= 1024 && unitIndex < units.lastIndex) {
        size /= 1024
        unitIndex++
    }

    return "${DecimalFormat("#,##0.##").format(size)} ${units[unitIndex]}"
}

/* -------------------------------------------------------------------------
 * File Type Helpers
 * ------------------------------------------------------------------------- */

fun File.isApk(): Boolean =
    extension.equals("apk", true)

fun File.isPdf(): Boolean =
    extension.equals("pdf", true)

fun File.isImage(): Boolean =
    extension.lowercase() in setOf(
        "png",
        "jpg",
        "jpeg",
        "webp",
        "bmp",
        "gif"
    )

fun File.isVideo(): Boolean =
    extension.lowercase() in setOf(
        "mp4",
        "mkv",
        "avi",
        "mov",
        "webm"
    )

fun File.isArchive(): Boolean =
    extension.lowercase() in setOf(
        "zip",
        "rar",
        "7z",
        "tar",
        "gz"
    )

/* -------------------------------------------------------------------------
 * Hashing Helpers
 * ------------------------------------------------------------------------- */

fun File.sha256(): String {

    val digest = MessageDigest.getInstance("SHA-256")

    FileInputStream(this).use { input ->

        val buffer = ByteArray(8192)
        var bytesRead: Int

        while (input.read(buffer).also {
                bytesRead = it
            } > 0) {

            digest.update(
                buffer,
                0,
                bytesRead
            )
        }
    }

    return digest.digest()
        .joinToString("") {
            "%02x".format(it)
        }
}

fun File.md5(): String {

    val digest = MessageDigest.getInstance("MD5")

    FileInputStream(this).use { input ->

        val buffer = ByteArray(8192)
        var bytesRead: Int

        while (input.read(buffer).also {
                bytesRead = it
            } > 0) {

            digest.update(
                buffer,
                0,
                bytesRead
            )
        }
    }

    return digest.digest()
        .joinToString("") {
            "%02x".format(it)
        }
}

/* -------------------------------------------------------------------------
 * Read Helpers
 * ------------------------------------------------------------------------- */

fun File.readTextSafe(): String? {
    return runCatching {
        readText()
    }.getOrNull()
}

fun File.readBytesSafe(): ByteArray? {
    return runCatching {
        readBytes()
    }.getOrNull()
}

/* -------------------------------------------------------------------------
 * Write Helpers
 * ------------------------------------------------------------------------- */

fun File.writeTextSafe(
    content: String
): Boolean {
    return runCatching {
        writeText(content)
        true
    }.getOrElse { false }
}

fun File.appendTextSafe(
    content: String
): Boolean {
    return runCatching {
        appendText(content)
        true
    }.getOrElse { false }
}

/* -------------------------------------------------------------------------
 * Copy / Move Helpers
 * ------------------------------------------------------------------------- */

fun File.copyToSafe(
    destination: File,
    overwrite: Boolean = true
): Boolean {
    return runCatching {
        copyTo(destination, overwrite)
        true
    }.getOrElse { false }
}

fun File.moveToSafe(
    destination: File
): Boolean {
    return runCatching {
        copyTo(destination, true)
        delete()
        true
    }.getOrElse { false }
}

/* -------------------------------------------------------------------------
 * Delete Helpers
 * ------------------------------------------------------------------------- */

fun File.deleteSafe(): Boolean {
    return runCatching {
        deleteRecursively()
    }.getOrElse { false }
}

/* -------------------------------------------------------------------------
 * Directory Helpers
 * ------------------------------------------------------------------------- */

fun File.ensureDirectory(): Boolean {
    return if (exists()) {
        isDirectory
    } else {
        mkdirs()
    }
}

fun File.listFilesSafe(): List<File> {
    return listFiles()?.toList() ?: emptyList()
}

fun File.totalDirectorySize(): Long {

    if (!isDirectory) return length()

    return walkTopDown()
        .filter { it.isFile }
        .sumOf { it.length() }
}

/* -------------------------------------------------------------------------
 * Uri Helpers
 * ------------------------------------------------------------------------- */

fun Uri.fileName(
    context: Context
): String? {

    return runCatching {

        context.contentResolver
            .query(
                this,
                null,
                null,
                null,
                null
            )?.use { cursor ->

                val index =
                    cursor.getColumnIndex("_display_name")

                if (cursor.moveToFirst() && index >= 0) {
                    return cursor.getString(index)
                }
            }

        null

    }.getOrNull()
}

/* -------------------------------------------------------------------------
 * Malware & Security Helpers
 * ------------------------------------------------------------------------- */

fun File.isPotentiallyExecutable(): Boolean {

    return extension.lowercase() in setOf(
        "apk",
        "dex",
        "jar",
        "so",
        "exe",
        "bat",
        "sh"
    )
}

fun File.isHiddenFileSafe(): Boolean {
    return isHidden
}

fun File.securityRiskLevel(): String {

    return when {
        isPotentiallyExecutable() -> "High"
        isArchive() -> "Medium"
        else -> "Low"
    }
}

fun File.isSuspicious(
    maxSizeMb: Long = 500
): Boolean {

    return isPotentiallyExecutable() ||
            isHiddenFileSafe() ||
            length() > maxSizeMb * 1024 * 1024
}

/* -------------------------------------------------------------------------
 * Export Helpers
 * ------------------------------------------------------------------------- */

fun ByteArray.saveToFile(
    destination: File
): Boolean {

    return runCatching {

        FileOutputStream(destination).use {
            it.write(this)
            it.flush()
        }

        true

    }.getOrElse { false }
}

/* -------------------------------------------------------------------------
 * Scan Report Helpers
 * ------------------------------------------------------------------------- */

fun File.toScanSummary(): String {

    return buildString {
        appendLine("File Name: ${name}")
        appendLine("Extension: ${extension}")
        appendLine("Size: ${readableSize()}")
        appendLine("Risk Level: ${securityRiskLevel()}")
        appendLine("Last Modified: ${lastModifiedDate()}")
    }
}
