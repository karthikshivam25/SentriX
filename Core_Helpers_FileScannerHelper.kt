package com.sentrix.core.helpers

import android.content.Context
import android.os.Environment
import com.sentrix.core.enums.SecurityStatus
import java.io.File
import java.security.MessageDigest

object FileScannerHelper {

    /**
     * Suspicious file extensions
     */
    private val suspiciousExtensions = listOf(
        "apk",
        "xapk",
        "exe",
        "bat",
        "cmd",
        "sh",
        "jar",
        "dex",
        "bin"
    )

    /**
     * Suspicious file keywords
     */
    private val suspiciousKeywords = listOf(
        "hack",
        "crack",
        "keygen",
        "inject",
        "payload",
        "exploit",
        "trojan",
        "spy",
        "rat",
        "stealer"
    )

    /**
     * Scan device storage
     */
    fun scanStorage(
        context: Context
    ): List<FileScanResult> {

        val results = mutableListOf<FileScanResult>()

        val storageDirectories = listOfNotNull(
            context.getExternalFilesDir(null),
            Environment.getExternalStorageDirectory()
        )

        storageDirectories.forEach { directory ->

            if (directory.exists()) {

                scanDirectory(
                    directory = directory,
                    results = results
                )
            }
        }

        return results
    }

    /**
     * Scan directory recursively
     */
    private fun scanDirectory(
        directory: File,
        results: MutableList<FileScanResult>
    ) {

        try {

            val files = directory.listFiles() ?: return

            files.forEach { file ->

                if (file.isDirectory) {

                    scanDirectory(file, results)

                } else {

                    val result = analyzeFile(file)

                    if (result.securityStatus != SecurityStatus.SECURE) {
                        results.add(result)
                    }
                }
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * Analyze individual file
     */
    fun analyzeFile(
        file: File
    ): FileScanResult {

        val threatScore = calculateThreatScore(file)

        val securityStatus = when {

            threatScore >= 80 -> SecurityStatus.CRITICAL

            threatScore >= 60 -> SecurityStatus.DANGEROUS

            threatScore >= 40 -> SecurityStatus.WARNING

            threatScore >= 20 -> SecurityStatus.SAFE

            else -> SecurityStatus.SECURE
        }

        return FileScanResult(
            fileName = file.name,
            filePath = file.absolutePath,
            fileSize = file.length(),
            fileExtension = file.extension,
            sha256Hash = calculateFileHash(file),
            threatScore = threatScore,
            securityStatus = securityStatus,
            isSuspicious = threatScore >= 40
        )
    }

    /**
     * Calculate threat score
     */
    private fun calculateThreatScore(
        file: File
    ): Int {

        var score = 0

        val extension = file.extension.lowercase()
        val fileName = file.name.lowercase()

        if (suspiciousExtensions.contains(extension)) {
            score += 30
        }

        if (
            suspiciousKeywords.any {
                fileName.contains(it)
            }
        ) {
            score += 40
        }

        if (file.length() > 100 * 1024 * 1024) {
            score += 10
        }

        if (file.canExecute()) {
            score += 20
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Calculate SHA-256 file hash
     */
    fun calculateFileHash(
        file: File
    ): String {

        return try {

            val digest = MessageDigest
                .getInstance("SHA-256")

            val bytes = file.readBytes()

            val hashBytes = digest.digest(bytes)

            hashBytes.joinToString("") {
                "%02x".format(it)
            }

        } catch (e: Exception) {
            "Hash Error"
        }
    }

    /**
     * Get suspicious files only
     */
    fun getSuspiciousFiles(
        context: Context
    ): List<FileScanResult> {

        return scanStorage(context).filter {
            it.isSuspicious
        }
    }

    /**
     * Get scan summary
     */
    fun getScanSummary(
        context: Context
    ): FileScanSummary {

        val scanResults = scanStorage(context)

        val criticalFiles = scanResults.count {
            it.securityStatus == SecurityStatus.CRITICAL
        }

        val dangerousFiles = scanResults.count {
            it.securityStatus == SecurityStatus.DANGEROUS
        }

        val warningFiles = scanResults.count {
            it.securityStatus == SecurityStatus.WARNING
        }

        return FileScanSummary(
            totalScannedFiles = scanResults.size,
            criticalFiles = criticalFiles,
            dangerousFiles = dangerousFiles,
            warningFiles = warningFiles,
            suspiciousFiles = scanResults.count {
                it.isSuspicious
            }
        )
    }

    /**
     * File scan result model
     */
    data class FileScanResult(
        val fileName: String,
        val filePath: String,
        val fileSize: Long,
        val fileExtension: String,
        val sha256Hash: String,
        val threatScore: Int,
        val securityStatus: SecurityStatus,
        val isSuspicious: Boolean
    )

    /**
     * File scan summary model
     */
    data class FileScanSummary(
        val totalScannedFiles: Int,
        val criticalFiles: Int,
        val dangerousFiles: Int,
        val warningFiles: Int,
        val suspiciousFiles: Int
    )
}
