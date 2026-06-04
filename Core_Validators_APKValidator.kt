package com.sentrix.core.validators

import android.content.pm.PackageManager
import com.sentrix.core.exceptions.InvalidAPKException
import com.sentrix.core.exceptions.RequiredFieldException
import java.io.File

/**
 * APKValidator
 *
 * Responsibilities:
 * - APK file validation
 * - APK integrity checks
 * - Package verification
 * - Size validation
 * - Installation safety checks
 */
object APKValidator {

    private const val MAX_APK_SIZE_MB = 500L

    /**
     * Validate APK file.
     */
    @Throws(
        RequiredFieldException::class,
        InvalidAPKException::class
    )
    fun validate(
        apkFile: File?
    ): Boolean {

        if (apkFile == null) {
            throw RequiredFieldException(
                "APK File"
            )
        }

        if (!apkFile.exists()) {
            throw InvalidAPKException(
                "APK file does not exist."
            )
        }

        if (!apkFile.isFile) {
            throw InvalidAPKException(
                "Invalid APK file."
            )
        }

        if (
            !apkFile.name.lowercase()
                .endsWith(".apk")
        ) {
            throw InvalidAPKException(
                "File is not an APK."
            )
        }

        if (
            apkFile.length() <= 0
        ) {
            throw InvalidAPKException(
                "APK file is empty."
            )
        }

        if (
            getSizeInMB(apkFile) >
            MAX_APK_SIZE_MB
        ) {
            throw InvalidAPKException(
                "APK exceeds maximum allowed size."
            )
        }

        return true
    }

    /**
     * Safe validation.
     */
    fun isValid(
        apkFile: File?
    ): Boolean {

        return try {

            validate(apkFile)

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Get APK size in MB.
     */
    fun getSizeInMB(
        apkFile: File
    ): Long {

        return apkFile.length() /
                (1024 * 1024)
    }

    /**
     * Extract package name.
     */
    fun getPackageName(
        packageManager: PackageManager,
        apkFile: File
    ): String? {

        return try {

            packageManager
                .getPackageArchiveInfo(
                    apkFile.absolutePath,
                    0
                )
                ?.packageName

        } catch (_: Exception) {
            null
        }
    }

    /**
     * Check if APK is debuggable.
     */
    fun isDebuggable(
        packageManager: PackageManager,
        apkFile: File
    ): Boolean {

        return try {

            val packageInfo =
                packageManager
                    .getPackageArchiveInfo(
                        apkFile.absolutePath,
                        PackageManager.GET_ACTIVITIES
                    )

            val flags =
                packageInfo
                    ?.applicationInfo
                    ?.flags ?: 0

            flags and
                    android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if APK is signed.
     */
    fun isSigned(
        packageManager: PackageManager,
        apkFile: File
    ): Boolean {

        return try {

            val packageInfo =
                packageManager
                    .getPackageArchiveInfo(
                        apkFile.absolutePath,
                        PackageManager.GET_SIGNING_CERTIFICATES
                    )

            packageInfo?.signingInfo != null

        } catch (_: Exception) {
            false
        }
    }

    /**
     * Generate APK summary.
     */
    fun getSummary(
        apkFile: File
    ): String {

        return buildString {

            appendLine(
                "APK Name: ${apkFile.name}"
            )

            appendLine(
                "Size: ${getSizeInMB(apkFile)} MB"
            )

            appendLine(
                "Path: ${apkFile.absolutePath}"
            )
        }
    }
}
