package com.sentrix.security.rootdetection

import java.io.File

/**
 * RootBinaryChecker
 *
 * Performs filesystem-based checks for binaries commonly associated
 * with elevated/root privileges on Android devices.
 *
 * Responsibility:
 * - Check known root-binary locations.
 * - Collect structured evidence.
 * - Provide safe helper methods for higher-level components.
 *
 * It does NOT:
 * - determine the final root status
 * - calculate the overall device risk score
 * - inspect installed packages
 * - inspect system properties
 * - inspect mount configuration
 * - generate security reports
 *
 * Architecture:
 *
 * RootDetectionService
 *        ↓
 * RootDetectionManager
 *        ↓
 * RootChecker
 *        ↓
 * RootBinaryChecker
 *        ↓
 * Filesystem
 */
class RootBinaryChecker {

    /**
     * Common locations where an `su` binary or related root
     * executable may be present.
     *
     * These paths are indicators only. Android/OEM versions may
     * use different filesystem layouts.
     */
    private val knownRootBinaryPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/su/bin/daemonsu",
        "/system/bin/.ext/su",
        "/system/xbin/daemonsu",
        "/vendor/bin/su",
        "/vendor/xbin/su",
        "/odm/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su"
    )

    /**
     * Performs a complete root-binary scan.
     *
     * @return RootBinaryScanResult containing every discovered
     *         binary and the paths that were inspected.
     */
    fun scan(): RootBinaryScanResult {

        val detectedBinaries = mutableListOf<RootBinaryEvidence>()

        knownRootBinaryPaths.forEach { path ->

            val fileState = inspectPath(path)

            if (fileState.exists) {

                detectedBinaries += RootBinaryEvidence(
                    path = path,
                    fileName = File(path).name,
                    exists = true,
                    isFile = fileState.isFile,
                    isDirectory = fileState.isDirectory,
                    isExecutable = fileState.isExecutable,
                    isReadable = fileState.isReadable,
                    isWritable = fileState.isWritable
                )
            }
        }

        return RootBinaryScanResult(
            detectedBinaries = detectedBinaries,
            pathsChecked = knownRootBinaryPaths.size,
            scanCompleted = true,
            scanTimestamp = System.currentTimeMillis()
        )
    }

    /**
     * Checks whether a known root-related binary exists.
     *
     * This is intentionally a simple existence check.
     */
    fun hasRootBinary(): Boolean {

        return knownRootBinaryPaths.any { path ->
            existsSafely(path)
        }
    }

    /**
     * Returns all known root-binary paths that currently exist.
     */
    fun getDetectedBinaryPaths(): List<String> {

        return knownRootBinaryPaths.filter { path ->
            existsSafely(path)
        }
    }

    /**
     * Checks a specific filesystem path.
     *
     * Useful for tests and future OEM-specific path additions.
     *
     * @param path Absolute filesystem path.
     */
    fun checkPath(path: String): RootBinaryEvidence {

        val state = inspectPath(path)

        return RootBinaryEvidence(
            path = path,
            fileName = File(path).name,
            exists = state.exists,
            isFile = state.isFile,
            isDirectory = state.isDirectory,
            isExecutable = state.isExecutable,
            isReadable = state.isReadable,
            isWritable = state.isWritable
        )
    }

    /**
     * Checks whether a particular path exists.
     */
    fun exists(path: String): Boolean {
        return existsSafely(path)
    }

    /**
     * Returns the number of known paths that contain a possible
     * root-related binary.
     */
    fun getDetectedBinaryCount(): Int {

        return knownRootBinaryPaths.count { path ->
            existsSafely(path)
        }
    }

    /**
     * Returns the configured paths used by this checker.
     *
     * Returning a copy prevents callers from modifying the internal
     * list.
     */
    fun getCheckedPaths(): List<String> {
        return knownRootBinaryPaths.toList()
    }

    /**
     * Inspects a filesystem path while safely handling exceptions.
     *
     * Android security restrictions and OEM-specific behavior can
     * cause filesystem operations to fail.
     */
    private fun inspectPath(
        path: String
    ): FileState {

        return try {

            val file = File(path)

            if (!file.exists()) {
                return FileState(
                    exists = false,
                    isFile = false,
                    isDirectory = false,
                    isExecutable = false,
                    isReadable = false,
                    isWritable = false
                )
            }

            FileState(
                exists = true,
                isFile = file.isFile,
                isDirectory = file.isDirectory,
                isExecutable = file.canExecute(),
                isReadable = file.canRead(),
                isWritable = file.canWrite()
            )

        } catch (_: SecurityException) {

            FileState(
                exists = false,
                isFile = false,
                isDirectory = false,
                isExecutable = false,
                isReadable = false,
                isWritable = false
            )

        } catch (_: Exception) {

            FileState(
                exists = false,
                isFile = false,
                isDirectory = false,
                isExecutable = false,
                isReadable = false,
                isWritable = false
            )
        }
    }

    /**
     * Safely checks whether a path exists.
     *
     * Exceptions are intentionally hidden from the security
     * detection pipeline.
     */
    private fun existsSafely(
        path: String
    ): Boolean {

        return try {

            File(path).exists()

        } catch (_: SecurityException) {

            false

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Internal representation of filesystem state.
     */
    private data class FileState(
        val exists: Boolean,
        val isFile: Boolean,
        val isDirectory: Boolean,
        val isExecutable: Boolean,
        val isReadable: Boolean,
        val isWritable: Boolean
    )
}

/**
 * Result of a root-binary scan.
 */
data class RootBinaryScanResult(

    /**
     * Root-related binaries discovered during the scan.
     */
    val detectedBinaries: List<RootBinaryEvidence>,

    /**
     * Number of known paths inspected.
     */
    val pathsChecked: Int,

    /**
     * Indicates that the scan completed normally.
     */
    val scanCompleted: Boolean,

    /**
     * Time at which the scan completed.
     */
    val scanTimestamp: Long
) {

    /**
     * Returns true when at least one possible root binary
     * was discovered.
     */
    val hasDetectedBinary: Boolean
        get() = detectedBinaries.isNotEmpty()

    /**
     * Number of detected binaries.
     */
    val detectedBinaryCount: Int
        get() = detectedBinaries.size

    /**
     * Returns only the paths of detected binaries.
     */
    val detectedPaths: List<String>
        get() = detectedBinaries.map {
            it.path
        }
}

/**
 * Detailed information about a discovered root-related binary.
 */
data class RootBinaryEvidence(

    /**
     * Absolute path where the binary was found.
     */
    val path: String,

    /**
     * Filename extracted from the path.
     */
    val fileName: String,

    /**
     * Whether the filesystem entry exists.
     */
    val exists: Boolean,

    /**
     * Whether the entry is a regular file.
     */
    val isFile: Boolean,

    /**
     * Whether the entry is a directory.
     */
    val isDirectory: Boolean,

    /**
     * Whether the application reports the entry as executable.
     */
    val isExecutable: Boolean,

    /**
     * Whether the entry is readable.
     */
    val isReadable: Boolean,

    /**
     * Whether the entry is writable.
     */
    val isWritable: Boolean
)
