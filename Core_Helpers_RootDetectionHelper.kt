package com.sentrix.core.helpers

import android.os.Build
import java.io.File

object RootDetectionHelper {

    /**
     * Check if device is rooted
     */
    fun isDeviceRooted(): Boolean {

        return checkRootFiles() ||
                checkSuBinary() ||
                checkDangerousProps() ||
                checkTestKeys() ||
                checkRootManagementApps()
    }

    /**
     * Check for root-related files
     */
    private fun checkRootFiles(): Boolean {

        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/xbin/daemonsu"
        )

        return paths.any {
            File(it).exists()
        }
    }

    /**
     * Check for SU binary
     */
    private fun checkSuBinary(): Boolean {

        return try {

            val process = Runtime.getRuntime()
                .exec(arrayOf("/system/xbin/which", "su"))

            process.inputStream.bufferedReader()
                .readLine() != null

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check dangerous system properties
     */
    private fun checkDangerousProps(): Boolean {

        return try {

            val process = Runtime.getRuntime()
                .exec("getprop")

            val properties = process.inputStream
                .bufferedReader()
                .readText()

            properties.contains("ro.debuggable=1") ||
                    properties.contains("ro.secure=0")

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check test-keys build tag
     */
    private fun checkTestKeys(): Boolean {

        return Build.TAGS?.contains("test-keys") == true
    }

    /**
     * Check common root management apps
     */
    private fun checkRootManagementApps(): Boolean {

        val rootApps = listOf(
            "/system/app/Kinguser.apk",
            "/system/app/SuperSU.apk",
            "/system/app/Magisk.apk",
            "/data/adb/magisk",
            "/sbin/magisk"
        )

        return rootApps.any {
            File(it).exists()
        }
    }

    /**
     * Get detailed root status
     */
    fun getRootStatusReport(): RootStatusReport {

        val rootFilesDetected = checkRootFiles()
        val suBinaryDetected = checkSuBinary()
        val dangerousPropsDetected = checkDangerousProps()
        val testKeysDetected = checkTestKeys()
        val rootAppsDetected = checkRootManagementApps()

        val rooted = rootFilesDetected ||
                suBinaryDetected ||
                dangerousPropsDetected ||
                testKeysDetected ||
                rootAppsDetected

        return RootStatusReport(
            isRooted = rooted,
            rootFilesDetected = rootFilesDetected,
            suBinaryDetected = suBinaryDetected,
            dangerousPropertiesDetected = dangerousPropsDetected,
            testKeysDetected = testKeysDetected,
            rootAppsDetected = rootAppsDetected
        )
    }

    /**
     * Root status data model
     */
    data class RootStatusReport(
        val isRooted: Boolean,
        val rootFilesDetected: Boolean,
        val suBinaryDetected: Boolean,
        val dangerousPropertiesDetected: Boolean,
        val testKeysDetected: Boolean,
        val rootAppsDetected: Boolean
    )
}
