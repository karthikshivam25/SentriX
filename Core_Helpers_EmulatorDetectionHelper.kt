package com.sentrix.core.helpers

import android.os.Build
import java.io.File

object EmulatorDetectionHelper {

    /**
     * Check if device is running on emulator
     */
    fun isEmulator(): Boolean {

        return checkBuildProperties() ||
                checkEmulatorFiles() ||
                checkEmulatorHardware() ||
                checkEmulatorProducts()
    }

    /**
     * Check emulator-related build properties
     */
    private fun checkBuildProperties(): Boolean {

        return (
            Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.lowercase().contains("vbox") ||
            Build.FINGERPRINT.lowercase().contains("test-keys") ||

            Build.MODEL.contains("google_sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for x86") ||

            Build.MANUFACTURER.contains("Genymotion") ||

            Build.BRAND.startsWith("generic") &&
                    Build.DEVICE.startsWith("generic") ||

            "google_sdk" == Build.PRODUCT
        )
    }

    /**
     * Check emulator-related files
     */
    private fun checkEmulatorFiles(): Boolean {

        val emulatorFiles = listOf(
            "/dev/qemu_pipe",
            "/dev/qemu_trace",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )

        return emulatorFiles.any {
            File(it).exists()
        }
    }

    /**
     * Check emulator hardware names
     */
    private fun checkEmulatorHardware(): Boolean {

        return (
            Build.HARDWARE.contains("goldfish") ||
            Build.HARDWARE.contains("ranchu") ||
            Build.HARDWARE.contains("vbox86")
        )
    }

    /**
     * Check emulator product identifiers
     */
    private fun checkEmulatorProducts(): Boolean {

        return (
            Build.PRODUCT.contains("sdk") ||
            Build.PRODUCT.contains("emulator") ||
            Build.PRODUCT.contains("simulator")
        )
    }

    /**
     * Get detailed emulator report
     */
    fun getEmulatorReport(): EmulatorReport {

        val buildPropertiesDetected = checkBuildProperties()
        val emulatorFilesDetected = checkEmulatorFiles()
        val emulatorHardwareDetected = checkEmulatorHardware()
        val emulatorProductsDetected = checkEmulatorProducts()

        val isEmulatorDetected =
            buildPropertiesDetected ||
                    emulatorFilesDetected ||
                    emulatorHardwareDetected ||
                    emulatorProductsDetected

        return EmulatorReport(
            isEmulator = isEmulatorDetected,
            buildPropertiesDetected = buildPropertiesDetected,
            emulatorFilesDetected = emulatorFilesDetected,
            emulatorHardwareDetected = emulatorHardwareDetected,
            emulatorProductsDetected = emulatorProductsDetected
        )
    }

    /**
     * Emulator report data model
     */
    data class EmulatorReport(
        val isEmulator: Boolean,
        val buildPropertiesDetected: Boolean,
        val emulatorFilesDetected: Boolean,
        val emulatorHardwareDetected: Boolean,
        val emulatorProductsDetected: Boolean
    )
}
