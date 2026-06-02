package com.sentrix.core.helpers

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import java.io.File
import java.security.MessageDigest

object APKHelper {

    /**
     * Get installed applications
     */
    fun getInstalledApps(context: Context): List<ApplicationInfo> {

        val packageManager = context.packageManager

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledApplications(
                PackageManager.ApplicationInfoFlags.of(0)
            )
        } else {
            packageManager.getInstalledApplications(0)
        }
    }

    /**
     * Get user installed applications only
     */
    fun getUserInstalledApps(context: Context): List<ApplicationInfo> {

        return getInstalledApps(context).filter {

            (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0
        }
    }

    /**
     * Get system applications only
     */
    fun getSystemApps(context: Context): List<ApplicationInfo> {

        return getInstalledApps(context).filter {

            (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        }
    }

    /**
     * Get app name
     */
    fun getAppName(
        context: Context,
        packageName: String
    ): String {

        return try {

            val packageManager = context.packageManager
            val applicationInfo =
                packageManager.getApplicationInfo(packageName, 0)

            packageManager.getApplicationLabel(applicationInfo).toString()

        } catch (e: Exception) {
            "Unknown App"
        }
    }

    /**
     * Get app icon
     */
    fun getAppIcon(
        context: Context,
        packageName: String
    ): Drawable? {

        return try {

            val packageManager = context.packageManager
            packageManager.getApplicationIcon(packageName)

        } catch (e: Exception) {
            null
        }
    }

    /**
     * Get package info
     */
    fun getPackageInfo(
        context: Context,
        packageName: String
    ): PackageInfo? {

        return try {

            val packageManager = context.packageManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {

                packageManager.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(0)
                )

            } else {

                packageManager.getPackageInfo(packageName, 0)
            }

        } catch (e: Exception) {
            null
        }
    }

    /**
     * Get version name
     */
    fun getVersionName(
        context: Context,
        packageName: String
    ): String {

        return getPackageInfo(context, packageName)
            ?.versionName ?: "Unknown"
    }

    /**
     * Get version code
     */
    fun getVersionCode(
        context: Context,
        packageName: String
    ): Long {

        val packageInfo =
            getPackageInfo(context, packageName)

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo?.longVersionCode ?: 0
        } else {
            @Suppress("DEPRECATION")
            packageInfo?.versionCode?.toLong() ?: 0
        }
    }

    /**
     * Check if app is installed
     */
    fun isAppInstalled(
        context: Context,
        packageName: String
    ): Boolean {

        return try {

            context.packageManager.getPackageInfo(packageName, 0)
            true

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get APK path
     */
    fun getApkPath(
        context: Context,
        packageName: String
    ): String? {

        return try {

            val applicationInfo =
                context.packageManager.getApplicationInfo(packageName, 0)

            applicationInfo.sourceDir

        } catch (e: Exception) {
            null
        }
    }

    /**
     * Calculate APK SHA-256 hash
     */
    fun calculateApkHash(apkPath: String): String {

        return try {

            val file = File(apkPath)
            val digest = MessageDigest.getInstance("SHA-256")

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
     * Get APK size in MB
     */
    fun getApkSize(
        context: Context,
        packageName: String
    ): Double {

        return try {

            val apkPath = getApkPath(context, packageName)
                ?: return 0.0

            val file = File(apkPath)

            file.length().toDouble() / (1024 * 1024)

        } catch (e: Exception) {
            0.0
        }
    }

    /**
     * Check if app is debuggable
     */
    fun isAppDebuggable(
        context: Context,
        packageName: String
    ): Boolean {

        return try {

            val applicationInfo =
                context.packageManager.getApplicationInfo(packageName, 0)

            (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get installer package name
     */
    fun getInstallerPackage(
        context: Context,
        packageName: String
    ): String {

        return try {

            val packageManager = context.packageManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {

                packageManager.getInstallSourceInfo(packageName)
                    .installingPackageName ?: "Unknown"

            } else {

                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(packageName)
                    ?: "Unknown"
            }

        } catch (e: Exception) {
            "Unknown"
        }
    }
}
