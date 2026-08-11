package com.sentrix.security.permissions

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withContext

/**
 * PermissionUsageMonitor
 *
 * Monitors permission-related application operations using
 * Android's AppOps framework where the platform exposes
 * corresponding operations.
 *
 * Responsibilities:
 * - Inspect permission-related AppOps states.
 * - Monitor selected sensitive operations.
 * - Detect changes in operation state.
 * - Identify unexpected permission-operation activity.
 * - Produce permission usage events.
 * - Provide polling-based monitoring for supported operations.
 *
 * Important:
 * Android does not expose a universal public API that allows
 * third-party applications to observe every permission access
 * performed by every application.
 *
 * Therefore this monitor uses AppOps only where the Android
 * platform makes the operation available.
 *
 * It does NOT:
 * - Request permissions.
 * - Revoke permissions.
 * - Bypass Android security restrictions.
 * - Claim visibility into unsupported permission accesses.
 *
 * Architecture:
 *
 * PermissionManager
 *        ↓
 * PermissionChecker
 *        ↓
 * PermissionUsageMonitor
 *        ↓
 * PermissionUsageEvent
 *        ↓
 * PermissionEventHandler / SecurityLogger
 */
class PermissionUsageMonitor(
    private val context: Context,
    private val permissionChecker: PermissionChecker =
        PermissionChecker(context)
) {

    private val applicationContext =
        context.applicationContext

    private val packageManager =
        applicationContext.packageManager

    private val appOpsManager: AppOpsManager? =
        applicationContext.getSystemService(
            Context.APP_OPS_SERVICE
        ) as? AppOpsManager

    /**
     * Returns the current AppOps state for a permission.
     *
     * The permission must have an AppOps mapping on the
     * current Android version for meaningful results.
     */
    fun getPermissionUsageState(
        packageName: String,
        permission: String
    ): PermissionUsageState {

        if (!isPackageInstalled(packageName)) {
            return PermissionUsageState.UNKNOWN
        }

        val operation =
            permissionToAppOp(permission)
                ?: return PermissionUsageState.UNSUPPORTED

        return getOperationState(
            packageName = packageName,
            operation = operation
        )
    }

    /**
     * Returns the current state for an AppOps operation.
     */
    fun getOperationState(
        packageName: String,
        operation: String
    ): PermissionUsageState {

        val manager =
            appOpsManager
                ?: return PermissionUsageState.UNKNOWN

        return try {

            val uid =
                getApplicationUid(
                    packageName
                )
                    ?: return PermissionUsageState.UNKNOWN

            val mode =
                checkOperation(
                    manager = manager,
                    operation = operation,
                    uid = uid,
                    packageName = packageName
                )

            mapAppOpsMode(mode)

        } catch (_: SecurityException) {

            PermissionUsageState.UNKNOWN

        } catch (_: IllegalArgumentException) {

            PermissionUsageState.UNSUPPORTED

        } catch (_: Exception) {

            PermissionUsageState.UNKNOWN
        }
    }

    /**
     * Checks a collection of permission usage states.
     */
    suspend fun checkPermissions(
        packageName: String,
        permissions: List<String>
    ): Map<String, PermissionUsageState> =
        withContext(Dispatchers.IO) {

            permissions.associateWith { permission ->

                permission to
                        getPermissionUsageState(
                            packageName,
                            permission
                        )
            }.mapValues {
                it.value.second
            }
        }

    /**
     * Returns usage snapshots for all supported monitored
     * permissions.
     */
    suspend fun createSnapshot(
        packageName: String
    ): PermissionUsageSnapshot =
        withContext(Dispatchers.IO) {

            if (!isPackageInstalled(packageName)) {

                return@withContext PermissionUsageSnapshot(
                    packageName = packageName,
                    timestamp = System.currentTimeMillis(),
                    entries = emptyList(),
                    supportedPermissionCount = 0,
                    activePermissionCount = 0
                )
            }

            val requestedPermissions =
                getRequestedPermissions(
                    packageName
                )

            val entries =
                requestedPermissions.map { permission ->

                    val state =
                        getPermissionUsageState(
                            packageName,
                            permission
                        )

                    PermissionUsageEntry(
                        permission = permission,
                        state = state,
                        timestamp =
                            System.currentTimeMillis()
                    )
                }

            PermissionUsageSnapshot(
                packageName = packageName,
                timestamp =
                    System.currentTimeMillis(),
                entries = entries,
                supportedPermissionCount =
                    entries.count {
                        it.state !=
                                PermissionUsageState.UNSUPPORTED
                    },
                activePermissionCount =
                    entries.count {
                        it.state ==
                                PermissionUsageState.ALLOWED
                    }
            )
        }

    /**
     * Compares two snapshots and returns usage-state changes.
     */
    fun detectChanges(
        previous: PermissionUsageSnapshot,
        current: PermissionUsageSnapshot
    ): List<PermissionUsageEvent> {

        if (
            previous.packageName !=
            current.packageName
        ) {
            return emptyList()
        }

        val previousMap =
            previous.entries.associateBy {
                it.permission
            }

        val currentMap =
            current.entries.associateBy {
                it.permission
            }

        val events =
            mutableListOf<PermissionUsageEvent>()

        currentMap.forEach { (permission, currentEntry) ->

            val previousEntry =
                previousMap[permission]

            if (previousEntry == null) {

                events += PermissionUsageEvent(
                    packageName =
                        current.packageName,
                    permission = permission,
                    previousState =
                        PermissionUsageState.UNKNOWN,
                    currentState =
                        currentEntry.state,
                    eventType =
                        PermissionUsageEventType
                            .PERMISSION_OBSERVED,
                    timestamp =
                        current.timestamp
                )

                return@forEach
            }

            if (
                previousEntry.state !=
                currentEntry.state
            ) {

                events += PermissionUsageEvent(
                    packageName =
                        current.packageName,
                    permission = permission,
                    previousState =
                        previousEntry.state,
                    currentState =
                        currentEntry.state,
                    eventType =
                        determineEventType(
                            previousState =
                                previousEntry.state,
                            currentState =
                                currentEntry.state
                        ),
                    timestamp =
                        current.timestamp
                )
            }
        }

        return events
    }

    /**
     * Creates a polling Flow that periodically checks
     * permission/AppOps state.
     *
     * The caller controls lifecycle by cancelling collection.
     *
     * @param intervalMillis polling interval.
     */
    fun monitor(
        packageName: String,
        intervalMillis: Long = DEFAULT_POLL_INTERVAL_MILLIS
    ): Flow<PermissionUsageEvent> = flow {

        require(
            intervalMillis >=
                    MIN_POLL_INTERVAL_MILLIS
        ) {
            "Polling interval must be at least " +
                    "$MIN_POLL_INTERVAL_MILLIS ms."
        }

        var previousSnapshot =
            createSnapshot(
                packageName
            )

        while (true) {

            delay(
                intervalMillis
            )

            val currentSnapshot =
                createSnapshot(
                    packageName
                )

            val changes =
                detectChanges(
                    previous = previousSnapshot,
                    current = currentSnapshot
                )

            changes.forEach { event ->
                emit(event)
            }

            previousSnapshot =
                currentSnapshot
        }
    }

    /**
     * Monitors a single permission.
     *
     * Useful for targeted monitoring of a sensitive permission.
     */
    fun monitorPermission(
        packageName: String,
        permission: String,
        intervalMillis: Long =
            DEFAULT_POLL_INTERVAL_MILLIS
    ): Flow<PermissionUsageEvent> = flow {

        require(
            intervalMillis >=
                    MIN_POLL_INTERVAL_MILLIS
        ) {
            "Polling interval must be at least " +
                    "$MIN_POLL_INTERVAL_MILLIS ms."
        }

        var previousState =
            getPermissionUsageState(
                packageName,
                permission
            )

        while (true) {

            delay(
                intervalMillis
            )

            val currentState =
                getPermissionUsageState(
                    packageName,
                    permission
                )

            if (
                currentState !=
                previousState
            ) {

                emit(
                    PermissionUsageEvent(
                        packageName =
                            packageName,
                        permission =
                            permission,
                        previousState =
                            previousState,
                        currentState =
                            currentState,
                        eventType =
                            determineEventType(
                                previousState =
                                    previousState,
                                currentState =
                                    currentState
                            ),
                        timestamp =
                            System.currentTimeMillis()
                    )
                )
            }

            previousState =
                currentState
        }
    }

    /**
     * Returns only currently allowed operations.
     */
    suspend fun getActivePermissions(
        packageName: String
    ): List<String> =
        withContext(Dispatchers.IO) {

            getRequestedPermissions(
                packageName
            ).filter { permission ->

                getPermissionUsageState(
                    packageName,
                    permission
                ) ==
                        PermissionUsageState.ALLOWED
            }
        }

    /**
     * Returns permissions whose AppOps state is denied.
     */
    suspend fun getDeniedOperations(
        packageName: String
    ): List<String> =
        withContext(Dispatchers.IO) {

            getRequestedPermissions(
                packageName
            ).filter { permission ->

                getPermissionUsageState(
                    packageName,
                    permission
                ) ==
                        PermissionUsageState.DENIED
            }
        }

    /**
     * Returns sensitive permissions that are currently
     * represented as allowed AppOps operations.
     */
    suspend fun getActiveSensitivePermissions(
        packageName: String
    ): List<String> =
        withContext(Dispatchers.IO) {

            getRequestedPermissions(
                packageName
            ).filter { permission ->

                permissionChecker.isSensitivePermission(
                    permission
                ) &&
                        getPermissionUsageState(
                            packageName,
                            permission
                        ) ==
                        PermissionUsageState.ALLOWED
            }
        }

    /**
     * Returns a risk-oriented usage summary.
     */
    suspend fun analyzeUsage(
        packageName: String
    ): PermissionUsageAnalysis =
        withContext(Dispatchers.IO) {

            val snapshot =
                createSnapshot(
                    packageName
                )

            val activeSensitive =
                snapshot.entries.filter { entry ->

                    entry.state ==
                            PermissionUsageState.ALLOWED &&
                            permissionChecker
                                .isSensitivePermission(
                                    entry.permission
                                )
                }

            val activeDangerous =
                snapshot.entries.filter { entry ->

                    entry.state ==
                            PermissionUsageState.ALLOWED &&
                            permissionChecker
                                .isDangerousPermission(
                                    entry.permission
                                )
                }

            val riskLevel =
                calculateUsageRisk(
                    sensitiveCount =
                        activeSensitive.size,
                    dangerousCount =
                        activeDangerous.size
                )

            PermissionUsageAnalysis(
                packageName =
                    packageName,
                timestamp =
                    snapshot.timestamp,
                activePermissionCount =
                    snapshot.activePermissionCount,
                activeSensitivePermissionCount =
                    activeSensitive.size,
                activeDangerousPermissionCount =
                    activeDangerous.size,
                riskLevel =
                    riskLevel,
                activePermissions =
                    snapshot.entries
                        .filter {
                            it.state ==
                                    PermissionUsageState.ALLOWED
                        }
                        .map {
                            it.permission
                        }
            )
        }

    /**
     * Converts Android AppOps mode into SentriX state.
     */
    private fun mapAppOpsMode(
        mode: Int
    ): PermissionUsageState {

        return when (mode) {

            AppOpsManager.MODE_ALLOWED ->
                PermissionUsageState.ALLOWED

            AppOpsManager.MODE_IGNORED ->
                PermissionUsageState.IGNORED

            AppOpsManager.MODE_ERRORED ->
                PermissionUsageState.DENIED

            AppOpsManager.MODE_DEFAULT ->
                PermissionUsageState.DEFAULT

            else ->
                PermissionUsageState.UNKNOWN
        }
    }

    /**
     * Determines the event represented by a state transition.
     */
    private fun determineEventType(
        previousState: PermissionUsageState,
        currentState: PermissionUsageState
    ): PermissionUsageEventType {

        return when {

            previousState !=
                    PermissionUsageState.ALLOWED &&
                    currentState ==
                    PermissionUsageState.ALLOWED ->
                PermissionUsageEventType
                    .ACCESS_ALLOWED

            previousState ==
                    PermissionUsageState.ALLOWED &&
                    currentState ==
                    PermissionUsageState.DENIED ->
                PermissionUsageEventType
                    .ACCESS_DENIED

            previousState ==
                    PermissionUsageState.ALLOWED &&
                    currentState ==
                    PermissionUsageState.IGNORED ->
                PermissionUsageEventType
                    .ACCESS_IGNORED

            previousState ==
                    PermissionUsageState.DENIED &&
                    currentState ==
                    PermissionUsageState.ALLOWED ->
                PermissionUsageEventType
                    .ACCESS_RESTORED

            else ->
                PermissionUsageEventType
                    .STATE_CHANGED
        }
    }

    /**
     * Calculates a lightweight usage-risk classification.
     *
     * This is intentionally not the final SentriX permission
     * risk score. PermissionRiskAnalyzer should combine this
     * information with the complete permission footprint.
     */
    private fun calculateUsageRisk(
        sensitiveCount: Int,
        dangerousCount: Int
    ): PermissionRiskLevel {

        val score =
            (sensitiveCount * 8) +
                    (dangerousCount * 3)

        return when {

            score >= 50 ->
                PermissionRiskLevel.CRITICAL

            score >= 30 ->
                PermissionRiskLevel.HIGH

            score >= 15 ->
                PermissionRiskLevel.MEDIUM

            else ->
                PermissionRiskLevel.LOW
        }
    }

    /**
     * Performs an AppOps check while accounting for
     * Android API-level differences.
     */
    private fun checkOperation(
        manager: AppOpsManager,
        operation: String,
        uid: Int,
        packageName: String
    ): Int {

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.Q
        ) {

            manager.unsafeCheckOpNoThrow(
                operation,
                uid,
                packageName
            )

        } else {

            @Suppress("DEPRECATION")
            manager.checkOpNoThrow(
                operation,
                uid,
                packageName
            )
        }
    }

    /**
     * Attempts to resolve an Android permission into an
     * AppOps operation.
     *
     * AppOps mappings vary across Android releases.
     */
    private fun permissionToAppOp(
        permission: String
    ): String? {

        return permissionToAppOpMap[permission]
    }

    /**
     * Returns the UID of the application.
     */
    private fun getApplicationUid(
        packageName: String
    ): Int? {

        return try {

            packageManager
                .getApplicationInfo(
                    packageName,
                    0
                )
                .uid

        } catch (_: PackageManager.NameNotFoundException) {

            null
        }
    }

    /**
     * Checks whether a package is installed.
     */
    private fun isPackageInstalled(
        packageName: String
    ): Boolean {

        return getApplicationUid(
            packageName
        ) != null
    }

    /**
     * Returns permissions requested by a package.
     */
    @Suppress("DEPRECATION")
    private fun getRequestedPermissions(
        packageName: String
    ): List<String> {

        return try {

            val packageInfo =
                if (
                    Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.TIRAMISU
                ) {

                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.PackageInfoFlags.of(
                            PackageManager.GET_PERMISSIONS
                                .toLong()
                        )
                    )

                } else {

                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.GET_PERMISSIONS
                    )
                }

            packageInfo.requestedPermissions
                ?.toList()
                ?: emptyList()

        } catch (_: Exception) {

            emptyList()
        }
    }

    companion object {

        /**
         * Default polling interval.
         *
         * Polling too aggressively can waste battery and CPU.
         */
        const val DEFAULT_POLL_INTERVAL_MILLIS =
            5_000L

        /**
         * Minimum supported polling interval.
         */
        const val MIN_POLL_INTERVAL_MILLIS =
            1_000L

        /**
         * Permission-to-AppOps mappings used by SentriX.
         *
         * AppOps operation names are platform-defined strings.
         * Unsupported mappings are intentionally omitted.
         */
        private val permissionToAppOpMap =
            mapOf(

                "android.permission.ACCESS_COARSE_LOCATION" to
                        AppOpsManager.OPSTR_COARSE_LOCATION,

                "android.permission.ACCESS_FINE_LOCATION" to
                        AppOpsManager.OPSTR_FINE_LOCATION,

                "android.permission.CAMERA" to
                        AppOpsManager.OPSTR_CAMERA,

                "android.permission.RECORD_AUDIO" to
                        AppOpsManager.OPSTR_RECORD_AUDIO,

                "android.permission.READ_CONTACTS" to
                        AppOpsManager.OPSTR_READ_CONTACTS,

                "android.permission.WRITE_CONTACTS" to
                        AppOpsManager.OPSTR_WRITE_CONTACTS,

                "android.permission.READ_CALL_LOG" to
                        AppOpsManager.OPSTR_READ_CALL_LOG,

                "android.permission.WRITE_CALL_LOG" to
                        AppOpsManager.OPSTR_WRITE_CALL_LOG,

                "android.permission.CALL_PHONE" to
                        AppOpsManager.OPSTR_PHONE_CALL,

                "android.permission.READ_SMS" to
                        AppOpsManager.OPSTR_READ_SMS,

                "android.permission.RECEIVE_SMS" to
                        AppOpsManager.OPSTR_RECEIVE_SMS,

                "android.permission.SEND_SMS" to
                        AppOpsManager.OPSTR_SEND_SMS
            )
    }
}

/**
 * Current usage state exposed by the SentriX permission
 * usage monitor.
 */
enum class PermissionUsageState {

    /**
     * Operation is currently allowed by AppOps.
     */
    ALLOWED,

    /**
     * Operation is ignored by AppOps.
     */
    IGNORED,

    /**
     * Operation is explicitly denied.
     */
    DENIED,

    /**
     * Android has not explicitly configured the operation.
     */
    DEFAULT,

    /**
     * Operation exists but cannot be evaluated reliably.
     */
    UNKNOWN,

    /**
     * No supported AppOps mapping exists for the permission.
     */
    UNSUPPORTED
}

/**
 * Snapshot of permission/AppOps states at a point in time.
 */
data class PermissionUsageSnapshot(

    val packageName: String,

    val timestamp: Long,

    val entries: List<PermissionUsageEntry>,

    val supportedPermissionCount: Int,

    val activePermissionCount: Int
)

/**
 * State entry for one permission.
 */
data class PermissionUsageEntry(

    val permission: String,

    val state: PermissionUsageState,

    val timestamp: Long
)

/**
 * Event emitted when a permission usage state changes.
 */
data class PermissionUsageEvent(

    val packageName: String,

    val permission: String,

    val previousState: PermissionUsageState,

    val currentState: PermissionUsageState,

    val eventType: PermissionUsageEventType,

    val timestamp: Long
)

/**
 * Permission usage state transition.
 */
enum class PermissionUsageEventType {

    /**
     * Permission was encountered for the first time
     * during monitoring.
     */
    PERMISSION_OBSERVED,

    /**
     * Operation transitioned into an allowed state.
     */
    ACCESS_ALLOWED,

    /**
     * Operation transitioned into a denied state.
     */
    ACCESS_DENIED,

    /**
     * Operation transitioned into an ignored state.
     */
    ACCESS_IGNORED,

    /**
     * Previously denied operation became allowed.
     */
    ACCESS_RESTORED,

    /**
     * Any other AppOps state transition.
     */
    STATE_CHANGED
}

/**
 * Aggregated permission usage analysis.
 */
data class PermissionUsageAnalysis(

    val packageName: String,

    val timestamp: Long,

    val activePermissionCount: Int,

    val activeSensitivePermissionCount: Int,

    val activeDangerousPermissionCount: Int,

    val riskLevel: PermissionRiskLevel,

    val activePermissions: List<String>
) {

    /**
     * Indicates whether sensitive permission activity
     * is currently represented by allowed AppOps states.
     */
    val hasSensitiveActivity: Boolean
        get() =
            activeSensitivePermissionCount > 0

    /**
     * Indicates whether dangerous permission activity
     * is currently represented by allowed AppOps states.
     */
    val hasDangerousActivity: Boolean
        get() =
            activeDangerousPermissionCount > 0
}
