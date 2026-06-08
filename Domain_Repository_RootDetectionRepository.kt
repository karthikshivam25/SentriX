package com.sentrix.domain.repositories

import com.sentrix.domain.models.RootDetectionResult
import com.sentrix.domain.models.RootDetectionStatus
import com.sentrix.domain.models.RootIndicator

/**
 * RootDetectionRepository
 *
 * Repository responsible for
 * managing root detection and
 * device integrity validation
 * within the SentriX platform.
 *
 * Used by:
 * - ValidateDeviceTrustUseCase
 * - DeviceIntegrityManager
 * - SecurityDashboard
 * - CyberDefenseManager
 * - RootDetectionEngine
 *
 * Responsibilities:
 * - Detect rooted devices
 * - Store root detection results
 * - Retrieve root indicators
 * - Validate device integrity
 * - Support trust evaluation
 */
interface RootDetectionRepository {

    /**
     * Performs root detection.
     *
     * @return Detection result.
     */
    suspend fun detectRoot():
        RootDetectionResult

    /**
     * Retrieves latest
     * detection result.
     *
     * @return Detection result.
     */
    suspend fun getLatestResult():
        RootDetectionResult?

    /**
     * Saves detection result.
     *
     * @param result Detection result.
     */
    suspend fun saveResult(
        result: RootDetectionResult
    )

    /**
     * Retrieves all
     * root indicators.
     *
     * @return Indicator list.
     */
    suspend fun getRootIndicators():
        List<RootIndicator>

    /**
     * Retrieves active
     * root indicators.
     *
     * @return Active indicators.
     */
    suspend fun getActiveIndicators():
        List<RootIndicator>

    /**
     * Checks whether
     * device is rooted.
     *
     * @return Root status.
     */
    suspend fun isDeviceRooted():
        Boolean

    /**
     * Retrieves current
     * root status.
     *
     * @return Root status.
     */
    suspend fun getRootStatus():
        RootDetectionStatus
}

/**
 * RootDetectionResult
 *
 * Represents root
 * detection results.
 */
data class RootDetectionResult(

    /**
     * Detection identifier.
     */
    val detectionId: String,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Root status.
     */
    val isRooted: Boolean,

    /**
     * Detection status.
     */
    val status:
        RootDetectionStatus,

    /**
     * Root indicators.
     */
    val indicators:
        List<RootIndicator>,

    /**
     * Detection summary.
     */
    val summary: String
)

/**
 * RootIndicator
 *
 * Represents evidence
 * of root access.
 */
data class RootIndicator(

    /**
     * Indicator identifier.
     */
    val indicatorId: String,

    /**
     * Indicator name.
     */
    val name: String,

    /**
     * Indicator description.
     */
    val description: String,

    /**
     * Detection timestamp.
     */
    val detectedAt: Long,

    /**
     * Active status.
     */
    val isActive: Boolean
)

/**
 * Root detection status.
 */
enum class RootDetectionStatus {

    /**
     * Device is secure.
     */
    SECURE,

    /**
     * Root indicators found.
     */
    SUSPICIOUS,

    /**
     * Device is rooted.
     */
    ROOTED,

    /**
     * Detection failed.
     */
    UNKNOWN
}
