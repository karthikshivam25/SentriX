package com.sentrix.security.sandbox

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * SandboxResourceManager
 *
 * Central resource-management component for SentriX sandbox
 * environments.
 *
 * Responsibilities:
 *
 * - Register sandbox resource allocations.
 * - Track resource consumption.
 * - Validate resource usage against SandboxPolicy.
 * - Track execution time.
 * - Track storage usage.
 * - Track file count.
 * - Track security/resource violations.
 * - Detect resource exhaustion.
 * - Release resources when a sandbox terminates.
 *
 * Architectural role:
 *
 * SandboxService
 *       |
 *       v
 * SandboxManager
 *       |
 *       v
 * SandboxEnvironment
 *       |
 *       +--------------------+
 *       |                    |
 *       v                    v
 * SandboxPolicy     SandboxResourceManager
 *                            |
 *                            v
 *                    ResourceAllocation
 *
 * IMPORTANT:
 *
 * This class primarily provides resource accounting and policy
 * evaluation.
 *
 * Actual OS-level CPU/memory/process enforcement must be performed
 * by the execution/isolation mechanism available to the platform.
 */
class SandboxResourceManager {

    companion object {

        /**
         * Maximum number of tracked sandbox resource allocations.
         */
        private const val MAX_TRACKED_SANDBOXES = 100

        /**
         * Default resource warning threshold.
         *
         * A warning is generated when a resource reaches this
         * percentage of its configured limit.
         */
        private const val DEFAULT_WARNING_THRESHOLD_PERCENT = 80

        /**
         * Critical resource threshold.
         */
        private const val CRITICAL_THRESHOLD_PERCENT = 95
    }

    /**
     * Resource allocation registry.
     *
     * ConcurrentHashMap allows resource operations from multiple
     * background threads/coroutines.
     */
    private val allocations =
        ConcurrentHashMap<String, ResourceAllocation>()

    /**
     * Registers a sandbox environment for resource tracking.
     */
    @Synchronized
    fun registerSandbox(
        environment: SandboxEnvironment
    ): ResourceAllocation {

        val sandboxId = environment.id

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        if (allocations.containsKey(sandboxId)) {
            return allocations[sandboxId]!!
        }

        if (allocations.size >= MAX_TRACKED_SANDBOXES) {
            throw IllegalStateException(
                "Maximum tracked sandbox resource allocations reached."
            )
        }

        val policy = environment.policy

        policy.validate().requireValid()

        val allocation = ResourceAllocation(
            sandboxId = sandboxId,
            maxMemoryBytes = policy.maxMemoryBytes,
            maxInputBytes = policy.maxInputBytes,
            maxOutputBytes = policy.maxOutputBytes,
            maxTemporaryStorageBytes =
                policy.maxTemporaryStorageBytes,
            maxFileCount = policy.maxFileCount,
            maxIndividualFileBytes =
                policy.maxIndividualFileBytes,
            maxCpuTimeMs = policy.maxCpuTimeMs,
            maxExecutionTimeMs =
                policy.maxExecutionTimeMs,
            maxThreads = policy.maxThreads,
            warningThresholdPercent =
                DEFAULT_WARNING_THRESHOLD_PERCENT
        )

        allocations[sandboxId] = allocation

        return allocation
    }

    /**
     * Returns the resource allocation for a sandbox.
     */
    fun getAllocation(
        sandboxId: String
    ): ResourceAllocation? {

        return allocations[sandboxId]
    }

    /**
     * Checks whether resource tracking exists for a sandbox.
     */
    fun isRegistered(
        sandboxId: String
    ): Boolean {

        return allocations.containsKey(sandboxId)
    }

    /**
     * Returns the number of currently tracked sandboxes.
     */
    fun getTrackedSandboxCount(): Int {

        return allocations.size
    }

    /**
     * Records memory usage.
     *
     * This method records observed memory usage. It does not itself
     * force the operating system to release memory.
     */
    fun updateMemoryUsage(
        sandboxId: String,
        memoryBytes: Long
    ): ResourceCheckResult {

        requireNonNegative(
            memoryBytes,
            "Memory usage"
        )

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentMemoryBytes =
            memoryBytes

        return evaluateMemory(
            allocation
        )
    }

    /**
     * Records CPU time consumed by a sandbox.
     */
    fun updateCpuTime(
        sandboxId: String,
        cpuTimeMs: Long
    ): ResourceCheckResult {

        requireNonNegative(
            cpuTimeMs,
            "CPU time"
        )

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentCpuTimeMs =
            cpuTimeMs

        return evaluateCpuTime(
            allocation
        )
    }

    /**
     * Records the number of active threads.
     */
    fun updateThreadCount(
        sandboxId: String,
        threadCount: Int
    ): ResourceCheckResult {

        require(threadCount >= 0) {
            "Thread count cannot be negative."
        }

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentThreadCount =
            threadCount

        return evaluateThreadCount(
            allocation
        )
    }

    /**
     * Updates the total input storage consumed by the sandbox.
     */
    fun updateInputStorage(
        sandboxId: String,
        bytes: Long
    ): ResourceCheckResult {

        requireNonNegative(
            bytes,
            "Input storage"
        )

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentInputBytes =
            bytes

        return evaluateInputStorage(
            allocation
        )
    }

    /**
     * Updates the total output storage consumed by the sandbox.
     */
    fun updateOutputStorage(
        sandboxId: String,
        bytes: Long
    ): ResourceCheckResult {

        requireNonNegative(
            bytes,
            "Output storage"
        )

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentOutputBytes =
            bytes

        return evaluateOutputStorage(
            allocation
        )
    }

    /**
     * Updates temporary storage consumption.
     */
    fun updateTemporaryStorage(
        sandboxId: String,
        bytes: Long
    ): ResourceCheckResult {

        requireNonNegative(
            bytes,
            "Temporary storage"
        )

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentTemporaryStorageBytes =
            bytes

        return evaluateTemporaryStorage(
            allocation
        )
    }

    /**
     * Updates the number of files currently present.
     */
    fun updateFileCount(
        sandboxId: String,
        fileCount: Int
    ): ResourceCheckResult {

        require(fileCount >= 0) {
            "File count cannot be negative."
        }

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentFileCount =
            fileCount

        return evaluateFileCount(
            allocation
        )
    }

    /**
     * Records a newly created file.
     */
    fun recordFileCreated(
        sandboxId: String,
        fileSizeBytes: Long
    ): ResourceCheckResult {

        requireNonNegative(
            fileSizeBytes,
            "File size"
        )

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentFileCount++

        allocation.currentInputBytes +=
            fileSizeBytes

        allocation.lastFileSizeBytes =
            fileSizeBytes

        return evaluateAll(
            allocation
        )
    }

    /**
     * Records a file deletion.
     */
    fun recordFileDeleted(
        sandboxId: String,
        fileSizeBytes: Long
    ): ResourceCheckResult {

        requireNonNegative(
            fileSizeBytes,
            "File size"
        )

        val allocation =
            requireAllocation(sandboxId)

        allocation.currentFileCount =
            (allocation.currentFileCount - 1)
                .coerceAtLeast(0)

        allocation.currentInputBytes =
            (allocation.currentInputBytes -
                fileSizeBytes)
                .coerceAtLeast(0L)

        return evaluateAll(
            allocation
        )
    }

    /**
     * Starts execution-time tracking for a sandbox.
     */
    fun startExecution(
        sandboxId: String
    ): ResourceCheckResult {

        val allocation =
            requireAllocation(sandboxId)

        if (allocation.executionStarted) {
            return ResourceCheckResult(
                sandboxId = sandboxId,
                status = ResourceStatus.ALLOWED,
                violations = emptyList()
            )
        }

        allocation.executionStarted = true
        allocation.startedAt =
            System.currentTimeMillis()

        return ResourceCheckResult(
            sandboxId = sandboxId,
            status = ResourceStatus.ALLOWED,
            violations = emptyList()
        )
    }

    /**
     * Updates wall-clock execution duration.
     */
    fun updateExecutionTime(
        sandboxId: String
    ): ResourceCheckResult {

        val allocation =
            requireAllocation(sandboxId)

        if (!allocation.executionStarted) {
            return ResourceCheckResult(
                sandboxId = sandboxId,
                status = ResourceStatus.ALLOWED,
                violations = emptyList()
            )
        }

        val startedAt =
            allocation.startedAt

        val elapsed =
            System.currentTimeMillis() - startedAt

        allocation.currentExecutionTimeMs =
            elapsed

        return evaluateExecutionTime(
            allocation
        )
    }

    /**
     * Performs a complete resource evaluation.
     */
    fun evaluateResources(
        sandboxId: String
    ): ResourceCheckResult {

        val allocation =
            requireAllocation(sandboxId)

        if (allocation.executionStarted) {
            allocation.currentExecutionTimeMs =
                System.currentTimeMillis() -
                    allocation.startedAt
        }

        return evaluateAll(
            allocation
        )
    }

    /**
     * Determines whether the sandbox has exceeded any configured
     * resource limit.
     */
    fun hasExceededLimit(
        sandboxId: String
    ): Boolean {

        return evaluateResources(
            sandboxId
        ).status == ResourceStatus.EXCEEDED
    }

    /**
     * Determines whether a sandbox is approaching a resource limit.
     */
    fun isApproachingLimit(
        sandboxId: String
    ): Boolean {

        return evaluateResources(
            sandboxId
        ).status == ResourceStatus.WARNING
    }

    /**
     * Returns all currently violated resources.
     */
    fun getViolations(
        sandboxId: String
    ): List<ResourceViolation> {

        return evaluateResources(
            sandboxId
        ).violations
    }

    /**
     * Records a resource/security violation.
     */
    fun recordViolation(
        sandboxId: String,
        violation: ResourceViolationType
    ) {

        val allocation =
            requireAllocation(sandboxId)

        allocation.violationCount.incrementAndGet()

        allocation.lastViolation =
            violation
    }

    /**
     * Returns the number of resource violations.
     */
    fun getViolationCount(
        sandboxId: String
    ): Int {

        return requireAllocation(
            sandboxId
        ).violationCount.get()
    }

    /**
     * Determines whether the sandbox should be terminated because
     * of resource exhaustion.
     */
    fun shouldTerminate(
        sandboxId: String
    ): Boolean {

        val allocation =
            requireAllocation(sandboxId)

        val result =
            evaluateResources(
                sandboxId
            )

        return result.status ==
            ResourceStatus.EXCEEDED ||
            allocation.terminated.get()
    }

    /**
     * Marks the resource allocation as terminated.
     */
    fun markTerminated(
        sandboxId: String
    ) {

        requireAllocation(
            sandboxId
        ).terminated.set(true)
    }

    /**
     * Releases all resources associated with a sandbox.
     *
     * This removes the resource accounting state. Actual filesystem
     * cleanup should be handled by SandboxManager.
     */
    @Synchronized
    fun releaseSandbox(
        sandboxId: String
    ): Boolean {

        return allocations.remove(
            sandboxId
        ) != null
    }

    /**
     * Releases every tracked sandbox allocation.
     */
    @Synchronized
    fun releaseAll() {

        allocations.clear()
    }

    /**
     * Scans the filesystem and updates storage statistics.
     *
     * This provides a convenient synchronization mechanism between
     * actual sandbox storage and the resource accounting state.
     */
    suspend fun synchronizeStorage(
        environment: SandboxEnvironment
    ): ResourceCheckResult =
        withContext(Dispatchers.IO) {

            val allocation =
                allocations[environment.id]
                    ?: registerSandbox(environment)

            allocation.currentInputBytes =
                calculateDirectorySize(
                    environment.inputDirectory
                )

            allocation.currentOutputBytes =
                calculateDirectorySize(
                    environment.outputDirectory
                )

            allocation.currentTemporaryStorageBytes =
                calculateDirectorySize(
                    environment.temporaryDirectory
                )

            allocation.currentFileCount =
                countFiles(
                    environment.rootDirectory
                )

            evaluateAll(
                allocation
            )
        }

    /**
     * Evaluates all resource categories.
     */
    private fun evaluateAll(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        val violations =
            mutableListOf<ResourceViolation>()

        collectViolation(
            violations,
            evaluateMemory(allocation)
        )

        collectViolation(
            violations,
            evaluateCpuTime(allocation)
        )

        collectViolation(
            violations,
            evaluateThreadCount(allocation)
        )

        collectViolation(
            violations,
            evaluateInputStorage(allocation)
        )

        collectViolation(
            violations,
            evaluateOutputStorage(allocation)
        )

        collectViolation(
            violations,
            evaluateTemporaryStorage(allocation)
        )

        collectViolation(
            violations,
            evaluateFileCount(allocation)
        )

        collectViolation(
            violations,
            evaluateExecutionTime(allocation)
        )

        if (violations.isNotEmpty()) {

            allocation.lastViolations =
                violations

            return ResourceCheckResult(
                sandboxId = allocation.sandboxId,
                status = ResourceStatus.EXCEEDED,
                violations = violations
            )
        }

        if (isAnyResourceAtWarningLevel(allocation)) {

            return ResourceCheckResult(
                sandboxId = allocation.sandboxId,
                status = ResourceStatus.WARNING,
                violations = emptyList()
            )
        }

        return ResourceCheckResult(
            sandboxId = allocation.sandboxId,
            status = ResourceStatus.ALLOWED,
            violations = emptyList()
        )
    }

    private fun evaluateMemory(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.MEMORY,
            current = allocation.currentMemoryBytes,
            maximum = allocation.maxMemoryBytes
        )
    }

    private fun evaluateCpuTime(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.CPU_TIME,
            current = allocation.currentCpuTimeMs,
            maximum = allocation.maxCpuTimeMs
        )
    }

    private fun evaluateThreadCount(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.THREADS,
            current = allocation.currentThreadCount.toLong(),
            maximum = allocation.maxThreads.toLong()
        )
    }

    private fun evaluateInputStorage(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.INPUT_STORAGE,
            current = allocation.currentInputBytes,
            maximum = allocation.maxInputBytes
        )
    }

    private fun evaluateOutputStorage(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.OUTPUT_STORAGE,
            current = allocation.currentOutputBytes,
            maximum = allocation.maxOutputBytes
        )
    }

    private fun evaluateTemporaryStorage(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.TEMPORARY_STORAGE,
            current = allocation.currentTemporaryStorageBytes,
            maximum = allocation.maxTemporaryStorageBytes
        )
    }

    private fun evaluateFileCount(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.FILE_COUNT,
            current = allocation.currentFileCount.toLong(),
            maximum = allocation.maxFileCount.toLong()
        )
    }

    private fun evaluateExecutionTime(
        allocation: ResourceAllocation
    ): ResourceCheckResult {

        return evaluateNumericResource(
            sandboxId = allocation.sandboxId,
            resource = ResourceType.EXECUTION_TIME,
            current = allocation.currentExecutionTimeMs,
            maximum = allocation.maxExecutionTimeMs
        )
    }

    /**
     * Generic resource evaluation.
     */
    private fun evaluateNumericResource(
        sandboxId: String,
        resource: ResourceType,
        current: Long,
        maximum: Long
    ): ResourceCheckResult {

        if (maximum <= 0) {

            return ResourceCheckResult(
                sandboxId = sandboxId,
                status = ResourceStatus.EXCEEDED,
                violations = listOf(
                    ResourceViolation(
                        resource = resource,
                        currentValue = current,
                        maximumValue = maximum,
                        percentage = 100.0,
                        type = ResourceViolationType.INVALID_LIMIT
                    )
                )
            )
        }

        val percentage =
            (current.toDouble() /
                maximum.toDouble()) *
                100.0

        if (current > maximum) {

            return ResourceCheckResult(
                sandboxId = sandboxId,
                status = ResourceStatus.EXCEEDED,
                violations = listOf(
                    ResourceViolation(
                        resource = resource,
                        currentValue = current,
                        maximumValue = maximum,
                        percentage = percentage,
                        type = resource.toViolationType()
                    )
                )
            )
        }

        if (percentage >= DEFAULT_WARNING_THRESHOLD_PERCENT) {

            return ResourceCheckResult(
                sandboxId = sandboxId,
                status = ResourceStatus.WARNING,
                violations = emptyList()
            )
        }

        return ResourceCheckResult(
            sandboxId = sandboxId,
            status = ResourceStatus.ALLOWED,
            violations = emptyList()
        )
    }

    private fun isAnyResourceAtWarningLevel(
        allocation: ResourceAllocation
    ): Boolean {

        return warningPercentage(
            allocation.currentMemoryBytes,
            allocation.maxMemoryBytes
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT ||

        warningPercentage(
            allocation.currentCpuTimeMs,
            allocation.maxCpuTimeMs
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT ||

        warningPercentage(
            allocation.currentThreadCount.toLong(),
            allocation.maxThreads.toLong()
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT ||

        warningPercentage(
            allocation.currentInputBytes,
            allocation.maxInputBytes
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT ||

        warningPercentage(
            allocation.currentOutputBytes,
            allocation.maxOutputBytes
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT ||

        warningPercentage(
            allocation.currentTemporaryStorageBytes,
            allocation.maxTemporaryStorageBytes
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT ||

        warningPercentage(
            allocation.currentFileCount.toLong(),
            allocation.maxFileCount.toLong()
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT ||

        warningPercentage(
            allocation.currentExecutionTimeMs,
            allocation.maxExecutionTimeMs
        ) >= DEFAULT_WARNING_THRESHOLD_PERCENT
    }

    private fun warningPercentage(
        current: Long,
        maximum: Long
    ): Double {

        if (maximum <= 0) {
            return 100.0
        }

        return (current.toDouble() /
            maximum.toDouble()) * 100.0
    }

    private fun collectViolation(
        target: MutableList<ResourceViolation>,
        result: ResourceCheckResult
    ) {

        target.addAll(
            result.violations
        )
    }

    private fun requireAllocation(
        sandboxId: String
    ): ResourceAllocation {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        return allocations[sandboxId]
            ?: throw IllegalArgumentException(
                "No resource allocation found for sandbox: " +
                    sandboxId
            )
    }

    private fun requireNonNegative(
        value: Long,
        name: String
    ) {

        require(value >= 0) {
            "$name cannot be negative."
        }
    }

    /**
     * Recursively calculates directory size.
     */
    private fun calculateDirectorySize(
        directory: File
    ): Long {

        if (!directory.exists()) {
            return 0L
        }

        if (directory.isFile) {
            return directory.length()
        }

        return directory.listFiles()
            ?.sumOf { file ->

                try {
                    calculateDirectorySize(file)
                } catch (_: Exception) {
                    0L
                }
            }
            ?: 0L
    }

    /**
     * Counts files inside a directory tree.
     */
    private fun countFiles(
        directory: File
    ): Int {

        if (!directory.exists()) {
            return 0
        }

        if (directory.isFile) {
            return 1
        }

        return directory.listFiles()
            ?.sumOf { file ->

                try {
                    countFiles(file)
                } catch (_: Exception) {
                    0
                }
            }
            ?: 0
    }

    /**
     * Maps a resource type to its corresponding violation type.
     */
    private fun ResourceType.toViolationType():
        ResourceViolationType {

        return when (this) {

            ResourceType.MEMORY ->
                ResourceViolationType.MEMORY_EXCEEDED

            ResourceType.CPU_TIME ->
                ResourceViolationType.CPU_TIME_EXCEEDED

            ResourceType.THREADS ->
                ResourceViolationType.THREAD_LIMIT_EXCEEDED

            ResourceType.INPUT_STORAGE ->
                ResourceViolationType.INPUT_STORAGE_EXCEEDED

            ResourceType.OUTPUT_STORAGE ->
                ResourceViolationType.OUTPUT_STORAGE_EXCEEDED

            ResourceType.TEMPORARY_STORAGE ->
                ResourceViolationType.TEMPORARY_STORAGE_EXCEEDED

            ResourceType.FILE_COUNT ->
                ResourceViolationType.FILE_COUNT_EXCEEDED

            ResourceType.EXECUTION_TIME ->
                ResourceViolationType.EXECUTION_TIME_EXCEEDED
        }
    }
}


/**
 * Runtime resource allocation for a sandbox.
 */
data class ResourceAllocation(

    /**
     * Sandbox associated with this allocation.
     */
    val sandboxId: String,

    /**
     * Maximum memory.
     */
    val maxMemoryBytes: Long,

    /**
     * Maximum input storage.
     */
    val maxInputBytes: Long,

    /**
     * Maximum output storage.
     */
    val maxOutputBytes: Long,

    /**
     * Maximum temporary storage.
     */
    val maxTemporaryStorageBytes: Long,

    /**
     * Maximum file count.
     */
    val maxFileCount: Int,

    /**
     * Maximum individual file size.
     */
    val maxIndividualFileBytes: Long,

    /**
     * Maximum CPU time.
     */
    val maxCpuTimeMs: Long,

    /**
     * Maximum execution time.
     */
    val maxExecutionTimeMs: Long,

    /**
     * Maximum number of threads.
     */
    val maxThreads: Int,

    /**
     * Warning threshold.
     */
    val warningThresholdPercent: Int,

    /**
     * Current memory consumption.
     */
    var currentMemoryBytes: Long = 0L,

    /**
     * Current CPU consumption.
     */
    var currentCpuTimeMs: Long = 0L,

    /**
     * Current thread count.
     */
    var currentThreadCount: Int = 0,

    /**
     * Current input storage.
     */
    var currentInputBytes: Long = 0L,

    /**
     * Current output storage.
     */
    var currentOutputBytes: Long = 0L,

    /**
     * Current temporary storage.
     */
    var currentTemporaryStorageBytes: Long = 0L,

    /**
     * Current file count.
     */
    var currentFileCount: Int = 0,

    /**
     * Last individual file size observed.
     */
    var lastFileSizeBytes: Long = 0L,

    /**
     * Whether execution tracking has started.
     */
    var executionStarted: Boolean = false,

    /**
     * Execution start timestamp.
     */
    var startedAt: Long = 0L,

    /**
     * Current wall-clock execution time.
     */
    var currentExecutionTimeMs: Long = 0L,

    /**
     * Number of resource violations.
     */
    val violationCount: AtomicLong =
        AtomicLong(0L),

    /**
     * Last resource violation.
     */
    @Volatile
    var lastViolation:
        ResourceViolationType? = null,

    /**
     * All currently detected violations.
     */
    @Volatile
    var lastViolations:
        List<ResourceViolation> = emptyList(),

    /**
     * Indicates whether the sandbox has been terminated.
     */
    val terminated: AtomicBoolean =
        AtomicBoolean(false)
)


/**
 * Resource categories tracked by SentriX.
 */
enum class ResourceType {

    MEMORY,

    CPU_TIME,

    THREADS,

    INPUT_STORAGE,

    OUTPUT_STORAGE,

    TEMPORARY_STORAGE,

    FILE_COUNT,

    EXECUTION_TIME
}


/**
 * Overall resource evaluation status.
 */
enum class ResourceStatus {

    /**
     * All resources are within safe limits.
     */
    ALLOWED,

    /**
     * Resource usage is approaching a configured limit.
     */
    WARNING,

    /**
     * One or more resource limits have been exceeded.
     */
    EXCEEDED
}


/**
 * Resource violation categories.
 */
enum class ResourceViolationType {

    MEMORY_EXCEEDED,

    CPU_TIME_EXCEEDED,

    THREAD_LIMIT_EXCEEDED,

    INPUT_STORAGE_EXCEEDED,

    OUTPUT_STORAGE_EXCEEDED,

    TEMPORARY_STORAGE_EXCEEDED,

    FILE_COUNT_EXCEEDED,

    EXECUTION_TIME_EXCEEDED,

    INVALID_LIMIT
}


/**
 * Detailed resource violation information.
 */
data class ResourceViolation(

    /**
     * Resource that exceeded its limit.
     */
    val resource: ResourceType,

    /**
     * Current resource value.
     */
    val currentValue: Long,

    /**
     * Maximum allowed resource value.
     */
    val maximumValue: Long,

    /**
     * Current usage percentage.
     */
    val percentage: Double,

    /**
     * Type of violation.
     */
    val type: ResourceViolationType,

    /**
     * Time at which the violation was detected.
     */
    val detectedAt: Long =
        System.currentTimeMillis()
)


/**
 * Result of a resource evaluation.
 */
data class ResourceCheckResult(

    /**
     * Sandbox being evaluated.
     */
    val sandboxId: String,

    /**
     * Overall resource status.
     */
    val status: ResourceStatus,

    /**
     * Detected violations.
     */
    val violations: List<ResourceViolation>
)
