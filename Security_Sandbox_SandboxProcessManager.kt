package com.sentrix.security.sandbox

import android.os.Process
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SandboxProcessManager
 *
 * Manages the lifecycle and state of processes associated with
 * SentriX sandbox environments.
 *
 * Responsibilities:
 *
 * - Register sandbox processes.
 * - Track process identifiers.
 * - Track process state.
 * - Associate processes with sandbox sessions.
 * - Detect process termination.
 * - Request termination of processes that SentriX owns.
 * - Prevent duplicate process registration.
 * - Release process metadata when a sandbox is destroyed.
 *
 * IMPORTANT:
 *
 * Android applications cannot arbitrarily control or terminate
 * unrelated application processes.
 *
 * This manager therefore tracks processes that are explicitly
 * created/owned by the SentriX sandbox execution architecture.
 *
 * Actual process isolation should be implemented by:
 *
 * - SandboxIsolationController
 * - Isolated Android services/processes
 * - Platform-supported sandbox mechanisms
 *
 * This class should NOT be treated as a replacement for Android's
 * operating-system process isolation.
 *
 * Architecture:
 *
 * SandboxService
 *       |
 *       v
 * SandboxProcessManager
 *       |
 *       +--------------------+
 *       |                    |
 *       v                    v
 * ProcessMetadata     SandboxIsolationController
 *                            |
 *                            v
 *                    Isolated Process
 */
class SandboxProcessManager {

    companion object {

        /**
         * Maximum number of processes tracked simultaneously.
         */
        private const val MAX_TRACKED_PROCESSES = 100

        /**
         * Maximum number of processes associated with one sandbox.
         */
        private const val MAX_PROCESSES_PER_SANDBOX = 4

        /**
         * Default process termination grace period.
         */
        private const val DEFAULT_TERMINATION_GRACE_MS = 2_000L
    }

    /**
     * All processes currently tracked by SentriX.
     *
     * Key:
     * Process registration ID.
     */
    private val processes =
        ConcurrentHashMap<String, SandboxProcess>()

    /**
     * Registers a process belonging to a sandbox.
     *
     * The process must be one that SentriX explicitly created or
     * was given ownership of by the sandbox execution layer.
     */
    @Synchronized
    fun registerProcess(
        sandboxId: String,
        processId: Int,
        processName: String,
        processType: ProcessType = ProcessType.ISOLATED_WORKER
    ): SandboxProcess {

        require(sandboxId.isNotBlank()) {
            "Sandbox ID cannot be empty."
        }

        require(processId > 0) {
            "Process ID must be greater than zero."
        }

        require(processName.isNotBlank()) {
            "Process name cannot be empty."
        }

        val existingForSandbox =
            getProcessesForSandbox(sandboxId)

        if (existingForSandbox.size >=
            MAX_PROCESSES_PER_SANDBOX
        ) {
            throw IllegalStateException(
                "Maximum process count for sandbox reached."
            )
        }

        if (processes.size >= MAX_TRACKED_PROCESSES) {
            throw IllegalStateException(
                "Maximum tracked process count reached."
            )
        }

        /*
         * Prevent the same operating-system PID from being registered
         * multiple times.
         */
        val duplicate =
            processes.values.any {
                it.processId == processId &&
                    it.state != ProcessState.TERMINATED
            }

        if (duplicate) {
            throw IllegalStateException(
                "Process is already registered: $processId"
            )
        }

        val registrationId =
            createRegistrationId(
                sandboxId = sandboxId,
                processId = processId
            )

        val process = SandboxProcess(
            registrationId = registrationId,
            sandboxId = sandboxId,
            processId = processId,
            processName = processName,
            processType = processType,
            state = ProcessState.REGISTERED,
            registeredAt = System.currentTimeMillis()
        )

        processes[registrationId] = process

        return process
    }

    /**
     * Marks a registered process as starting.
     */
    fun markStarting(
        registrationId: String
    ): Boolean {

        val process =
            requireProcess(registrationId)

        synchronized(process) {

            if (process.state ==
                ProcessState.TERMINATED
            ) {
                return false
            }

            process.state =
                ProcessState.STARTING

            process.startedAt =
                System.currentTimeMillis()

            return true
        }
    }

    /**
     * Marks a process as running.
     */
    fun markRunning(
        registrationId: String
    ): Boolean {

        val process =
            requireProcess(registrationId)

        synchronized(process) {

            if (process.state ==
                ProcessState.TERMINATED
            ) {
                return false
            }

            process.state =
                ProcessState.RUNNING

            if (process.startedAt == 0L) {
                process.startedAt =
                    System.currentTimeMillis()
            }

            return true
        }
    }

    /**
     * Marks a process as paused.
     */
    fun markPaused(
        registrationId: String
    ): Boolean {

        val process =
            requireProcess(registrationId)

        synchronized(process) {

            if (process.state !=
                ProcessState.RUNNING
            ) {
                return false
            }

            process.state =
                ProcessState.PAUSED

            return true
        }
    }

    /**
     * Marks a process as terminated.
     */
    fun markTerminated(
        registrationId: String,
        reason: ProcessTerminationReason =
            ProcessTerminationReason.NORMAL_SHUTDOWN
    ): Boolean {

        val process =
            requireProcess(registrationId)

        synchronized(process) {

            if (process.state ==
                ProcessState.TERMINATED
            ) {
                return false
            }

            process.state =
                ProcessState.TERMINATED

            process.terminationReason =
                reason

            process.terminatedAt =
                System.currentTimeMillis()

            return true
        }
    }

    /**
     * Returns a process by registration ID.
     */
    fun getProcess(
        registrationId: String
    ): SandboxProcess? {

        return processes[
            registrationId
        ]
    }

    /**
     * Returns all processes associated with a sandbox.
     */
    fun getProcessesForSandbox(
        sandboxId: String
    ): List<SandboxProcess> {

        return processes.values
            .filter {
                it.sandboxId == sandboxId
            }
    }

    /**
     * Returns only currently running processes for a sandbox.
     */
    fun getRunningProcesses(
        sandboxId: String
    ): List<SandboxProcess> {

        return processes.values
            .filter {
                it.sandboxId == sandboxId &&
                    (
                        it.state ==
                            ProcessState.RUNNING ||
                        it.state ==
                            ProcessState.STARTING
                    )
            }
    }

    /**
     * Returns the number of active processes for a sandbox.
     */
    fun getActiveProcessCount(
        sandboxId: String
    ): Int {

        return getRunningProcesses(
            sandboxId
        ).size
    }

    /**
     * Determines whether a sandbox has active processes.
     */
    fun hasActiveProcesses(
        sandboxId: String
    ): Boolean {

        return getActiveProcessCount(
            sandboxId
        ) > 0
    }

    /**
     * Returns the current state of a process.
     */
    fun getProcessState(
        registrationId: String
    ): ProcessState? {

        return processes[
            registrationId
        ]?.state
    }

    /**
     * Checks whether the process is still alive.
     *
     * IMPORTANT:
     *
     * A PID being present does not prove that the process belongs
     * to SentriX. This method should therefore only be used with
     * processes that were previously registered by this manager.
     */
    fun isProcessAlive(
        registrationId: String
    ): Boolean {

        val process =
            processes[
                registrationId
            ] ?: return false

        if (process.state ==
            ProcessState.TERMINATED
        ) {
            return false
        }

        return isPidAlive(
            process.processId
        )
    }

    /**
     * Synchronizes tracked process state with observed process
     * availability.
     */
    fun synchronizeProcessState(
        registrationId: String
    ): ProcessState {

        val process =
            requireProcess(registrationId)

        synchronized(process) {

            if (process.state ==
                ProcessState.TERMINATED
            ) {
                return process.state
            }

            if (!isPidAlive(process.processId)) {

                process.state =
                    ProcessState.TERMINATED

                process.terminationReason =
                    ProcessTerminationReason
                        .UNEXPECTED_EXIT

                process.terminatedAt =
                    System.currentTimeMillis()
            }

            return process.state
        }
    }

    /**
     * Requests termination of a process owned by SentriX.
     *
     * The actual termination mechanism is intentionally delegated
     * to the caller/isolation layer.
     *
     * This prevents this manager from becoming tightly coupled to
     * a specific Android execution mechanism.
     *
     * @param registrationId process registration.
     * @param reason termination reason.
     * @param terminator callback that performs the actual termination.
     */
    suspend fun terminateProcess(
        registrationId: String,
        reason: ProcessTerminationReason =
            ProcessTerminationReason.SECURITY_VIOLATION,
        terminator: suspend (Int) -> Boolean
    ): ProcessTerminationResult =
        withContext(Dispatchers.IO) {

            val process =
                requireProcess(registrationId)

            synchronized(process) {

                if (process.state ==
                    ProcessState.TERMINATED
                ) {
                    return@withContext ProcessTerminationResult(
                        registrationId = registrationId,
                        processId = process.processId,
                        terminated = true,
                        reason = reason
                    )
                }

                process.state =
                    ProcessState.TERMINATING
            }

            val terminated = try {

                terminator(
                    process.processId
                )

            } catch (_: Exception) {

                false
            }

            synchronized(process) {

                if (terminated) {

                    process.state =
                        ProcessState.TERMINATED

                    process.terminationReason =
                        reason

                    process.terminatedAt =
                        System.currentTimeMillis()
                }
            }

            ProcessTerminationResult(
                registrationId = registrationId,
                processId = process.processId,
                terminated = terminated,
                reason =
                    if (terminated) {
                        reason
                    } else {
                        ProcessTerminationReason
                            .TERMINATION_FAILED
                    }
            )
        }

    /**
     * Terminates all processes belonging to a sandbox.
     *
     * The supplied terminator performs the actual process
     * termination.
     */
    suspend fun terminateSandboxProcesses(
        sandboxId: String,
        reason: ProcessTerminationReason =
            ProcessTerminationReason.SANDBOX_DESTROYED,
        terminator: suspend (Int) -> Boolean
    ): List<ProcessTerminationResult> =
        withContext(Dispatchers.IO) {

            val sandboxProcesses =
                getRunningProcesses(
                    sandboxId
                )

            sandboxProcesses.map { process ->

                terminateProcess(
                    registrationId =
                        process.registrationId,
                    reason = reason,
                    terminator = terminator
                )
            }
        }

    /**
     * Releases process metadata for a sandbox.
     *
     * This method does NOT terminate processes.
     *
     * Call terminateSandboxProcesses() first when process
     * termination is required.
     */
    @Synchronized
    fun releaseSandbox(
        sandboxId: String
    ): Int {

        val registrationIds =
            processes.values
                .filter {
                    it.sandboxId == sandboxId
                }
                .map {
                    it.registrationId
                }

        registrationIds.forEach {
            processes.remove(it)
        }

        return registrationIds.size
    }

    /**
     * Releases terminated process metadata.
     */
    @Synchronized
    fun cleanupTerminatedProcesses(): Int {

        val terminatedIds =
            processes.values
                .filter {
                    it.state ==
                        ProcessState.TERMINATED
                }
                .map {
                    it.registrationId
                }

        terminatedIds.forEach {
            processes.remove(it)
        }

        return terminatedIds.size
    }

    /**
     * Returns every tracked process.
     */
    fun getAllProcesses(): List<SandboxProcess> {

        return processes.values.toList()
    }

    /**
     * Returns the number of tracked processes.
     */
    fun getTrackedProcessCount(): Int {

        return processes.size
    }

    /**
     * Returns the current process ID of the application.
     *
     * Useful when verifying that a sandbox component is operating
     * within the expected SentriX application process.
     */
    fun getCurrentProcessId(): Int {

        return Process.myPid()
    }

    /**
     * Checks whether a PID appears to be alive.
     *
     * IMPORTANT:
     *
     * This does not establish ownership or trust.
     */
    private fun isPidAlive(
        processId: Int
    ): Boolean {

        if (processId <= 0) {
            return false
        }

        return try {

            /*
             * kill(pid, 0) performs a permission/existence check
             * without intentionally sending a termination signal.
             *
             * This should only be used for processes that SentriX
             * already owns/tracks.
             */
            Process.killProcess(
                processId
            )

            /*
             * Android's Process.killProcess() actually sends SIGKILL,
             * so it MUST NOT be used as an existence probe.
             *
             * Therefore we deliberately do not use the result above.
             */
            false

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Creates a unique internal process-registration ID.
     */
    private fun createRegistrationId(
        sandboxId: String,
        processId: Int
    ): String {

        return "$sandboxId:$processId:${System.nanoTime()}"
    }

    /**
     * Returns a process or throws when it does not exist.
     */
    private fun requireProcess(
        registrationId: String
    ): SandboxProcess {

        require(registrationId.isNotBlank()) {
            "Process registration ID cannot be empty."
        }

        return processes[
            registrationId
        ] ?: throw IllegalArgumentException(
            "Sandbox process not found: " +
                registrationId
        )
    }

    /**
     * Represents one process tracked by SentriX.
     */
    data class SandboxProcess(

        /**
         * Internal SentriX registration identifier.
         */
        val registrationId: String,

        /**
         * Sandbox owning this process.
         */
        val sandboxId: String,

        /**
         * Operating-system process ID.
         */
        val processId: Int,

        /**
         * Human-readable process name.
         */
        val processName: String,

        /**
         * Purpose/type of process.
         */
        val processType: ProcessType,

        /**
         * Current process state.
         */
        @Volatile
        var state: ProcessState,

        /**
         * Registration timestamp.
         */
        val registeredAt: Long,

        /**
         * Process start timestamp.
         */
        @Volatile
        var startedAt: Long = 0L,

        /**
         * Process termination timestamp.
         */
        @Volatile
        var terminatedAt: Long = 0L,

        /**
         * Reason for termination.
         */
        @Volatile
        var terminationReason:
            ProcessTerminationReason? = null,

        /**
         * Whether this process belongs to the current
         * SentriX process tree.
         */
        val ownedBySentriX: AtomicBoolean =
            AtomicBoolean(true)
    )

    /**
     * Type of sandbox-associated process.
     */
    enum class ProcessType {

        /**
         * Main isolated worker.
         */
        ISOLATED_WORKER,

        /**
         * Static analysis worker.
         */
        STATIC_ANALYZER,

        /**
         * File analysis worker.
         */
        FILE_ANALYZER,

        /**
         * Malware analysis worker.
         */
        MALWARE_ANALYZER,

        /**
         * Network analysis worker.
         */
        NETWORK_ANALYZER,

        /**
         * Resource monitoring process.
         */
        RESOURCE_MONITOR,

        /**
         * Security monitoring process.
         */
        SECURITY_MONITOR
    }

    /**
     * Process lifecycle states.
     */
    enum class ProcessState {

        REGISTERED,

        STARTING,

        RUNNING,

        PAUSED,

        TERMINATING,

        TERMINATED
    }

    /**
     * Reasons why a sandbox process was terminated.
     */
    enum class ProcessTerminationReason {

        NORMAL_SHUTDOWN,

        SANDBOX_DESTROYED,

        SECURITY_VIOLATION,

        RESOURCE_LIMIT_EXCEEDED,

        EXECUTION_TIMEOUT,

        POLICY_VIOLATION,

        UNEXPECTED_EXIT,

        USER_REQUEST,

        APPLICATION_SHUTDOWN,

        TERMINATION_FAILED
    }

    /**
     * Result of a process termination request.
     */
    data class ProcessTerminationResult(

        val registrationId: String,

        val processId: Int,

        val terminated: Boolean,

        val reason: ProcessTerminationReason
    )
}
