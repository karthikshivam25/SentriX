package com.sentrix.security.sandbox

import android.content.Context
import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * SandboxManager
 *
 * Central manager responsible for coordinating sandboxed execution
 * inside SentriX.
 *
 * Responsibilities:
 * - Create isolated sandbox workspaces.
 * - Track active sandbox sessions.
 * - Enforce execution limits.
 * - Restrict sandbox input/output.
 * - Clean up sandbox resources.
 * - Prevent sandbox state from leaking into the main application.
 *
 * IMPORTANT:
 * Android applications already execute inside an OS-level application
 * sandbox. This class represents an additional application-level security
 * abstraction used by SentriX for controlled analysis workflows.
 *
 * Typical use cases:
 * - APK analysis
 * - Suspicious file analysis
 * - PDF/file inspection
 * - Malware analysis preparation
 * - Script/content inspection
 * - Temporary threat-analysis workspaces
 *
 * This manager does NOT attempt to provide a kernel-level sandbox.
 * Strong isolation for arbitrary native/untrusted code should be delegated
 * to an appropriate isolated process, service, VM, or platform mechanism.
 */
class SandboxManager(
    private val context: Context
) {

    companion object {

        /**
         * Default maximum lifetime of a sandbox session.
         *
         * Prevents abandoned sessions from consuming resources forever.
         */
        private const val DEFAULT_TIMEOUT_MS = 60_000L

        /**
         * Maximum number of simultaneously tracked sandbox sessions.
         */
        private const val MAX_ACTIVE_SESSIONS = 10

        /**
         * Directory used for temporary sandbox workspaces.
         */
        private const val SANDBOX_ROOT_DIRECTORY = "sentrix_sandbox"

        /**
         * Maximum size allowed for sandbox input.
         *
         * This prevents accidental processing of extremely large files.
         */
        private const val MAX_INPUT_SIZE_BYTES = 50L * 1024L * 1024L

        /**
         * Maximum size allowed for sandbox output.
         */
        private const val MAX_OUTPUT_SIZE_BYTES = 50L * 1024L * 1024L
    }

    /**
     * Root directory for all temporary sandbox workspaces.
     *
     * The directory lives inside the application's private storage.
     */
    private val sandboxRoot: File by lazy {
        File(context.cacheDir, SANDBOX_ROOT_DIRECTORY).apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }

    /**
     * Active sandbox sessions.
     *
     * ConcurrentHashMap is used because sandbox operations may be triggered
     * from background workers or multiple coroutines.
     */
    private val activeSessions =
        ConcurrentHashMap<String, SandboxSession>()

    /**
     * Creates a new sandbox session.
     *
     * @param purpose Human-readable reason for creating the sandbox.
     * @param timeoutMs Maximum allowed lifetime of the session.
     *
     * @return SandboxSession representing the isolated workspace.
     *
     * @throws IllegalStateException if the session limit is reached.
     */
    @Synchronized
    fun createSandbox(
        purpose: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): SandboxSession {

        require(purpose.isNotBlank()) {
            "Sandbox purpose cannot be empty."
        }

        require(timeoutMs > 0) {
            "Sandbox timeout must be greater than zero."
        }

        if (activeSessions.size >= MAX_ACTIVE_SESSIONS) {
            throw IllegalStateException(
                "Maximum number of active sandbox sessions reached."
            )
        }

        val sandboxId = UUID.randomUUID().toString()

        val sandboxDirectory = File(
            sandboxRoot,
            sandboxId
        )

        if (!sandboxDirectory.mkdirs()) {
            throw IllegalStateException(
                "Unable to create sandbox workspace."
            )
        }

        val inputDirectory = File(
            sandboxDirectory,
            "input"
        ).apply {
            mkdirs()
        }

        val outputDirectory = File(
            sandboxDirectory,
            "output"
        ).apply {
            mkdirs()
        }

        val metadataDirectory = File(
            sandboxDirectory,
            "metadata"
        ).apply {
            mkdirs()
        }

        val session = SandboxSession(
            id = sandboxId,
            purpose = purpose,
            rootDirectory = sandboxDirectory,
            inputDirectory = inputDirectory,
            outputDirectory = outputDirectory,
            metadataDirectory = metadataDirectory,
            createdAt = System.currentTimeMillis(),
            timeoutMs = timeoutMs
        )

        activeSessions[sandboxId] = session

        return session
    }

    /**
     * Returns an active sandbox session.
     */
    fun getSandbox(
        sandboxId: String
    ): SandboxSession? {
        return activeSessions[sandboxId]
    }

    /**
     * Returns all currently active sandbox sessions.
     */
    fun getActiveSandboxes(): List<SandboxSession> {
        return activeSessions.values.toList()
    }

    /**
     * Checks whether a sandbox session is currently active.
     */
    fun isSandboxActive(
        sandboxId: String
    ): Boolean {
        return activeSessions.containsKey(sandboxId)
    }

    /**
     * Copies an input file into the sandbox.
     *
     * The source file is copied rather than directly exposed to sandbox
     * processing. This prevents the analysis workflow from modifying
     * the original file.
     */
    suspend fun importFile(
        sandboxId: String,
        source: File
    ): File = withContext(Dispatchers.IO) {

        val session = activeSessions[sandboxId]
            ?: throw IllegalArgumentException(
                "Sandbox session not found."
            )

        validateSession(session)

        require(source.exists()) {
            "Source file does not exist."
        }

        require(source.isFile) {
            "Source must be a regular file."
        }

        require(source.length() <= MAX_INPUT_SIZE_BYTES) {
            "Input file exceeds sandbox size limit."
        }

        val safeFileName = sanitizeFileName(source.name)

        val destination = File(
            session.inputDirectory,
            safeFileName
        )

        source.copyTo(
            target = destination,
            overwrite = false
        )

        destination
    }

    /**
     * Writes controlled data into the sandbox input directory.
     */
    suspend fun writeInput(
        sandboxId: String,
        fileName: String,
        data: ByteArray
    ): File = withContext(Dispatchers.IO) {

        val session = activeSessions[sandboxId]
            ?: throw IllegalArgumentException(
                "Sandbox session not found."
            )

        validateSession(session)

        require(data.size <= MAX_INPUT_SIZE_BYTES) {
            "Sandbox input exceeds size limit."
        }

        val safeFileName = sanitizeFileName(fileName)

        val destination = File(
            session.inputDirectory,
            safeFileName
        )

        destination.writeBytes(data)

        destination
    }

    /**
     * Reads sandbox output.
     *
     * The returned data is copied into memory and the caller receives no
     * direct writable reference to the sandbox file.
     */
    suspend fun readOutput(
        sandboxId: String,
        fileName: String
    ): ByteArray = withContext(Dispatchers.IO) {

        val session = activeSessions[sandboxId]
            ?: throw IllegalArgumentException(
                "Sandbox session not found."
            )

        validateSession(session)

        val safeFileName = sanitizeFileName(fileName)

        val file = File(
            session.outputDirectory,
            safeFileName
        )

        require(file.exists()) {
            "Sandbox output does not exist."
        }

        require(file.isFile) {
            "Sandbox output is not a regular file."
        }

        require(file.length() <= MAX_OUTPUT_SIZE_BYTES) {
            "Sandbox output exceeds size limit."
        }

        file.readBytes()
    }

    /**
     * Terminates and removes a sandbox session.
     */
    suspend fun destroySandbox(
        sandboxId: String
    ) = withContext(Dispatchers.IO) {

        val session = activeSessions.remove(sandboxId)
            ?: return@withContext

        deleteRecursivelySafely(session.rootDirectory)
    }

    /**
     * Removes expired sandbox sessions.
     *
     * This method should normally be invoked periodically by a cleanup
     * worker or application lifecycle component.
     */
    suspend fun cleanupExpiredSandboxes() =
        withContext(Dispatchers.IO) {

            val now = System.currentTimeMillis()

            val expiredSessions = activeSessions.values.filter { session ->

                now - session.createdAt >= session.timeoutMs
            }

            expiredSessions.forEach { session ->

                activeSessions.remove(session.id)

                deleteRecursivelySafely(
                    session.rootDirectory
                )
            }
        }

    /**
     * Completely removes all sandbox sessions.
     *
     * Intended for:
     * - Application shutdown
     * - Security reset
     * - Emergency cleanup
     */
    suspend fun destroyAllSandboxes() =
        withContext(Dispatchers.IO) {

            val sessions = activeSessions.values.toList()

            activeSessions.clear()

            sessions.forEach { session ->
                deleteRecursivelySafely(
                    session.rootDirectory
                )
            }
        }

    /**
     * Returns the number of currently active sandbox sessions.
     */
    fun getActiveSandboxCount(): Int {
        return activeSessions.size
    }

    /**
     * Validates that a sandbox session is still usable.
     */
    private fun validateSession(
        session: SandboxSession
    ) {

        if (session.isDestroyed) {
            throw IllegalStateException(
                "Sandbox session has already been destroyed."
            )
        }

        val elapsedTime =
            System.currentTimeMillis() - session.createdAt

        if (elapsedTime >= session.timeoutMs) {

            activeSessions.remove(session.id)

            deleteRecursivelySafely(
                session.rootDirectory
            )

            throw IllegalStateException(
                "Sandbox session has expired."
            )
        }

        check(
            session.rootDirectory.canonicalPath
                .startsWith(
                    sandboxRoot.canonicalPath
                )
        ) {
            "Sandbox path escaped sandbox root."
        }
    }

    /**
     * Prevents path traversal attacks.
     *
     * Examples rejected:
     * ../secret
     * ../../database
     * /data/data/...
     */
    private fun sanitizeFileName(
        fileName: String
    ): String {

        require(fileName.isNotBlank()) {
            "File name cannot be empty."
        }

        val sanitized = File(fileName).name

        require(
            sanitized == fileName &&
                sanitized != "." &&
                sanitized != ".."
        ) {
            "Invalid sandbox file name."
        }

        return sanitized
    }

    /**
     * Safely deletes a directory tree.
     */
    private fun deleteRecursivelySafely(
        file: File
    ) {

        if (!file.exists()) {
            return
        }

        val canonicalRoot =
            sandboxRoot.canonicalFile

        val canonicalTarget =
            file.canonicalFile

        require(
            canonicalTarget.path.startsWith(
                canonicalRoot.path
            )
        ) {
            "Refusing to delete path outside sandbox root."
        }

        file.deleteRecursively()
    }

    /**
     * Represents one SentriX sandbox execution environment.
     */
    data class SandboxSession(

        /**
         * Unique sandbox identifier.
         */
        val id: String,

        /**
         * Reason for creating the sandbox.
         */
        val purpose: String,

        /**
         * Sandbox root directory.
         */
        val rootDirectory: File,

        /**
         * Controlled input directory.
         */
        val inputDirectory: File,

        /**
         * Controlled output directory.
         */
        val outputDirectory: File,

        /**
         * Metadata directory.
         */
        val metadataDirectory: File,

        /**
         * Creation timestamp.
         */
        val createdAt: Long,

        /**
         * Maximum lifetime.
         */
        val timeoutMs: Long,

        /**
         * Indicates whether the sandbox has been destroyed.
         */
        var isDestroyed: Boolean = false
    )
}
