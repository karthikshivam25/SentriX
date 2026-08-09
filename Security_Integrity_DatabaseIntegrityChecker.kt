package com.sentrix.security.integrity

import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * SentriX Database Integrity Checker
 *
 * Performs integrity verification for local SQLite databases used by SentriX.
 *
 * Responsibilities:
 *
 * - Verify database existence.
 * - Verify database accessibility.
 * - Execute SQLite integrity_check.
 * - Execute SQLite quick_check.
 * - Inspect database schema.
 * - Validate expected tables.
 * - Validate expected columns.
 * - Calculate database file fingerprints.
 * - Inspect WAL and SHM companion files.
 * - Compare database state with a trusted baseline.
 * - Detect database corruption indicators.
 * - Detect unexpected schema changes.
 *
 * This class is intentionally focused on DATABASE integrity.
 *
 * It does NOT:
 *
 * - Perform encryption/decryption.
 * - Manage Room DAOs.
 * - Manage migrations.
 * - Perform application-level integrity checks.
 * - Perform device/root detection.
 * - Decide the final SentriX security response.
 *
 * Architecture:
 *
 *        DatabaseIntegrityChecker
 *                    │
 *        ┌───────────┼────────────┐
 *        ▼           ▼            ▼
 *    SQLite      Schema       File Hash
 *    Checks      Checks       Checks
 *        │           │            │
 *        └───────────┼────────────┘
 *                    ▼
 *           DatabaseIntegrityReport
 *                    │
 *                    ▼
 *             IntegrityValidator
 */
class DatabaseIntegrityChecker {

    // =========================================================================
    // Main Database Check
    // =========================================================================

    /**
     * Performs a complete database integrity check.
     *
     * The caller supplies the SQLite database path.
     */
    fun check(
        databaseFile: File
    ): DatabaseIntegrityReport {

        if (
            databaseFile.path.isBlank()
        ) {

            return DatabaseIntegrityReport.failure(
                databasePath =
                    databaseFile.absolutePath,
                reason =
                    "Database path is empty."
            )
        }

        if (
            !databaseFile.exists()
        ) {

            return DatabaseIntegrityReport.failure(
                databasePath =
                    databaseFile.absolutePath,
                reason =
                    "Database file does not exist.",
                findingType =
                    DatabaseIntegrityFindingType
                        .DATABASE_NOT_FOUND
            )
        }

        if (
            !databaseFile.isFile
        ) {

            return DatabaseIntegrityReport.failure(
                databasePath =
                    databaseFile.absolutePath,
                reason =
                    "Database path is not a regular file.",
                findingType =
                    DatabaseIntegrityFindingType
                        .INVALID_DATABASE_FILE
            )
        }

        if (
            !databaseFile.canRead()
        ) {

            return DatabaseIntegrityReport.failure(
                databasePath =
                    databaseFile.absolutePath,
                reason =
                    "Database file is not readable.",
                findingType =
                    DatabaseIntegrityFindingType
                        .DATABASE_NOT_READABLE
            )
        }

        val fileInspection =
            inspectDatabaseFiles(
                databaseFile
            )

        val sqliteInspection =
            inspectSQLiteDatabase(
                databaseFile
            )

        val schemaInspection =
            inspectSchema(
                databaseFile
            )

        val hashInspection =
            inspectDatabaseHashes(
                databaseFile
            )

        val findings =
            (
                fileInspection.findings +
                        sqliteInspection.findings +
                        schemaInspection.findings +
                        hashInspection.findings
                ).distinct()

        val severity =
            findings
                .maxByOrNull {
                    it.severity.priority
                }
                ?.severity
                ?: DatabaseIntegritySeverity
                    .SAFE

        val status =
            determineStatus(
                findings
            )

        return DatabaseIntegrityReport(

            databasePath =
                databaseFile.absolutePath,

            databaseName =
                databaseFile.name,

            fileInspection =
                fileInspection,

            sqliteInspection =
                sqliteInspection,

            schemaInspection =
                schemaInspection,

            hashInspection =
                hashInspection,

            findings =
                findings,

            severity =
                severity,

            status =
                status,

            checkedAtMillis =
                System.currentTimeMillis()
        )
    }

    // =========================================================================
    // Database File Inspection
    // =========================================================================

    /**
     * Inspects the primary SQLite database and companion files.
     *
     * SQLite may use:
     *
     * database.db
     * database.db-wal
     * database.db-shm
     *
     * The presence of WAL/SHM files is not inherently suspicious.
     */
    private fun inspectDatabaseFiles(
        databaseFile: File
    ): DatabaseFileInspection {

        val findings =
            mutableListOf<DatabaseIntegrityFinding>()

        val walFile =
            File(
                databaseFile.absolutePath +
                        "-wal"
            )

        val shmFile =
            File(
                databaseFile.absolutePath +
                        "-shm"
            )

        val journalFile =
            File(
                databaseFile.absolutePath +
                        "-journal"
            )

        if (
            databaseFile.length() == 0L
        ) {

            findings +=
                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .EMPTY_DATABASE_FILE,

                    severity =
                        DatabaseIntegritySeverity
                            .HIGH,

                    message =
                        "Database file exists but has zero length."
                )
        }

        if (
            !isSQLiteHeader(
                databaseFile
            )
        ) {

            findings +=
                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .INVALID_SQLITE_HEADER,

                    severity =
                        DatabaseIntegritySeverity
                            .CRITICAL,

                    message =
                        "Database file does not contain a valid SQLite header."
                )
        }

        return DatabaseFileInspection(

            databasePath =
                databaseFile.absolutePath,

            databaseSize =
                databaseFile.length(),

            databaseExists =
                databaseFile.exists(),

            databaseReadable =
                databaseFile.canRead(),

            walExists =
                walFile.exists(),

            walSize =
                if (
                    walFile.exists()
                ) {
                    walFile.length()
                } else {
                    null
                },

            shmExists =
                shmFile.exists(),

            shmSize =
                if (
                    shmFile.exists()
                ) {
                    shmFile.length()
                } else {
                    null
                },

            journalExists =
                journalFile.exists(),

            journalSize =
                if (
                    journalFile.exists()
                ) {
                    journalFile.length()
                } else {
                    null
                },

            findings =
                findings
        )
    }

    /**
     * Checks for the standard SQLite file header.
     *
     * SQLite databases begin with:
     *
     * "SQLite format 3\000"
     */
    private fun isSQLiteHeader(
        databaseFile: File
    ): Boolean {

        return try {

            FileInputStream(
                databaseFile
            )
                .buffered()
                .use { input ->

                    val expected =
                        "SQLite format 3\u0000"
                            .toByteArray(
                                Charsets.US_ASCII
                            )

                    val actual =
                        ByteArray(
                            expected.size
                        )

                    val read =
                        input.read(
                            actual
                        )

                    read ==
                            expected.size &&
                            actual.contentEquals(
                                expected
                            )
                }

        } catch (
            _: Exception
        ) {

            false
        }
    }

    // =========================================================================
    // SQLite Integrity Check
    // =========================================================================

    /**
     * Executes SQLite's native integrity_check.
     *
     * This is one of the strongest corruption-oriented checks available
     * directly from SQLite.
     */
    private fun inspectSQLiteDatabase(
        databaseFile: File
    ): SQLiteIntegrityInspection {

        val findings =
            mutableListOf<DatabaseIntegrityFinding>()

        var integrityCheckPassed =
            false

        var quickCheckPassed =
            false

        var integrityMessage:
                String? = null

        var quickCheckMessage:
                String? = null

        var database:
                SQLiteDatabase? = null

        try {

            database =
                SQLiteDatabase.openDatabase(
                    databaseFile.absolutePath,
                    null,
                    SQLiteDatabase.OPEN_READONLY
                )

            // -----------------------------------------------------------------
            // Full integrity check
            // -----------------------------------------------------------------

            val integrityResult =
                executePragmaCheck(
                    database =
                        database,
                    pragma =
                        "integrity_check"
                )

            integrityMessage =
                integrityResult.message

            integrityCheckPassed =
                integrityResult.passed

            if (
                !integrityResult.passed
            ) {

                findings +=
                    DatabaseIntegrityFinding(

                        type =
                            DatabaseIntegrityFindingType
                                .SQLITE_INTEGRITY_CHECK_FAILED,

                        severity =
                            DatabaseIntegritySeverity
                                .CRITICAL,

                        message =
                            "SQLite integrity_check failed: " +
                                    (
                                        integrityResult.message
                                            ?: "Unknown SQLite integrity error."
                                        )
                    )
            }

            // -----------------------------------------------------------------
            // Quick check
            // -----------------------------------------------------------------

            val quickResult =
                executePragmaCheck(
                    database =
                        database,
                    pragma =
                        "quick_check"
                )

            quickCheckMessage =
                quickResult.message

            quickCheckPassed =
                quickResult.passed

            if (
                !quickResult.passed
            ) {

                findings +=
                    DatabaseIntegrityFinding(

                        type =
                            DatabaseIntegrityFindingType
                                .SQLITE_QUICK_CHECK_FAILED,

                        severity =
                            DatabaseIntegritySeverity
                                .CRITICAL,

                        message =
                            "SQLite quick_check failed: " +
                                    (
                                        quickResult.message
                                            ?: "Unknown SQLite error."
                                        )
                    )
            }

        } catch (
            exception: SQLiteException
        ) {

            findings +=
                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .DATABASE_OPEN_FAILED,

                    severity =
                        DatabaseIntegritySeverity
                            .CRITICAL,

                    message =
                        "SQLite database could not be opened: " +
                                (
                                    exception.message
                                        ?: "Unknown SQLite error."
                                    )
                )

        } catch (
            exception: Exception
        ) {

            findings +=
                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .DATABASE_CHECK_FAILED,

                    severity =
                        DatabaseIntegritySeverity
                            .HIGH,

                    message =
                        "Unexpected database integrity-check error: " +
                                (
                                    exception.message
                                        ?: "Unknown error."
                                    )
                )

        } finally {

            try {
                database?.close()
            } catch (
                _: Exception
            ) {
                // Ignore close failures.
            }
        }

        return SQLiteIntegrityInspection(

            openedSuccessfully =
                database != null,

            integrityCheckPassed =
                integrityCheckPassed,

            quickCheckPassed =
                quickCheckPassed,

            integrityCheckMessage =
                integrityMessage,

            quickCheckMessage =
                quickCheckMessage,

            findings =
                findings
        )
    }

    /**
     * Executes a SQLite PRAGMA integrity check.
     */
    private fun executePragmaCheck(
        database: SQLiteDatabase,
        pragma: String
    ): SQLitePragmaResult {

        var cursor:
                Cursor? = null

        return try {

            cursor =
                database.rawQuery(
                    "PRAGMA $pragma;",
                    null
                )

            if (
                !cursor.moveToFirst()
            ) {

                return SQLitePragmaResult(
                    passed =
                        false,
                    message =
                        "SQLite returned no result."
                )
            }

            val message =
                cursor.getString(
                    0
                )

            SQLitePragmaResult(

                passed =
                    message.equals(
                        "ok",
                        ignoreCase = true
                    ),

                message =
                    message
            )

        } catch (
            exception: Exception
        ) {

            SQLitePragmaResult(

                passed =
                    false,

                message =
                    exception.message
                        ?: "SQLite pragma execution failed."
            )

        } finally {

            try {
                cursor?.close()
            } catch (
                _: Exception
            ) {
                // Ignore cursor-close failures.
            }
        }
    }

    // =========================================================================
    // Schema Inspection
    // =========================================================================

    /**
     * Inspects the database schema.
     */
    private fun inspectSchema(
        databaseFile: File
    ): DatabaseSchemaInspection {

        val findings =
            mutableListOf<DatabaseIntegrityFinding>()

        val tables =
            mutableListOf<DatabaseTableInfo>()

        var database:
                SQLiteDatabase? = null

        try {

            database =
                SQLiteDatabase.openDatabase(
                    databaseFile.absolutePath,
                    null,
                    SQLiteDatabase.OPEN_READONLY
                )

            val cursor =
                database.rawQuery(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    AND name NOT LIKE 'sqlite_%'
                    ORDER BY name
                    """.trimIndent(),
                    null
                )

            cursor.use {

                while (
                    it.moveToNext()
                ) {

                    val tableName =
                        it.getString(
                            0
                        )

                    val columns =
                        readTableColumns(
                            database =
                                database,
                            tableName =
                                tableName
                        )

                    tables +=
                        DatabaseTableInfo(

                            name =
                                tableName,

                            columns =
                                columns
                        )
                }
            }

        } catch (
            exception: Exception
        ) {

            findings +=
                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .SCHEMA_READ_FAILED,

                    severity =
                        DatabaseIntegritySeverity
                            .HIGH,

                    message =
                        "Unable to inspect database schema: " +
                                (
                                    exception.message
                                        ?: "Unknown error."
                                    )
                )

        } finally {

            try {
                database?.close()
            } catch (
                _: Exception
            ) {
                // Ignore close failures.
            }
        }

        return DatabaseSchemaInspection(

            tableCount =
                tables.size,

            tables =
                tables,

            findings =
                findings
        )
    }

    /**
     * Reads column names for a table.
     */
    private fun readTableColumns(
        database: SQLiteDatabase,
        tableName: String
    ): List<String> {

        if (
            !isSafeIdentifier(
                tableName
            )
        ) {

            return emptyList()
        }

        val columns =
            mutableListOf<String>()

        var cursor:
                Cursor? = null

        try {

            cursor =
                database.rawQuery(
                    "PRAGMA table_info($tableName);",
                    null
                )

            while (
                cursor.moveToNext()
            ) {

                val columnName =
                    cursor.getString(
                        cursor.getColumnIndexOrThrow(
                            "name"
                        )
                    )

                columns +=
                    columnName
            }

        } catch (
            _: Exception
        ) {

            // Schema failure is reported at the parent level.
        } finally {

            try {
                cursor?.close()
            } catch (
                _: Exception
            ) {
                // Ignore.
            }
        }

        return columns
    }

    /**
     * Validates that an identifier is safe to use in a PRAGMA statement.
     */
    private fun isSafeIdentifier(
        identifier: String
    ): Boolean {

        if (
            identifier.isBlank()
        ) {

            return false
        }

        return identifier.all {
            it.isLetterOrDigit() ||
                    it == '_' ||
                    it == '$'
        }
    }

    /**
     * Validates expected database tables.
     */
    fun validateExpectedTables(
        databaseFile: File,
        expectedTables:
            Collection<String>
    ): List<DatabaseIntegrityFinding> {

        val inspection =
            inspectSchema(
                databaseFile
            )

        val actualTables =
            inspection.tables
                .map {
                    it.name
                }
                .toSet()

        return expectedTables
            .filter {
                expected ->
                expected !in actualTables
            }
            .map {
                missing ->

                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .EXPECTED_TABLE_MISSING,

                    severity =
                        DatabaseIntegritySeverity
                            .CRITICAL,

                    message =
                        "Expected database table is missing: $missing"
                )
            }
    }

    /**
     * Validates expected columns for a specific table.
     */
    fun validateExpectedColumns(
        databaseFile: File,
        tableName: String,
        expectedColumns:
            Collection<String>
    ): List<DatabaseIntegrityFinding> {

        val inspection =
            inspectSchema(
                databaseFile
            )

        val table =
            inspection.tables
                .firstOrNull {
                    it.name ==
                            tableName
                }

        if (
            table == null
        ) {

            return listOf(
                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .EXPECTED_TABLE_MISSING,

                    severity =
                        DatabaseIntegritySeverity
                            .CRITICAL,

                    message =
                        "Expected database table is missing: $tableName"
                )
            )
        }

        val actualColumns =
            table.columns.toSet()

        return expectedColumns
            .filter {
                expected ->
                expected !in actualColumns
            }
            .map {
                missing ->

                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .EXPECTED_COLUMN_MISSING,

                    severity =
                        DatabaseIntegritySeverity
                            .HIGH,

                    message =
                        "Expected column '$missing' is missing from table '$tableName'."
                )
            }
    }

    // =========================================================================
    // Database Hashing
    // =========================================================================

    /**
     * Calculates the SHA-256 fingerprint of the primary database file.
     */
    fun calculateDatabaseSha256(
        databaseFile: File
    ): String? {

        return calculateHash(
            file =
                databaseFile,
            algorithm =
                "SHA-256"
        )
    }

    /**
     * Calculates the SHA-512 fingerprint of the primary database file.
     */
    fun calculateDatabaseSha512(
        databaseFile: File
    ): String? {

        return calculateHash(
            file =
                databaseFile,
            algorithm =
                "SHA-512"
        )
    }

    /**
     * Inspects primary database and companion file hashes.
     *
     * WAL/SHM files are included as additional observations rather than
     * automatically being treated as security violations.
     */
    private fun inspectDatabaseHashes(
        databaseFile: File
    ): DatabaseHashInspection {

        val findings =
            mutableListOf<DatabaseIntegrityFinding>()

        val primaryHash =
            calculateDatabaseSha256(
                databaseFile
            )

        if (
            primaryHash == null
        ) {

            findings +=
                DatabaseIntegrityFinding(

                    type =
                        DatabaseIntegrityFindingType
                            .DATABASE_HASH_FAILED,

                    severity =
                        DatabaseIntegritySeverity
                            .HIGH,

                    message =
                        "Unable to calculate database SHA-256 fingerprint."
                )
        }

        val walFile =
            File(
                databaseFile.absolutePath +
                        "-wal"
            )

        val shmFile =
            File(
                databaseFile.absolutePath +
                        "-shm"
            )

        val journalFile =
            File(
                databaseFile.absolutePath +
                        "-journal"
            )

        return DatabaseHashInspection(

            primarySha256 =
                primaryHash,

            walSha256 =
                if (
                    walFile.exists() &&
                    walFile.isFile &&
                    walFile.canRead()
                ) {
                    calculateDatabaseSha256(
                        walFile
                    )
                } else {
                    null
                },

            shmSha256 =
                if (
                    shmFile.exists() &&
                    shmFile.isFile &&
                    shmFile.canRead()
                ) {
                    calculateDatabaseSha256(
                        shmFile
                    )
                } else {
                    null
                },

            journalSha256 =
                if (
                    journalFile.exists() &&
                    journalFile.isFile &&
                    journalFile.canRead()
                ) {
                    calculateDatabaseSha256(
                        journalFile
                    )
                } else {
                    null
                },

            findings =
                findings
        )
    }

    /**
     * Generic streaming hash function.
     */
    private fun calculateHash(
        file: File,
        algorithm: String
    ): String? {

        if (
            !file.exists() ||
            !file.isFile ||
            !file.canRead()
        ) {

            return null
        }

        return try {

            val digest =
                MessageDigest.getInstance(
                    algorithm
                )

            FileInputStream(
                file
            )
                .buffered()
                .use { input ->

                    val buffer =
                        ByteArray(
                            16 * 1024
                        )

                    while (
                        true
                    ) {

                        val read =
                            input.read(
                                buffer
                            )

                        if (
                            read <= 0
                        ) {

                            break
                        }

                        digest.update(
                            buffer,
                            0,
                            read
                        )
                    }
                }

            digest.digest()
                .joinToString(":") {
                    "%02X".format(
                        it.toInt() and 0xFF
                    )
                }

        } catch (
            _: Exception
        ) {

            null
        }
    }

    // =========================================================================
    // Baseline
    // =========================================================================

    /**
     * Creates a database integrity baseline from the current state.
     *
     * The baseline should only be created after the database has been
     * independently established as trusted.
     */
    fun createBaseline(
        databaseFile: File
    ): DatabaseIntegrityBaseline? {

        if (
            !databaseFile.exists() ||
            !databaseFile.isFile
        ) {

            return null
        }

        val report =
            check(
                databaseFile
            )

        if (
            report.status ==
            DatabaseIntegrityStatus
                .CORRUPTED
        ) {

            return null
        }

        val hash =
            report.hashInspection
                .primarySha256
                ?: return null

        return DatabaseIntegrityBaseline(

            databasePath =
                databaseFile.absolutePath,

            databaseName =
                databaseFile.name,

            databaseSha256 =
                hash,

            databaseSize =
                databaseFile.length(),

            expectedTables =
                report.schemaInspection
                    .tables
                    .map {
                        it.name
                    }
                    .sorted(),

            createdAtMillis =
                System.currentTimeMillis()
        )
    }

    /**
     * Compares the current database against a trusted baseline.
     */
    fun compareWithBaseline(
        databaseFile: File,
        baseline: DatabaseIntegrityBaseline
    ): DatabaseBaselineComparison {

        if (
            !databaseFile.exists()
        ) {

            return DatabaseBaselineComparison
                .DatabaseDeleted
        }

        if (
            databaseFile.absolutePath !=
            baseline.databasePath
        ) {

            return DatabaseBaselineComparison
                .DatabasePathMismatch
        }

        val currentHash =
            calculateDatabaseSha256(
                databaseFile
            )
                ?: return DatabaseBaselineComparison
                    .UnableToCalculateHash

        if (
            !secureEquals(
                currentHash,
                baseline.databaseSha256
            )
        ) {

            return DatabaseBaselineComparison
                .HashMismatch
        }

        val currentTables =
            inspectSchema(
                databaseFile
            )
                .tables
                .map {
                    it.name
                }
                .sorted()

        if (
            currentTables !=
            baseline.expectedTables.sorted()
        ) {

            return DatabaseBaselineComparison
                .SchemaMismatch
        }

        return DatabaseBaselineComparison
            .Match
    }

    // =========================================================================
    // Database Header
    // =========================================================================

    /**
     * Reads SQLite header information.
     */
    fun readDatabaseHeader(
        databaseFile: File
    ): SQLiteDatabaseHeader? {

        if (
            !databaseFile.exists() ||
            !databaseFile.isFile ||
            !databaseFile.canRead()
        ) {

            return null
        }

        return try {

            FileInputStream(
                databaseFile
            )
                .buffered()
                .use { input ->

                    val header =
                        ByteArray(
                            100
                        )

                    val read =
                        input.read(
                            header
                        )

                    if (
                        read < 100
                    ) {

                        return null
                    }

                    val magic =
                        String(
                            header,
                            0,
                            16,
                            Charsets.US_ASCII
                        )

                    if (
                        magic !=
                        "SQLite format 3\u0000"
                    ) {

                        return null
                    }

                    val pageSize =
                        readUnsignedShort(
                            header,
                            16
                        )

                    val writeVersion =
                        header[18]
                            .toInt() and
                                0xFF

                    val readVersion =
                        header[19]
                            .toInt() and
                                0xFF

                    val databaseSizeInPages =
                        readUnsignedInt(
                            header,
                            28
                        )

                    val textEncoding =
                        readUnsignedInt(
                            header,
                            56
                        )

                    SQLiteDatabaseHeader(

                        magic =
                            magic,

                        pageSize =
                            pageSize,

                        writeVersion =
                            writeVersion,

                        readVersion =
                            readVersion,

                        databaseSizeInPages =
                            databaseSizeInPages,

                        textEncoding =
                            textEncoding
                    )
                }

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Reads a big-endian unsigned 16-bit integer.
     */
    private fun readUnsignedShort(
        bytes: ByteArray,
        offset: Int
    ): Int {

        return (
            (bytes[offset].toInt() and 0xFF)
                    shl 8
                ) or
                (
                    bytes[offset + 1].toInt() and
                            0xFF
                    )
    }

    /**
     * Reads a big-endian unsigned 32-bit integer.
     */
    private fun readUnsignedInt(
        bytes: ByteArray,
        offset: Int
    ): Long {

        return (
            (bytes[offset].toLong() and 0xFF) shl 24
                ) or
                (
                    (bytes[offset + 1].toLong() and 0xFF) shl 16
                    ) or
                (
                    (bytes[offset + 2].toLong() and 0xFF) shl 8
                    ) or
                (
                    bytes[offset + 3].toLong() and 0xFF
                    )
    }

    // =========================================================================
    // Status
    // =========================================================================

    /**
     * Determines overall database integrity status.
     */
    private fun determineStatus(
        findings:
            List<DatabaseIntegrityFinding>
    ): DatabaseIntegrityStatus {

        if (
            findings.any {
                it.severity ==
                        DatabaseIntegritySeverity
                            .CRITICAL
            }
        ) {

            return DatabaseIntegrityStatus
                .CORRUPTED
        }

        if (
            findings.any {
                it.severity ==
                        DatabaseIntegritySeverity
                            .HIGH
            }
        ) {

            return DatabaseIntegrityStatus
                .SUSPICIOUS
        }

        if (
            findings.any {
                it.severity ==
                        DatabaseIntegritySeverity
                            .MEDIUM
            }
        ) {

            return DatabaseIntegrityStatus
                .WARNING
        }

        return DatabaseIntegrityStatus
            .INTACT
    }

    // =========================================================================
    // Security Comparison
    // =========================================================================

    /**
     * Performs constant-time comparison of normalized hashes.
     */
    private fun secureEquals(
        first: String,
        second: String
    ): Boolean {

        val firstNormalized =
            normalizeHash(
                first
            )

        val secondNormalized =
            normalizeHash(
                second
            )

        if (
            firstNormalized.length !=
            secondNormalized.length
        ) {

            return false
        }

        var difference =
            0

        for (
            index in
                firstNormalized.indices
        ) {

            difference =
                difference or
                        (
                            firstNormalized[index].code xor
                                    secondNormalized[index].code
                            )
        }

        return difference == 0
    }

    /**
     * Normalizes a hexadecimal fingerprint.
     */
    private fun normalizeHash(
        hash: String
    ): String {

        return hash
            .trim()
            .replace(
                ":",
                ""
            )
            .replace(
                "-",
                ""
            )
            .replace(
                " ",
                ""
            )
            .uppercase()
    }
}

// =============================================================================
// Main Report
// =============================================================================

/**
 * Complete database integrity report.
 */
data class DatabaseIntegrityReport(

    val databasePath: String,

    val databaseName: String,

    val fileInspection:
        DatabaseFileInspection,

    val sqliteInspection:
        SQLiteIntegrityInspection,

    val schemaInspection:
        DatabaseSchemaInspection,

    val hashInspection:
        DatabaseHashInspection,

    val findings:
        List<DatabaseIntegrityFinding>,

    val severity:
        DatabaseIntegritySeverity,

    val status:
        DatabaseIntegrityStatus,

    val checkedAtMillis: Long
) {

    companion object {

        /**
         * Creates a failed database integrity report.
         */
        fun failure(
            databasePath: String,
            reason: String,
            findingType:
                DatabaseIntegrityFindingType =
                DatabaseIntegrityFindingType
                    .DATABASE_CHECK_FAILED
        ): DatabaseIntegrityReport {

            val finding =
                DatabaseIntegrityFinding(

                    type =
                        findingType,

                    severity =
                        when (
                            findingType
                        ) {

                            DatabaseIntegrityFindingType
                                .DATABASE_NOT_FOUND,

                            DatabaseIntegrityFindingType
                                .DATABASE_OPEN_FAILED,

                            DatabaseIntegrityFindingType
                                .INVALID_SQLITE_HEADER ->

                                DatabaseIntegritySeverity
                                    .CRITICAL

                            else ->

                                DatabaseIntegritySeverity
                                    .HIGH
                        },

                    message =
                        reason
                )

            return DatabaseIntegrityReport(

                databasePath =
                    databasePath,

                databaseName =
                    File(
                        databasePath
                    ).name,

                fileInspection =
                    DatabaseFileInspection.empty(),

                sqliteInspection =
                    SQLiteIntegrityInspection.empty(),

                schemaInspection =
                    DatabaseSchemaInspection.empty(),

                hashInspection =
                    DatabaseHashInspection.empty(),

                findings =
                    listOf(
                        finding
                    ),

                severity =
                    finding.severity,

                status =
                    DatabaseIntegrityStatus
                        .CORRUPTED,

                checkedAtMillis =
                    System.currentTimeMillis()
            )
        }
    }
}

// =============================================================================
// File Inspection
// =============================================================================

/**
 * Database filesystem inspection.
 */
data class DatabaseFileInspection(

    val databasePath: String,

    val databaseSize: Long,

    val databaseExists: Boolean,

    val databaseReadable: Boolean,

    val walExists: Boolean,

    val walSize: Long?,

    val shmExists: Boolean,

    val shmSize: Long?,

    val journalExists: Boolean,

    val journalSize: Long?,

    val findings:
        List<DatabaseIntegrityFinding>
) {

    companion object {

        fun empty():
                DatabaseFileInspection {

            return DatabaseFileInspection(

                databasePath =
                    "",

                databaseSize =
                    0L,

                databaseExists =
                    false,

                databaseReadable =
                    false,

                walExists =
                    false,

                walSize =
                    null,

                shmExists =
                    false,

                shmSize =
                    null,

                journalExists =
                    false,

                journalSize =
                    null,

                findings =
                    emptyList()
            )
        }
    }
}

// =============================================================================
// SQLite Inspection
// =============================================================================

/**
 * SQLite engine integrity inspection.
 */
data class SQLiteIntegrityInspection(

    val openedSuccessfully: Boolean,

    val integrityCheckPassed: Boolean,

    val quickCheckPassed: Boolean,

    val integrityCheckMessage: String?,

    val quickCheckMessage: String?,

    val findings:
        List<DatabaseIntegrityFinding>
) {

    companion object {

        fun empty():
                SQLiteIntegrityInspection {

            return SQLiteIntegrityInspection(

                openedSuccessfully =
                    false,

                integrityCheckPassed =
                    false,

                quickCheckPassed =
                    false,

                integrityCheckMessage =
                    null,

                quickCheckMessage =
                    null,

                findings =
                    emptyList()
            )
        }
    }
}

/**
 * Individual SQLite PRAGMA result.
 */
private data class SQLitePragmaResult(

    val passed: Boolean,

    val message: String?
)

// =============================================================================
// Schema
// =============================================================================

/**
 * Database schema inspection.
 */
data class DatabaseSchemaInspection(

    val tableCount: Int,

    val tables:
        List<DatabaseTableInfo>,

    val findings:
        List<DatabaseIntegrityFinding>
) {

    companion object {

        fun empty():
                DatabaseSchemaInspection {

            return DatabaseSchemaInspection(

                tableCount =
                    0,

                tables =
                    emptyList(),

                findings =
                    emptyList()
            )
        }
    }
}

/**
 * Database table metadata.
 */
data class DatabaseTableInfo(

    val name: String,

    val columns:
        List<String>
)

// =============================================================================
// Hash Inspection
// =============================================================================

/**
 * Database and companion-file fingerprints.
 */
data class DatabaseHashInspection(

    val primarySha256: String?,

    val walSha256: String?,

    val shmSha256: String?,

    val journalSha256: String?,

    val findings:
        List<DatabaseIntegrityFinding>
) {

    companion object {

        fun empty():
                DatabaseHashInspection {

            return DatabaseHashInspection(

                primarySha256 =
                    null,

                walSha256 =
                    null,

                shmSha256 =
                    null,

                journalSha256 =
                    null,

                findings =
                    emptyList()
            )
        }
    }
}

// =============================================================================
// Baseline
// =============================================================================

/**
 * Trusted database integrity baseline.
 */
data class DatabaseIntegrityBaseline(

    val databasePath: String,

    val databaseName: String,

    val databaseSha256: String,

    val databaseSize: Long,

    val expectedTables:
        List<String>,

    val createdAtMillis: Long
)

/**
 * Database baseline comparison.
 */
enum class DatabaseBaselineComparison {

    Match,

    HashMismatch,

    SchemaMismatch,

    DatabaseDeleted,

    DatabasePathMismatch,

    UnableToCalculateHash
}

// =============================================================================
// Database Status
// =============================================================================

/**
 * Overall database integrity status.
 */
enum class DatabaseIntegrityStatus {

    /**
     * Database passed all available integrity checks.
     */
    INTACT,

    /**
     * Database generated warnings but no critical failures.
     */
    WARNING,

    /**
     * Database contains suspicious integrity indicators.
     */
    SUSPICIOUS,

    /**
     * Database failed a critical integrity check.
     */
    CORRUPTED
}

// =============================================================================
// Severity
// =============================================================================

/**
 * Severity of a database integrity finding.
 */
enum class DatabaseIntegritySeverity(
    val priority: Int
) {

    SAFE(
        priority = 0
    ),

    LOW(
        priority = 1
    ),

    MEDIUM(
        priority = 2
    ),

    HIGH(
        priority = 3
    ),

    CRITICAL(
        priority = 4
    )
}

// =============================================================================
// Findings
// =============================================================================

/**
 * Database integrity finding.
 */
data class DatabaseIntegrityFinding(

    val type:
        DatabaseIntegrityFindingType,

    val severity:
        DatabaseIntegritySeverity,

    val message: String
)

/**
 * Database integrity finding categories.
 */
enum class DatabaseIntegrityFindingType {

    DATABASE_NOT_FOUND,

    INVALID_DATABASE_FILE,

    DATABASE_NOT_READABLE,

    EMPTY_DATABASE_FILE,

    INVALID_SQLITE_HEADER,

    DATABASE_OPEN_FAILED,

    DATABASE_CHECK_FAILED,

    SQLITE_INTEGRITY_CHECK_FAILED,

    SQLITE_QUICK_CHECK_FAILED,

    DATABASE_HASH_FAILED,

    SCHEMA_READ_FAILED,

    EXPECTED_TABLE_MISSING,

    EXPECTED_COLUMN_MISSING
}

// =============================================================================
// SQLite Header
// =============================================================================

/**
 * Important SQLite database header information.
 *
 * This is useful for detecting unexpected low-level changes without
 * modifying the database.
 */
data class SQLiteDatabaseHeader(

    val magic: String,

    val pageSize: Int,

    val writeVersion: Int,

    val readVersion: Int,

    val databaseSizeInPages: Long,

    val textEncoding: Long
)
