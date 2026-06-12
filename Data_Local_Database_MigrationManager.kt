package com.sentrix.data.local.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * MigrationManager
 *
 * Responsible for managing
 * database schema migrations
 * across SentriX releases.
 *
 * Responsibilities:
 * - Database upgrades
 * - Schema evolution
 * - Data preservation
 * - Version compatibility
 */
object MigrationManager {

    /**
     * Migration:
     * Version 1 -> Version 2
     *
     * Adds threat source information.
     */
    val MIGRATION_1_2 =
        object : Migration(1, 2) {

            override fun migrate(
                database: SupportSQLiteDatabase
            ) {

                database.execSQL(
                    """
                    ALTER TABLE threats
                    ADD COLUMN threatSource TEXT NOT NULL
                    DEFAULT 'UNKNOWN'
                    """
                )
            }
        }

    /**
     * Migration:
     * Version 2 -> Version 3
     *
     * Adds threat risk score.
     */
    val MIGRATION_2_3 =
        object : Migration(2, 3) {

            override fun migrate(
                database: SupportSQLiteDatabase
            ) {

                database.execSQL(
                    """
                    ALTER TABLE threats
                    ADD COLUMN riskScore INTEGER NOT NULL
                    DEFAULT 0
                    """
                )
            }
        }

    /**
     * Migration:
     * Version 3 -> Version 4
     *
     * Creates security reports table.
     */
    val MIGRATION_3_4 =
        object : Migration(3, 4) {

            override fun migrate(
                database: SupportSQLiteDatabase
            ) {

                database.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS
                    security_reports (
                        reportId TEXT NOT NULL,
                        reportTitle TEXT NOT NULL,
                        generatedAt INTEGER NOT NULL,
                        reportType TEXT NOT NULL,
                        PRIMARY KEY(reportId)
                    )
                    """
                )
            }
        }

    /**
     * Migration:
     * Version 4 -> Version 5
     *
     * Creates device trust table.
     */
    val MIGRATION_4_5 =
        object : Migration(4, 5) {

            override fun migrate(
                database: SupportSQLiteDatabase
            ) {

                database.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS
                    device_trust (
                        deviceId TEXT NOT NULL,
                        trustScore INTEGER NOT NULL,
                        lastVerifiedAt INTEGER NOT NULL,
                        PRIMARY KEY(deviceId)
                    )
                    """
                )
            }
        }

    /**
     * Returns all migrations.
     */
    fun getAllMigrations():
        Array<Migration> {

        return arrayOf(
            MIGRATION_1_2,
            MIGRATION_2_3,
            MIGRATION_3_4,
            MIGRATION_4_5
        )
    }
}
