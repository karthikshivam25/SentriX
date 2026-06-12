package com.sentrix.data.local.database

import android.content.Context

import androidx.room.Room

/**
 * DatabaseProvider
 *
 * Responsible for creating and
 * managing a singleton instance
 * of the SentriX database.
 *
 * Used by:
 * - Repository layer
 * - Background services
 * - Security modules
 * - Legacy components
 *
 * Responsibilities:
 * - Create database instance
 * - Maintain singleton access
 * - Prevent multiple instances
 * - Provide database lifecycle management
 */
object DatabaseProvider {

    @Volatile
    private var INSTANCE:
        SentriXDatabase? = null

    /**
     * Returns database instance.
     */
    fun getDatabase(
        context: Context
    ): SentriXDatabase {

        return INSTANCE ?: synchronized(this) {

            val instance =
                Room.databaseBuilder(
                    context.applicationContext,
                    SentriXDatabase::class.java,
                    SentriXDatabase.DATABASE_NAME
                )
                    .fallbackToDestructiveMigration()
                    .build()

            INSTANCE = instance

            instance
        }
    }

    /**
     * Clears database instance.
     */
    fun destroyInstance() {

        INSTANCE = null
    }
}
