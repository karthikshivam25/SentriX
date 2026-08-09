package com.sentrix.security.encryption

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * SentriX Encryption Key Manager
 *
 * Responsible for the complete lifecycle of encryption keys used
 * by the SentriX security subsystem.
 *
 * Responsibilities:
 *
 * - Create AES-256 encryption keys.
 * - Store keys inside Android Keystore.
 * - Retrieve Keystore-backed keys.
 * - Check key availability.
 * - Validate key configuration.
 * - Delete keys when explicitly required.
 * - Support controlled key rotation.
 *
 * Security architecture:
 *
 *      EncryptionService
 *              │
 *              ▼
 *      EncryptionEngine
 *              │
 *              ▼
 *      EncryptionKeyManager
 *              │
 *              ▼
 *      Android Keystore
 *
 * IMPORTANT:
 *
 * The raw AES key material is never persisted by this class in:
 *
 * - SharedPreferences
 * - DataStore
 * - Room
 * - SQLite
 * - Files
 * - Logs
 * - Network storage
 *
 * Android Keystore remains the authoritative key store.
 */
object EncryptionKeyManager {

    // -------------------------------------------------------------------------
    // Android Keystore Configuration
    // -------------------------------------------------------------------------

    /**
     * Android's hardware-backed/system Keystore provider.
     */
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /**
     * Primary SentriX encryption key alias.
     *
     * This alias should remain stable across application updates.
     */
    private const val MASTER_KEY_ALIAS =
        "SentriX_Master_Encryption_Key"

    /**
     * Temporary key alias prefix used during controlled key rotation.
     */
    private const val ROTATION_KEY_PREFIX =
        "SentriX_Rotation_Key_"

    /**
     * AES algorithm.
     */
    private const val KEY_ALGORITHM =
        KeyProperties.KEY_ALGORITHM_AES

    /**
     * AES-256.
     */
    private const val KEY_SIZE =
        256

    /**
     * GCM block mode.
     */
    private const val BLOCK_MODE =
        KeyProperties.BLOCK_MODE_GCM

    /**
     * GCM does not use traditional padding.
     */
    private const val ENCRYPTION_PADDING =
        KeyProperties.ENCRYPTION_PADDING_NONE

    /**
     * KeyStore instance.
     *
     * It is initialized lazily because accessing Android Keystore can
     * involve system-level operations.
     */
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(
            ANDROID_KEYSTORE
        ).apply {
            load(null)
        }
    }

    // -------------------------------------------------------------------------
    // Master Key Management
    // -------------------------------------------------------------------------

    /**
     * Ensures that the SentriX master encryption key exists.
     *
     * If the key already exists, no new key is generated.
     *
     * This makes the method safe to call repeatedly during:
     *
     * - Application startup
     * - Dependency initialization
     * - Security subsystem initialization
     * - Repository initialization
     */
    @Synchronized
    fun ensureMasterKey(): SecretKey {

        val existingKey = getMasterKeyOrNull()

        if (existingKey != null) {
            return existingKey
        }

        return generateMasterKey()
    }

    /**
     * Generates the SentriX master encryption key.
     *
     * The generated AES-256 key is stored directly inside
     * Android Keystore.
     */
    @Synchronized
    private fun generateMasterKey(): SecretKey {

        if (hasMasterKey()) {
            return requireNotNull(
                getMasterKeyOrNull()
            )
        }

        return try {

            val keyGenerator = KeyGenerator.getInstance(
                KEY_ALGORITHM,
                ANDROID_KEYSTORE
            )

            val keySpec = KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or
                        KeyProperties.PURPOSE_DECRYPT
            )
                /**
                 * AES-256 provides a 256-bit symmetric key.
                 */
                .setKeySize(KEY_SIZE)

                /**
                 * Restrict the key to AES-GCM.
                 */
                .setBlockModes(
                    BLOCK_MODE
                )

                /**
                 * GCM uses NoPadding.
                 */
                .setEncryptionPaddings(
                    ENCRYPTION_PADDING
                )

                /**
                 * Require randomized encryption.
                 *
                 * This prevents accidental attempts to perform
                 * deterministic encryption with the same IV.
                 */
                .setRandomizedEncryptionRequired(
                    true
                )
                .build()

            keyGenerator.init(
                keySpec
            )

            requireNotNull(
                keyGenerator.generateKey()
            )

        } catch (exception: Exception) {

            throw IllegalStateException(
                "Unable to generate SentriX master encryption key.",
                exception
            )
        }
    }

    /**
     * Retrieves the SentriX master encryption key.
     *
     * @throws IllegalStateException if the key does not exist.
     */
    fun getMasterKey(): SecretKey {

        return getMasterKeyOrNull()
            ?: throw IllegalStateException(
                "SentriX master encryption key is unavailable."
            )
    }

    /**
     * Retrieves the master key without throwing when it does not exist.
     *
     * Useful for status checks and initialization logic.
     */
    fun getMasterKeyOrNull(): SecretKey? {

        return try {

            val entry = keyStore.getEntry(
                MASTER_KEY_ALIAS,
                null
            )

            when (entry) {

                is KeyStore.SecretKeyEntry -> {
                    entry.secretKey
                }

                else -> {
                    null
                }
            }

        } catch (_: Exception) {

            null
        }
    }

    // -------------------------------------------------------------------------
    // Key Availability
    // -------------------------------------------------------------------------

    /**
     * Checks whether the SentriX master key exists.
     */
    fun hasMasterKey(): Boolean {

        return try {
            keyStore.containsAlias(
                MASTER_KEY_ALIAS
            )
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Checks whether a particular key alias exists.
     *
     * This is intentionally restricted to the SentriX Keystore namespace.
     */
    fun hasKey(
        alias: String
    ): Boolean {

        validateAlias(alias)

        return try {
            keyStore.containsAlias(
                alias
            )
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Returns the current master key alias.
     *
     * Keeping the alias behind a method prevents other classes from
     * depending directly on implementation constants.
     */
    fun getMasterKeyAlias(): String {
        return MASTER_KEY_ALIAS
    }

    // -------------------------------------------------------------------------
    // Key Validation
    // -------------------------------------------------------------------------

    /**
     * Validates the master encryption key configuration.
     *
     * This does not expose the actual key material.
     */
    fun validateMasterKey(): KeyValidationResult {

        val key = getMasterKeyOrNull()
            ?: return KeyValidationResult.Invalid(
                "SentriX master encryption key is unavailable."
            )

        if (!key.algorithm.equals(
                KEY_ALGORITHM,
                ignoreCase = true
            )
        ) {
            return KeyValidationResult.Invalid(
                "Encryption key is not an AES key."
            )
        }

        /**
         * Android Keystore-backed SecretKeys may intentionally return
         * null from getEncoded(). Therefore we must NOT use getEncoded()
         * as a validity test.
         */
        return KeyValidationResult.Valid
    }

    // -------------------------------------------------------------------------
    // Key Rotation
    // -------------------------------------------------------------------------

    /**
     * Creates a new temporary AES-256 key for a controlled key-rotation
     * operation.
     *
     * IMPORTANT:
     *
     * Creating a new key alone does NOT migrate existing encrypted data.
     *
     * A complete rotation workflow must:
     *
     * 1. Create the new key.
     * 2. Decrypt existing data using the old key.
     * 3. Encrypt the data using the new key.
     * 4. Persist the newly encrypted data.
     * 5. Verify successful migration.
     * 6. Delete the old key only after migration succeeds.
     *
     * This method therefore creates the key but deliberately does not
     * destroy the existing master key.
     */
    @Synchronized
    fun createRotationKey(): RotationKey {

        val rotationAlias =
            ROTATION_KEY_PREFIX +
                    System.currentTimeMillis()

        return try {

            val keyGenerator = KeyGenerator.getInstance(
                KEY_ALGORITHM,
                ANDROID_KEYSTORE
            )

            val keySpec = KeyGenParameterSpec.Builder(
                rotationAlias,
                KeyProperties.PURPOSE_ENCRYPT or
                        KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(KEY_SIZE)
                .setBlockModes(
                    BLOCK_MODE
                )
                .setEncryptionPaddings(
                    ENCRYPTION_PADDING
                )
                .setRandomizedEncryptionRequired(
                    true
                )
                .build()

            keyGenerator.init(
                keySpec
            )

            val key = requireNotNull(
                keyGenerator.generateKey()
            )

            RotationKey(
                alias = rotationAlias,
                key = key
            )

        } catch (exception: Exception) {

            throw IllegalStateException(
                "Unable to create SentriX rotation key.",
                exception
            )
        }
    }

    /**
     * Retrieves a rotation key by alias.
     */
    fun getKey(
        alias: String
    ): SecretKey {

        validateAlias(alias)

        val entry = keyStore.getEntry(
            alias,
            null
        )

        require(entry is KeyStore.SecretKeyEntry) {
            "No SecretKey exists for alias: $alias"
        }

        return entry.secretKey
    }

    /**
     * Deletes a specific SentriX encryption key.
     *
     * WARNING:
     *
     * Any encrypted data that depends on this key may become
     * permanently undecryptable.
     */
    @Synchronized
    fun deleteKey(
        alias: String
    ) {

        validateAlias(alias)

        try {

            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }

        } catch (exception: Exception) {

            throw IllegalStateException(
                "Unable to delete SentriX encryption key.",
                exception
            )
        }
    }

    /**
     * Deletes the master key.
     *
     * This should only be used for:
     *
     * - Secure application reset
     * - Enterprise wipe
     * - Security incident response
     * - Controlled cryptographic reset
     */
    @Synchronized
    fun deleteMasterKey() {
        deleteKey(
            MASTER_KEY_ALIAS
        )
    }

    // -------------------------------------------------------------------------
    // Key Enumeration
    // -------------------------------------------------------------------------

    /**
     * Returns SentriX-managed encryption aliases.
     *
     * Only aliases belonging to the SentriX namespace are returned.
     */
    fun getSentriXKeyAliases(): List<String> {

        return try {

            keyStore.aliases()
                .toList()
                .filter { alias ->
                    alias.startsWith(
                        "SentriX_"
                    )
                }

        } catch (exception: Exception) {

            throw IllegalStateException(
                "Unable to inspect SentriX encryption keys.",
                exception
            )
        }
    }

    /**
     * Removes obsolete rotation keys.
     *
     * The master key is deliberately never removed by this method.
     */
    @Synchronized
    fun cleanupRotationKeys() {

        val aliases = getSentriXKeyAliases()

        aliases
            .filter { alias ->
                alias.startsWith(
                    ROTATION_KEY_PREFIX
                )
            }
            .forEach { alias ->

                try {

                    keyStore.deleteEntry(
                        alias
                    )

                } catch (exception: Exception) {

                    throw IllegalStateException(
                        "Unable to remove rotation key: $alias",
                        exception
                    )
                }
            }
    }

    // -------------------------------------------------------------------------
    // Alias Validation
    // -------------------------------------------------------------------------

    /**
     * Prevents arbitrary external Keystore aliases from being managed
     * through this class.
     *
     * This keeps EncryptionKeyManager scoped to SentriX-managed keys.
     */
    private fun validateAlias(
        alias: String
    ) {

        require(alias.isNotBlank()) {
            "Key alias cannot be blank."
        }

        require(alias.startsWith("SentriX_")) {
            "Key alias does not belong to SentriX."
        }
    }
}

/**
 * Result of encryption-key validation.
 */
sealed class KeyValidationResult {

    /**
     * Key exists and satisfies the basic expected configuration.
     */
    data object Valid : KeyValidationResult()

    /**
     * Key is unavailable or incorrectly configured.
     */
    data class Invalid(
        val reason: String
    ) : KeyValidationResult()
}

/**
 * Represents a newly generated rotation key.
 *
 * The alias identifies the key inside Android Keystore.
 *
 * The SecretKey object is a Keystore-backed reference; the raw key
 * material is not exported.
 */
data class RotationKey(
    val alias: String,
    val key: SecretKey
)
