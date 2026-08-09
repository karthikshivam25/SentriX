package com.sentrix.security.encryption

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * SentriX Encryption Key Store
 *
 * Low-level abstraction over Android Keystore.
 *
 * Responsibilities:
 *
 * - Open Android Keystore.
 * - Generate AES encryption keys.
 * - Retrieve Keystore-backed SecretKeys.
 * - Check whether a key exists.
 * - Delete keys.
 * - Validate SentriX key aliases.
 * - Enumerate SentriX-managed keys.
 *
 * This class intentionally does NOT:
 *
 * - Encrypt application data.
 * - Decrypt application data.
 * - Store keys in files.
 * - Store keys in Room.
 * - Store keys in SharedPreferences.
 * - Store keys in DataStore.
 * - Export raw key material.
 * - Perform network operations.
 *
 * Android Keystore is the authoritative storage mechanism.
 *
 * Architecture:
 *
 *      EncryptionKeyManager
 *               │
 *               ▼
 *      EncryptionKeyStore
 *               │
 *               ▼
 *        Android Keystore
 */
object EncryptionKeyStore {

    // -------------------------------------------------------------------------
    // Android Keystore Configuration
    // -------------------------------------------------------------------------

    /**
     * Android system Keystore provider.
     */
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /**
     * AES algorithm supported by this key store.
     */
    private const val KEY_ALGORITHM =
        KeyProperties.KEY_ALGORITHM_AES

    /**
     * AES-256 key size.
     */
    private const val KEY_SIZE = 256

    /**
     * GCM block mode.
     */
    private const val BLOCK_MODE =
        KeyProperties.BLOCK_MODE_GCM

    /**
     * GCM uses no traditional block padding.
     */
    private const val ENCRYPTION_PADDING =
        KeyProperties.ENCRYPTION_PADDING_NONE

    /**
     * Namespace for all SentriX-managed Keystore aliases.
     *
     * Keeping a dedicated namespace prevents this class from
     * accidentally manipulating unrelated application keys.
     */
    private const val SENTRIX_ALIAS_PREFIX = "SentriX_"

    // -------------------------------------------------------------------------
    // KeyStore Initialization
    // -------------------------------------------------------------------------

    /**
     * Lazily initialized Android Keystore instance.
     *
     * Keystore initialization is deferred until it is actually required.
     */
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(
            ANDROID_KEYSTORE
        ).apply {
            load(null)
        }
    }

    // -------------------------------------------------------------------------
    // Key Generation
    // -------------------------------------------------------------------------

    /**
     * Generates an AES-256-GCM key and stores it directly inside
     * Android Keystore.
     *
     * If a key with the supplied alias already exists, the existing
     * key is returned instead of generating another one.
     *
     * @param alias SentriX-managed key alias.
     *
     * @return Keystore-backed SecretKey.
     */
    @Synchronized
    fun getOrCreateKey(
        alias: String
    ): SecretKey {

        validateAlias(alias)

        getKeyOrNull(alias)?.let { existingKey ->
            return existingKey
        }

        return generateKey(
            alias
        )
    }

    /**
     * Generates a new AES-256-GCM key.
     *
     * This method expects the alias not to already exist.
     */
    @Synchronized
    fun generateKey(
        alias: String
    ): SecretKey {

        validateAlias(alias)

        if (containsKey(alias)) {
            throw IllegalStateException(
                "Encryption key already exists for alias: $alias"
            )
        }

        return try {

            val keyGenerator = KeyGenerator.getInstance(
                KEY_ALGORITHM,
                ANDROID_KEYSTORE
            )

            val keySpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or
                        KeyProperties.PURPOSE_DECRYPT
            )
                /**
                 * AES-256 symmetric encryption key.
                 */
                .setKeySize(KEY_SIZE)

                /**
                 * Restrict the key to GCM mode.
                 */
                .setBlockModes(
                    BLOCK_MODE
                )

                /**
                 * GCM does not require PKCS padding.
                 */
                .setEncryptionPaddings(
                    ENCRYPTION_PADDING
                )

                /**
                 * Forces cryptographic operations to use
                 * randomized encryption.
                 *
                 * This protects against accidental IV reuse.
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

            throw KeyStoreException(
                message = "Unable to generate encryption key.",
                cause = exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Key Retrieval
    // -------------------------------------------------------------------------

    /**
     * Retrieves a Keystore-backed SecretKey.
     *
     * Returns null if the requested key does not exist.
     */
    fun getKeyOrNull(
        alias: String
    ): SecretKey? {

        validateAlias(alias)

        return try {

            val entry = keyStore.getEntry(
                alias,
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

        } catch (exception: Exception) {

            throw KeyStoreException(
                message = "Unable to retrieve encryption key.",
                cause = exception
            )
        }
    }

    /**
     * Retrieves a required encryption key.
     *
     * Throws a controlled exception when the key is unavailable.
     */
    fun getKey(
        alias: String
    ): SecretKey {

        return getKeyOrNull(
            alias
        ) ?: throw KeyNotFoundException(
            "Encryption key not found for alias: $alias"
        )
    }

    // -------------------------------------------------------------------------
    // Key Availability
    // -------------------------------------------------------------------------

    /**
     * Checks whether a key exists in Android Keystore.
     */
    fun containsKey(
        alias: String
    ): Boolean {

        validateAlias(alias)

        return try {
            keyStore.containsAlias(
                alias
            )
        } catch (exception: Exception) {

            throw KeyStoreException(
                message = "Unable to inspect encryption key.",
                cause = exception
            )
        }
    }

    /**
     * Returns the number of SentriX-managed keys.
     */
    fun getSentriXKeyCount(): Int {
        return getSentriXKeyAliases().size
    }

    // -------------------------------------------------------------------------
    // Key Deletion
    // -------------------------------------------------------------------------

    /**
     * Deletes a specific SentriX encryption key.
     *
     * WARNING:
     *
     * Any data encrypted using this key may become permanently
     * undecryptable.
     */
    @Synchronized
    fun deleteKey(
        alias: String
    ) {

        validateAlias(alias)

        try {

            if (keyStore.containsAlias(alias)) {

                keyStore.deleteEntry(
                    alias
                )
            }

        } catch (exception: Exception) {

            throw KeyStoreException(
                message = "Unable to delete encryption key.",
                cause = exception
            )
        }
    }

    /**
     * Deletes all SentriX-managed keys.
     *
     * This is a destructive operation.
     *
     * Intended only for:
     *
     * - Enterprise wipe
     * - Secure application reset
     * - Security incident response
     * - Controlled cryptographic reset
     *
     * The caller is responsible for ensuring that all dependent
     * encrypted data has already been handled.
     */
    @Synchronized
    fun deleteAllSentriXKeys() {

        val aliases = getSentriXKeyAliases()

        aliases.forEach { alias ->

            try {

                keyStore.deleteEntry(
                    alias
                )

            } catch (exception: Exception) {

                throw KeyStoreException(
                    message = "Unable to delete key: $alias",
                    cause = exception
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // Key Enumeration
    // -------------------------------------------------------------------------

    /**
     * Returns every Keystore alias owned by SentriX.
     *
     * Only aliases beginning with "SentriX_" are returned.
     */
    fun getSentriXKeyAliases(): List<String> {

        return try {

            val aliases = keyStore.aliases()

            aliases.toList()
                .filter { alias ->
                    alias.startsWith(
                        SENTRIX_ALIAS_PREFIX
                    )
                }
                .sorted()

        } catch (exception: Exception) {

            throw KeyStoreException(
                message = "Unable to enumerate SentriX keys.",
                cause = exception
            )
        }
    }

    /**
     * Returns true when at least one SentriX-managed key exists.
     */
    fun hasAnySentriXKey(): Boolean {
        return getSentriXKeyAliases().isNotEmpty()
    }

    // -------------------------------------------------------------------------
    // Key Validation
    // -------------------------------------------------------------------------

    /**
     * Performs structural validation of a key.
     *
     * This does not attempt to extract the raw AES key material.
     *
     * Android Keystore-backed keys may intentionally return null from
     * SecretKey.getEncoded(), so raw encoded-key inspection is avoided.
     */
    fun validateKey(
        alias: String
    ): KeyStoreKeyValidationResult {

        validateAlias(alias)

        val key = getKeyOrNull(alias)
            ?: return KeyStoreKeyValidationResult.NotFound

        if (!key.algorithm.equals(
                KEY_ALGORITHM,
                ignoreCase = true
            )
        ) {
            return KeyStoreKeyValidationResult.Invalid(
                "Key algorithm is not AES."
            )
        }

        return KeyStoreKeyValidationResult.Valid
    }

    /**
     * Validates every SentriX-managed key.
     *
     * Returns only aliases whose keys are invalid or unavailable.
     */
    fun findInvalidKeys(): List<String> {

        return getSentriXKeyAliases()
            .filter { alias ->

                when (
                    validateKey(alias)
                ) {

                    KeyStoreKeyValidationResult.Valid -> {
                        false
                    }

                    else -> {
                        true
                    }
                }
            }
    }

    // -------------------------------------------------------------------------
    // Key Metadata
    // -------------------------------------------------------------------------

    /**
     * Returns the Android Keystore provider name.
     */
    fun getProviderName(): String {
        return ANDROID_KEYSTORE
    }

    /**
     * Returns the algorithm used by SentriX encryption keys.
     */
    fun getKeyAlgorithm(): String {
        return KEY_ALGORITHM
    }

    /**
     * Returns the configured key size.
     */
    fun getKeySize(): Int {
        return KEY_SIZE
    }

    /**
     * Returns the configured block mode.
     */
    fun getBlockMode(): String {
        return BLOCK_MODE
    }

    /**
     * Returns the configured encryption padding.
     */
    fun getEncryptionPadding(): String {
        return ENCRYPTION_PADDING
    }

    /**
     * Determines whether an alias belongs to SentriX.
     */
    fun isSentriXAlias(
        alias: String
    ): Boolean {

        return alias.startsWith(
            SENTRIX_ALIAS_PREFIX
        )
    }

    // -------------------------------------------------------------------------
    // Alias Validation
    // -------------------------------------------------------------------------

    /**
     * Prevents callers from manipulating arbitrary Android Keystore
     * aliases through this SentriX abstraction.
     */
    private fun validateAlias(
        alias: String
    ) {

        require(alias.isNotBlank()) {
            "Encryption key alias cannot be blank."
        }

        require(
            alias.startsWith(
                SENTRIX_ALIAS_PREFIX
            )
        ) {
            "Encryption key alias must belong to SentriX."
        }
    }
}

/**
 * Result of validating a Keystore-backed encryption key.
 */
sealed class KeyStoreKeyValidationResult {

    /**
     * Key exists and uses the expected AES algorithm.
     */
    data object Valid : KeyStoreKeyValidationResult()

    /**
     * No key exists for the requested alias.
     */
    data object NotFound : KeyStoreKeyValidationResult()

    /**
     * Key exists but does not meet the expected configuration.
     */
    data class Invalid(
        val reason: String
    ) : KeyStoreKeyValidationResult()
}

/**
 * Exception thrown when an encryption key cannot be located.
 */
class KeyNotFoundException(
    message: String
) : IllegalStateException(message)

/**
 * Exception representing an Android Keystore operation failure.
 *
 * The underlying cause is retained for internal diagnostics while
 * the public message remains generic.
 */
class KeyStoreException(
    message: String,
    cause: Throwable? = null
) : IllegalStateException(
    message,
    cause
)
