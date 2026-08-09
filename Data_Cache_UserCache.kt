package com.sentrix.data.cache

import com.sentrix.domain.models.User
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SentriX - User Cache
 *
 * Package:
 * com.sentrix.data.cache
 *
 * Responsibility
 * ------------------------------------------------------------
 * Feature-specific cache for user profile and user-related
 * information.
 *
 * UserCache provides a strongly typed abstraction over the
 * generic CacheManager.
 *
 * Cached information can include:
 *
 * - Current user profile.
 * - User profile by user ID.
 * - User profile by email.
 * - User preferences.
 * - User security settings.
 * - User account metadata.
 * - User permissions.
 * - User roles.
 * - User dashboard information.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * UserCache does NOT:
 *
 * - Authenticate users.
 * - Store passwords.
 * - Store access tokens.
 * - Refresh authentication tokens.
 * - Create user accounts.
 * - Modify authentication state.
 * - Perform authorization decisions.
 *
 * Authentication belongs to AuthRepositoryImpl.
 * Session state belongs to SessionRepositoryImpl.
 * Authorization rules belong to the Domain layer.
 *
 * This class only manages cached USER DATA.
 *
 * Clean Architecture:
 *
 * UserRepositoryImpl
 *       │
 *       ▼
 *    UserCache
 *       │
 *       ▼
 *  CacheManager
 *       │
 *       ▼
 * In-Memory Cache
 *
 * Security Principle:
 * ------------------------------------------------------------
 * Sensitive authentication credentials must NEVER be placed
 * into this cache.
 */
@Singleton
class UserCache @Inject constructor(
    private val cacheManager: CacheManager
) {

    // -------------------------------------------------------------------------
    // Cache Namespace
    // -------------------------------------------------------------------------

    /**
     * Dedicated namespace for user-related cache entries.
     */
    private companion object {

        const val PREFIX =
            "user:"

        const val CURRENT_USER_KEY =
            "${PREFIX}current"

        const val USER_PROFILE_PREFIX =
            "${PREFIX}profile:"

        const val USER_EMAIL_PREFIX =
            "${PREFIX}email:"

        const val USER_PREFERENCES_PREFIX =
            "${PREFIX}preferences:"

        const val USER_SECURITY_SETTINGS_PREFIX =
            "${PREFIX}security_settings:"

        const val USER_PERMISSIONS_PREFIX =
            "${PREFIX}permissions:"

        const val USER_ROLES_PREFIX =
            "${PREFIX}roles:"

        const val USER_DASHBOARD_PREFIX =
            "${PREFIX}dashboard:"

        /**
         * User profiles normally do not change every second.
         */
        const val PROFILE_TTL =
            CacheManager.MEDIUM_TTL_MILLIS

        /**
         * Preferences and security settings can be cached
         * slightly longer, but should still be refreshed when
         * explicitly updated.
         */
        const val USER_SETTINGS_TTL =
            CacheManager.MEDIUM_TTL_MILLIS
    }

    // -------------------------------------------------------------------------
    // Current User
    // -------------------------------------------------------------------------

    /**
     * Stores the currently loaded user profile.
     *
     * This represents user DATA only.
     *
     * Authentication credentials must not be stored here.
     */
    fun putCurrentUser(
        user: User,
        ttlMillis: Long = PROFILE_TTL
    ) {

        cacheManager.put(
            key = CURRENT_USER_KEY,
            value = user,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves the current user profile.
     */
    fun getCurrentUser():
        User? {

        return cacheManager.get(
            CURRENT_USER_KEY
        )
    }

    /**
     * Checks whether a current user profile is cached.
     */
    fun containsCurrentUser(): Boolean {

        return cacheManager.contains(
            CURRENT_USER_KEY
        )
    }

    /**
     * Removes the current user profile.
     */
    fun removeCurrentUser(): Boolean {

        return cacheManager.remove(
            CURRENT_USER_KEY
        )
    }

    /**
     * Refreshes the current user profile.
     */
    fun refreshCurrentUser(
        user: User,
        ttlMillis: Long = PROFILE_TTL
    ) {

        cacheManager.refresh(
            key = CURRENT_USER_KEY,
            value = user,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Loads the current user using cache-aside behavior.
     */
    suspend fun getCurrentUserOrLoad(
        ttlMillis: Long = PROFILE_TTL,
        loader: suspend () -> User
    ): User {

        return cacheManager.getOrPut(
            key = CURRENT_USER_KEY,
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // User Profile by ID
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for a user profile.
     */
    private fun userProfileKey(
        userId: String
    ): String {

        return USER_PROFILE_PREFIX +
            userId.trim()
    }

    /**
     * Stores a user profile by user ID.
     */
    fun putUser(
        user: User,
        ttlMillis: Long = PROFILE_TTL
    ) {

        if (user.userId.isBlank()) {
            return
        }

        cacheManager.put(
            key = userProfileKey(
                user.userId
            ),
            value = user,
            ttlMillis = ttlMillis
        )

        /**
         * Keep the current-user cache synchronized when the
         * cached user represents the same user.
         */
        val currentUser =
            getCurrentUser()

        if (
            currentUser?.userId ==
            user.userId
        ) {

            cacheManager.refresh(
                key = CURRENT_USER_KEY,
                value = user,
                ttlMillis = ttlMillis
            )
        }
    }

    /**
     * Retrieves a user profile by ID.
     */
    fun getUser(
        userId: String
    ): User? {

        if (userId.isBlank()) {
            return null
        }

        return cacheManager.get(
            userProfileKey(
                userId
            )
        )
    }

    /**
     * Checks whether a user profile is cached.
     */
    fun containsUser(
        userId: String
    ): Boolean {

        if (userId.isBlank()) {
            return false
        }

        return cacheManager.contains(
            userProfileKey(
                userId
            )
        )
    }

    /**
     * Removes a user profile from cache.
     */
    fun removeUser(
        userId: String
    ): Boolean {

        if (userId.isBlank()) {
            return false
        }

        val removed =
            cacheManager.remove(
                userProfileKey(
                    userId
                )
            )

        val currentUser =
            getCurrentUser()

        if (
            currentUser?.userId ==
            userId
        ) {
            cacheManager.remove(
                CURRENT_USER_KEY
            )
        }

        return removed
    }

    /**
     * Refreshes a user profile.
     */
    fun refreshUser(
        user: User,
        ttlMillis: Long = PROFILE_TTL
    ) {

        if (user.userId.isBlank()) {
            return
        }

        cacheManager.refresh(
            key = userProfileKey(
                user.userId
            ),
            value = user,
            ttlMillis = ttlMillis
        )

        val currentUser =
            getCurrentUser()

        if (
            currentUser?.userId ==
            user.userId
        ) {

            cacheManager.refresh(
                key = CURRENT_USER_KEY,
                value = user,
                ttlMillis = ttlMillis
            )
        }
    }

    /**
     * Loads a user using cache-aside behavior.
     */
    suspend fun getUserOrLoad(
        userId: String,
        ttlMillis: Long = PROFILE_TTL,
        loader: suspend () -> User
    ): User {

        require(userId.isNotBlank()) {
            "User ID cannot be blank."
        }

        return cacheManager.getOrPut(
            key = userProfileKey(
                userId
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // User Profile by Email
    // -------------------------------------------------------------------------

    /**
     * Generates a normalized email cache key.
     *
     * Email is normalized for consistent lookup.
     */
    private fun userEmailKey(
        email: String
    ): String {

        return USER_EMAIL_PREFIX +
            email.trim().lowercase()
    }

    /**
     * Stores a user profile using email as a lookup key.
     *
     * The complete User object is cached, not the password
     * or authentication credentials.
     */
    fun putUserByEmail(
        email: String,
        user: User,
        ttlMillis: Long = PROFILE_TTL
    ) {

        if (
            email.isBlank() ||
            user.userId.isBlank()
        ) {
            return
        }

        cacheManager.put(
            key = userEmailKey(
                email
            ),
            value = user,
            ttlMillis = ttlMillis
        )

        /**
         * Also populate the primary user-ID cache.
         */
        putUser(
            user = user,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves a user using email.
     */
    fun getUserByEmail(
        email: String
    ): User? {

        if (email.isBlank()) {
            return null
        }

        return cacheManager.get(
            userEmailKey(
                email
            )
        )
    }

    /**
     * Checks whether an email lookup is cached.
     */
    fun containsUserByEmail(
        email: String
    ): Boolean {

        if (email.isBlank()) {
            return false
        }

        return cacheManager.contains(
            userEmailKey(
                email
            )
        )
    }

    /**
     * Removes an email-based user cache.
     */
    fun removeUserByEmail(
        email: String
    ): Boolean {

        if (email.isBlank()) {
            return false
        }

        return cacheManager.remove(
            userEmailKey(
                email
            )
        )
    }

    /**
     * Loads a user using an email cache key.
     */
    suspend fun getUserByEmailOrLoad(
        email: String,
        ttlMillis: Long = PROFILE_TTL,
        loader: suspend () -> User
    ): User {

        require(email.isNotBlank()) {
            "Email cannot be blank."
        }

        return cacheManager.getOrPut(
            key = userEmailKey(
                email
            ),
            ttlMillis = ttlMillis
        ) {
            loader()
        }
    }

    // -------------------------------------------------------------------------
    // User Preferences
    // -------------------------------------------------------------------------

    /**
     * Generates a user-preferences cache key.
     */
    private fun preferencesKey(
        userId: String
    ): String {

        return USER_PREFERENCES_PREFIX +
            userId.trim()
    }

    /**
     * Stores user preferences.
     *
     * T is intentionally generic because the concrete
     * UserPreferences domain model may evolve independently.
     */
    fun <T : Any> putPreferences(
        userId: String,
        preferences: T,
        ttlMillis: Long = USER_SETTINGS_TTL
    ) {

        if (userId.isBlank()) {
            return
        }

        cacheManager.put(
            key = preferencesKey(
                userId
            ),
            value = preferences,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached user preferences.
     */
    inline fun <reified T : Any> getPreferences(
        userId: String
    ): T? {

        if (userId.isBlank()) {
            return null
        }

        return cacheManager.get(
            preferencesKey(
                userId
            )
        )
    }

    /**
     * Removes user preferences from cache.
     */
    fun removePreferences(
        userId: String
    ): Boolean {

        if (userId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            preferencesKey(
                userId
            )
        )
    }

    // -------------------------------------------------------------------------
    // User Security Settings
    // -------------------------------------------------------------------------

    /**
     * Generates a cache key for user security settings.
     */
    private fun securitySettingsKey(
        userId: String
    ): String {

        return USER_SECURITY_SETTINGS_PREFIX +
            userId.trim()
    }

    /**
     * Stores user security settings.
     *
     * These settings may contain security-related preferences,
     * but must not contain authentication secrets.
     */
    fun <T : Any> putSecuritySettings(
        userId: String,
        settings: T,
        ttlMillis: Long = USER_SETTINGS_TTL
    ) {

        if (userId.isBlank()) {
            return
        }

        cacheManager.put(
            key = securitySettingsKey(
                userId
            ),
            value = settings,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves user security settings.
     */
    inline fun <reified T : Any> getSecuritySettings(
        userId: String
    ): T? {

        if (userId.isBlank()) {
            return null
        }

        return cacheManager.get(
            securitySettingsKey(
                userId
            )
        )
    }

    /**
     * Removes cached security settings.
     */
    fun removeSecuritySettings(
        userId: String
    ): Boolean {

        if (userId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            securitySettingsKey(
                userId
            )
        )
    }

    // -------------------------------------------------------------------------
    // User Permissions
    // -------------------------------------------------------------------------

    /**
     * Generates a permission cache key.
     */
    private fun permissionsKey(
        userId: String
    ): String {

        return USER_PERMISSIONS_PREFIX +
            userId.trim()
    }

    /**
     * Stores user permissions.
     *
     * Authorization decisions must still be made by the
     * appropriate Domain/application layer.
     */
    fun <T : Any> putPermissions(
        userId: String,
        permissions: T,
        ttlMillis: Long = USER_SETTINGS_TTL
    ) {

        if (userId.isBlank()) {
            return
        }

        cacheManager.put(
            key = permissionsKey(
                userId
            ),
            value = permissions,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached permissions.
     */
    inline fun <reified T : Any> getPermissions(
        userId: String
    ): T? {

        if (userId.isBlank()) {
            return null
        }

        return cacheManager.get(
            permissionsKey(
                userId
            )
        )
    }

    /**
     * Removes cached permissions.
     */
    fun removePermissions(
        userId: String
    ): Boolean {

        if (userId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            permissionsKey(
                userId
            )
        )
    }

    // -------------------------------------------------------------------------
    // User Roles
    // -------------------------------------------------------------------------

    /**
     * Generates a role cache key.
     */
    private fun rolesKey(
        userId: String
    ): String {

        return USER_ROLES_PREFIX +
            userId.trim()
    }

    /**
     * Stores user roles.
     */
    fun <T : Any> putRoles(
        userId: String,
        roles: T,
        ttlMillis: Long = USER_SETTINGS_TTL
    ) {

        if (userId.isBlank()) {
            return
        }

        cacheManager.put(
            key = rolesKey(
                userId
            ),
            value = roles,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves cached user roles.
     */
    inline fun <reified T : Any> getRoles(
        userId: String
    ): T? {

        if (userId.isBlank()) {
            return null
        }

        return cacheManager.get(
            rolesKey(
                userId
            )
        )
    }

    /**
     * Removes cached user roles.
     */
    fun removeRoles(
        userId: String
    ): Boolean {

        if (userId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            rolesKey(
                userId
            )
        )
    }

    // -------------------------------------------------------------------------
    // User Dashboard
    // -------------------------------------------------------------------------

    /**
     * Generates a dashboard cache key.
     */
    private fun dashboardKey(
        userId: String
    ): String {

        return USER_DASHBOARD_PREFIX +
            userId.trim()
    }

    /**
     * Stores user-specific dashboard data.
     *
     * The dashboard data is kept generic because its domain
     * representation can evolve independently.
     */
    fun <T : Any> putDashboard(
        userId: String,
        dashboard: T,
        ttlMillis: Long = CacheManager.SHORT_TTL_MILLIS
    ) {

        if (userId.isBlank()) {
            return
        }

        cacheManager.put(
            key = dashboardKey(
                userId
            ),
            value = dashboard,
            ttlMillis = ttlMillis
        )
    }

    /**
     * Retrieves user dashboard data.
     */
    inline fun <reified T : Any> getDashboard(
        userId: String
    ): T? {

        if (userId.isBlank()) {
            return null
        }

        return cacheManager.get(
            dashboardKey(
                userId
            )
        )
    }

    /**
     * Removes user dashboard data.
     */
    fun removeDashboard(
        userId: String
    ): Boolean {

        if (userId.isBlank()) {
            return false
        }

        return cacheManager.remove(
            dashboardKey(
                userId
            )
        )
    }

    // -------------------------------------------------------------------------
    // User-Level Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates all cached information belonging to one user.
     *
     * This is useful after:
     *
     * - User profile update.
     * - Account settings update.
     * - Permission changes.
     * - Role changes.
     * - Account deletion.
     */
    suspend fun invalidateUser(
        userId: String
    ) {

        if (userId.isBlank()) {
            return
        }

        cacheManager.remove(
            userProfileKey(
                userId
            )
        )

        cacheManager.remove(
            preferencesKey(
                userId
            )
        )

        cacheManager.remove(
            securitySettingsKey(
                userId
            )
        )

        cacheManager.remove(
            permissionsKey(
                userId
            )
        )

        cacheManager.remove(
            rolesKey(
                userId
            )
        )

        cacheManager.remove(
            dashboardKey(
                userId
            )
        )

        val currentUser =
            getCurrentUser()

        if (
            currentUser?.userId ==
            userId
        ) {

            cacheManager.remove(
                CURRENT_USER_KEY
            )
        }

        /**
         * Email-indexed entries are intentionally not guessed
         * here because the cache key should be removed using
         * the known email when available.
         */
    }

    /**
     * Invalidates user data using the known email.
     */
    suspend fun invalidateUser(
        userId: String,
        email: String?
    ) {

        invalidateUser(
            userId = userId
        )

        if (!email.isNullOrBlank()) {

            cacheManager.remove(
                userEmailKey(
                    email
                )
            )
        }
    }

    /**
     * Invalidates all user profiles.
     *
     * This does not clear authentication or session caches.
     */
    suspend fun invalidateProfiles() {

        cacheManager.invalidatePrefix(
            USER_PROFILE_PREFIX
        )

        cacheManager.invalidatePrefix(
            USER_EMAIL_PREFIX
        )

        cacheManager.remove(
            CURRENT_USER_KEY
        )
    }

    /**
     * Invalidates all user settings.
     */
    suspend fun invalidateSettings() {

        cacheManager.invalidatePrefix(
            USER_PREFERENCES_PREFIX
        )

        cacheManager.invalidatePrefix(
            USER_SECURITY_SETTINGS_PREFIX
        )
    }

    /**
     * Invalidates all authorization-related cached data.
     */
    suspend fun invalidateAuthorizationData() {

        cacheManager.invalidatePrefix(
            USER_PERMISSIONS_PREFIX
        )

        cacheManager.invalidatePrefix(
            USER_ROLES_PREFIX
        )
    }

    /**
     * Invalidates all dashboard caches.
     */
    suspend fun invalidateDashboards() {

        cacheManager.invalidatePrefix(
            USER_DASHBOARD_PREFIX
        )
    }

    // -------------------------------------------------------------------------
    // Complete User Cache Invalidation
    // -------------------------------------------------------------------------

    /**
     * Invalidates every UserCache entry.
     *
     * IMPORTANT:
     * This only affects the UserCache namespace.
     *
     * It does not clear:
     *
     * - AuthCache.
     * - SessionCache.
     * - ThreatCache.
     * - VPNCache.
     * - PrivacyCache.
     */
    suspend fun invalidateAll() {

        cacheManager.invalidatePrefix(
            PREFIX
        )
    }

    /**
     * Removes expired user-cache entries.
     */
    suspend fun removeExpiredEntries(): Int {

        return cacheManager.removeExpiredEntries()
    }

    /**
     * Returns global cache statistics.
     */
    fun getStatistics():
        CacheStatistics {

        return cacheManager.getStatistics()
    }
}
