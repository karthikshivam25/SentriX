package com.sentrix.security.phishing

import android.content.Context
import android.util.Log
import com.sentrix.domain.models.ScamAnalysis
import com.sentrix.domain.models.URLAnalysis
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PhishingDetectionService
 *
 * Application-level service responsible for executing phishing detection
 * workflows.
 *
 * Responsibilities:
 * - Coordinate phishing URL analysis.
 * - Coordinate phishing content analysis.
 * - Perform quick safety checks.
 * - Handle detection errors safely.
 * - Convert detection failures into controlled service results.
 * - Provide a clean service API for higher-level components.
 *
 * Architectural role:
 *
 * UI / Presentation
 *        |
 *        v
 * Use Case
 *        |
 *        v
 * PhishingDetectionService
 *        |
 *        v
 * PhishingDetectionManager
 *        |
 *        +--> URL Analyzer
 *        +--> Domain Analyzer
 *        +--> Content Analyzer
 *        +--> Risk Evaluator
 *        +--> Threat Intelligence
 *
 * The service should coordinate operations rather than contain complex
 * phishing detection algorithms itself.
 */
class PhishingDetectionService(
    private val context: Context,
    private val detectionManager: PhishingDetectionManager
) {

    companion object {

        private const val TAG = "PhishingDetectionService"

        /**
         * Maximum content size accepted for analysis.
         *
         * Limiting input size helps prevent unnecessarily expensive
         * processing.
         */
        private const val MAX_CONTENT_LENGTH = 100_000

        /**
         * Maximum URL size accepted by the service.
         */
        private const val MAX_URL_LENGTH = 8192
    }

    /**
     * Indicates whether the service has been initialized.
     */
    @Volatile
    private var initialized: Boolean = false

    /**
     * Initializes the phishing detection service.
     */
    fun initialize() {

        if (initialized) {
            Log.d(TAG, "Phishing detection service is already initialized.")
            return
        }

        try {

            Log.i(
                TAG,
                "Initializing phishing detection service."
            )

            detectionManager.initialize()

            initialized = true

            Log.i(
                TAG,
                "Phishing detection service initialized successfully."
            )

        } catch (exception: Exception) {

            initialized = false

            Log.e(
                TAG,
                "Failed to initialize phishing detection service.",
                exception
            )

            throw exception
        }
    }

    /**
     * Enables phishing protection.
     */
    fun enableProtection() {

        ensureInitialized()

        detectionManager.enableProtection()

        Log.i(
            TAG,
            "Phishing protection enabled through service."
        )
    }

    /**
     * Disables phishing protection.
     */
    fun disableProtection() {

        detectionManager.disableProtection()

        Log.w(
            TAG,
            "Phishing protection disabled through service."
        )
    }

    /**
     * Returns whether phishing protection is enabled.
     */
    fun isProtectionEnabled(): Boolean {
        return detectionManager.isProtectionEnabled()
    }

    /**
     * Performs complete phishing analysis on a URL.
     *
     * This is the primary service API for URL-based phishing detection.
     *
     * @param url URL to analyze.
     *
     * @return URLAnalysis containing the phishing risk assessment.
     */
    suspend fun analyzeUrl(
        url: String
    ): URLAnalysis = withContext(Dispatchers.Default) {

        ensureInitialized()

        validateUrl(url)

        checkCancellation()

        Log.d(
            TAG,
            "Starting phishing URL analysis."
        )

        try {

            val result = detectionManager.analyzeUrl(url)

            Log.d(
                TAG,
                "Phishing URL analysis completed. " +
                        "phishing=${result.isPhishing()}, " +
                        "risk=${result.riskScore}"
            )

            result

        } catch (exception: CancellationException) {

            Log.d(
                TAG,
                "Phishing URL analysis cancelled."
            )

            throw exception

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Phishing URL analysis failed.",
                exception
            )

            throw PhishingDetectionException(
                message = "Unable to analyze URL.",
                cause = exception
            )
        }
    }

    /**
     * Performs phishing analysis on arbitrary text/content.
     *
     * Typical sources include:
     *
     * - SMS messages
     * - Emails
     * - Browser text
     * - Notifications
     * - Copied messages
     * - Chat messages
     *
     * @param content text to analyze.
     */
    suspend fun analyzeContent(
        content: String
    ): ScamAnalysis = withContext(Dispatchers.Default) {

        ensureInitialized()

        validateContent(content)

        checkCancellation()

        Log.d(
            TAG,
            "Starting phishing content analysis."
        )

        try {

            val result = detectionManager.analyzeContent(content)

            Log.d(
                TAG,
                "Phishing content analysis completed. " +
                        "scam=${result.isScam()}, " +
                        "risk=${result.riskScore}"
            )

            result

        } catch (exception: CancellationException) {

            Log.d(
                TAG,
                "Phishing content analysis cancelled."
            )

            throw exception

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Phishing content analysis failed.",
                exception
            )

            throw PhishingDetectionException(
                message = "Unable to analyze content.",
                cause = exception
            )
        }
    }

    /**
     * Performs a lightweight phishing URL check.
     *
     * Returns:
     * - true  -> URL is considered phishing.
     * - false -> URL is not currently considered phishing.
     */
    suspend fun isPhishing(
        url: String
    ): Boolean = withContext(Dispatchers.Default) {

        ensureInitialized()

        validateUrl(url)

        checkCancellation()

        try {

            detectionManager.isPhishingUrl(url)

        } catch (exception: CancellationException) {

            throw exception

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Unable to determine phishing status.",
                exception
            )

            throw PhishingDetectionException(
                message = "Unable to determine phishing status.",
                cause = exception
            )
        }
    }

    /**
     * Performs a safe URL check.
     *
     * Returns true only when the phishing engine does not classify the
     * URL as phishing.
     */
    suspend fun isSafe(
        url: String
    ): Boolean = withContext(Dispatchers.Default) {

        ensureInitialized()

        validateUrl(url)

        checkCancellation()

        try {

            detectionManager.isSafeUrl(url)

        } catch (exception: CancellationException) {

            throw exception

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Unable to determine URL safety.",
                exception
            )

            throw PhishingDetectionException(
                message = "Unable to determine URL safety.",
                cause = exception
            )
        }
    }

    /**
     * Analyzes a URL and returns a service-level decision.
     *
     * This method is useful when callers need more than a boolean.
     */
    suspend fun evaluateUrl(
        url: String
    ): PhishingDecision = withContext(Dispatchers.Default) {

        val analysis = analyzeUrl(url)

        createDecision(
            url = url,
            riskScore = analysis.riskScore,
            isPhishing = analysis.isPhishing()
        )
    }

    /**
     * Analyzes content and returns a service-level decision.
     */
    suspend fun evaluateContent(
        content: String
    ): PhishingDecision = withContext(Dispatchers.Default) {

        val analysis = analyzeContent(content)

        createDecision(
            url = null,
            riskScore = analysis.riskScore,
            isPhishing = analysis.isScam()
        )
    }

    /**
     * Returns current phishing protection statistics.
     */
    fun getStatistics(): PhishingDetectionStatistics {

        return detectionManager.getStatistics()
    }

    /**
     * Changes the phishing detection risk threshold.
     *
     * @param threshold value between 0.0 and 1.0.
     */
    fun setRiskThreshold(
        threshold: Float
    ) {

        require(threshold in 0.0f..1.0f) {
            "Risk threshold must be between 0.0 and 1.0."
        }

        detectionManager.setRiskThreshold(threshold)

        Log.i(
            TAG,
            "Phishing risk threshold updated: $threshold"
        )
    }

    /**
     * Returns the currently configured phishing risk threshold.
     */
    fun getRiskThreshold(): Float {
        return detectionManager.getRiskThreshold()
    }

    /**
     * Resets phishing detection statistics.
     */
    fun resetStatistics() {

        detectionManager.resetStatistics()

        Log.d(
            TAG,
            "Phishing statistics reset."
        )
    }

    /**
     * Performs a batch analysis of multiple URLs.
     *
     * Each URL is analyzed independently.
     *
     * Failed individual analyses are represented by a failed
     * BatchPhishingResult rather than terminating the entire batch.
     */
    suspend fun analyzeUrls(
        urls: List<String>
    ): List<BatchPhishingResult> = withContext(Dispatchers.Default) {

        ensureInitialized()

        require(urls.isNotEmpty()) {
            "URL list must not be empty."
        }

        checkCancellation()

        urls.map { url ->

            try {

                validateUrl(url)

                val analysis = analyzeUrl(url)

                BatchPhishingResult(
                    url = url,
                    success = true,
                    analysis = analysis,
                    error = null
                )

            } catch (exception: CancellationException) {

                throw exception

            } catch (exception: Exception) {

                Log.e(
                    TAG,
                    "Failed to analyze URL in batch.",
                    exception
                )

                BatchPhishingResult(
                    url = url,
                    success = false,
                    analysis = null,
                    error = exception.message
                )
            }
        }
    }

    /**
     * Analyzes multiple pieces of content.
     *
     * Useful for scanning collections of messages, notifications or
     * extracted text.
     */
    suspend fun analyzeContents(
        contents: List<String>
    ): List<BatchContentResult> = withContext(Dispatchers.Default) {

        ensureInitialized()

        require(contents.isNotEmpty()) {
            "Content list must not be empty."
        }

        checkCancellation()

        contents.map { content ->

            try {

                validateContent(content)

                val analysis = analyzeContent(content)

                BatchContentResult(
                    content = content,
                    success = true,
                    analysis = analysis,
                    error = null
                )

            } catch (exception: CancellationException) {

                throw exception

            } catch (exception: Exception) {

                Log.e(
                    TAG,
                    "Failed to analyze content in batch.",
                    exception
                )

                BatchContentResult(
                    content = content,
                    success = false,
                    analysis = null,
                    error = exception.message
                )
            }
        }
    }

    /**
     * Returns a high-level phishing protection health status.
     */
    fun getHealthStatus(): PhishingServiceHealth {

        return when {

            !initialized -> {
                PhishingServiceHealth.NOT_INITIALIZED
            }

            !detectionManager.isProtectionEnabled() -> {
                PhishingServiceHealth.DISABLED
            }

            else -> {
                PhishingServiceHealth.HEALTHY
            }
        }
    }

    /**
     * Releases service resources.
     */
    fun shutdown() {

        if (!initialized) {
            return
        }

        try {

            detectionManager.shutdown()

            initialized = false

            Log.i(
                TAG,
                "Phishing detection service shut down."
            )

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Error while shutting down phishing service.",
                exception
            )
        }
    }

    /**
     * Ensures that the service has been initialized.
     */
    private fun ensureInitialized() {

        if (!initialized) {
            initialize()
        }
    }

    /**
     * Validates an incoming URL.
     */
    private fun validateUrl(
        url: String
    ) {

        require(url.isNotBlank()) {
            "URL must not be blank."
        }

        require(url.length <= MAX_URL_LENGTH) {
            "URL exceeds the maximum supported length."
        }

        require(
            url.startsWith(
                "http://",
                ignoreCase = true
            ) ||
                    url.startsWith(
                        "https://",
                        ignoreCase = true
                    )
        ) {
            "Only HTTP and HTTPS URLs are supported."
        }
    }

    /**
     * Validates text before sending it to the detection engine.
     */
    private fun validateContent(
        content: String
    ) {

        require(content.isNotBlank()) {
            "Content must not be blank."
        }

        require(content.length <= MAX_CONTENT_LENGTH) {
            "Content exceeds the maximum supported length."
        }
    }

    /**
     * Checks whether the coroutine has been cancelled.
     */
    private fun checkCancellation() {

        if (!kotlinx.coroutines.currentCoroutineContext().isActive) {
            throw CancellationException(
                "Phishing detection operation was cancelled."
            )
        }
    }

    /**
     * Creates a normalized phishing decision.
     */
    private fun createDecision(
        url: String?,
        riskScore: Float,
        isPhishing: Boolean
    ): PhishingDecision {

        val classification = when {

            riskScore >= 0.90f ->
                PhishingClassification.CRITICAL

            riskScore >= 0.70f ->
                PhishingClassification.HIGH

            riskScore >= 0.40f ->
                PhishingClassification.MEDIUM

            riskScore > 0.0f ->
                PhishingClassification.LOW

            else ->
                PhishingClassification.SAFE
        }

        return PhishingDecision(
            url = url,
            riskScore = riskScore,
            isPhishing = isPhishing,
            classification = classification,
            recommendedAction = when (classification) {

                PhishingClassification.CRITICAL,
                PhishingClassification.HIGH ->
                    PhishingAction.BLOCK

                PhishingClassification.MEDIUM ->
                    PhishingAction.WARN

                PhishingClassification.LOW ->
                    PhishingAction.MONITOR

                PhishingClassification.SAFE ->
                    PhishingAction.ALLOW
            }
        )
    }
}

/**
 * High-level result produced by the phishing detection service.
 */
data class PhishingDecision(

    /**
     * URL associated with the decision.
     *
     * Null when the decision was generated from text/content.
     */
    val url: String?,

    /**
     * Normalized risk score between 0.0 and 1.0.
     */
    val riskScore: Float,

    /**
     * Whether the input has been classified as phishing/scam.
     */
    val isPhishing: Boolean,

    /**
     * Human-readable classification level.
     */
    val classification: PhishingClassification,

    /**
     * Recommended security action.
     */
    val recommendedAction: PhishingAction
)

/**
 * Phishing severity classification.
 */
enum class PhishingClassification {

    SAFE,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Action recommended by the phishing engine.
 */
enum class PhishingAction {

    /**
     * Permit the URL/content.
     */
    ALLOW,

    /**
     * Allow but continue monitoring.
     */
    MONITOR,

    /**
     * Display a security warning.
     */
    WARN,

    /**
     * Prevent access or interaction.
     */
    BLOCK
}

/**
 * Result of an individual URL analysis in a batch operation.
 */
data class BatchPhishingResult(

    val url: String,

    val success: Boolean,

    val analysis: URLAnalysis?,

    val error: String?
)

/**
 * Result of an individual content analysis in a batch operation.
 */
data class BatchContentResult(

    val content: String,

    val success: Boolean,

    val analysis: ScamAnalysis?,

    val error: String?
)

/**
 * Health state of the phishing detection service.
 */
enum class PhishingServiceHealth {

    /**
     * Service has not been initialized.
     */
    NOT_INITIALIZED,

    /**
     * Service is initialized and operational.
     */
    HEALTHY,

    /**
     * Service is operational but protection is disabled.
     */
    DISABLED
}

/**
 * Domain-specific exception for phishing detection failures.
 */
class PhishingDetectionException(
    message: String,
    cause: Throwable? = null
) : RuntimeException(
    message,
    cause
)
