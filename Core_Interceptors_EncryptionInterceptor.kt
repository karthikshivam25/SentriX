package com.sentrix.core.interceptors

import com.sentrix.core.helpers.EncryptionHelper
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.Buffer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Interceptor responsible for encrypting outgoing request bodies
 * and marking requests that contain encrypted payloads.
 *
 * Note:
 * - Only encrypts requests with a body.
 * - Skips multipart/form-data requests.
 * - Requires EncryptionHelper implementation.
 */
@Singleton
class EncryptionInterceptor @Inject constructor(
    private val encryptionHelper: EncryptionHelper
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {

        val originalRequest = chain.request()
        val requestBody = originalRequest.body

        if (requestBody == null) {
            return chain.proceed(originalRequest)
        }

        val contentType = requestBody.contentType()?.toString().orEmpty()

        // Skip file uploads and multipart requests
        if (contentType.contains("multipart", ignoreCase = true)) {
            return chain.proceed(originalRequest)
        }

        return try {

            val buffer = Buffer()
            requestBody.writeTo(buffer)

            val originalPayload = buffer.readUtf8()

            val encryptedPayload =
                encryptionHelper.encrypt(originalPayload)

            val encryptedRequestBody = encryptedPayload
                .toRequestBody(
                    "application/octet-stream"
                        .toMediaTypeOrNull()
                )

            val encryptedRequest = originalRequest.newBuilder()
                .header("X-Encrypted", "true")
                .method(
                    originalRequest.method,
                    encryptedRequestBody
                )
                .build()

            chain.proceed(encryptedRequest)

        } catch (exception: Exception) {

            throw SecurityException(
                "Failed to encrypt request body",
                exception
            )
        }
    }
}
