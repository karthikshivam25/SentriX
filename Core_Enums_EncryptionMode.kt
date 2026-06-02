package com.sentrix.core.enums

/**
 * Represents supported encryption modes in SentriX
 */
enum class EncryptionMode(
    val algorithm: String,
    val displayName: String,
    val description: String
) {

    AES_128(
        algorithm = "AES-128",
        displayName = "AES 128-bit",
        description = "Standard symmetric encryption using 128-bit keys"
    ),

    AES_256(
        algorithm = "AES-256",
        displayName = "AES 256-bit",
        description = "Advanced symmetric encryption using 256-bit keys"
    ),

    RSA_2048(
        algorithm = "RSA-2048",
        displayName = "RSA 2048-bit",
        description = "Asymmetric encryption using 2048-bit RSA keys"
    ),

    RSA_4096(
        algorithm = "RSA-4096",
        displayName = "RSA 4096-bit",
        description = "High-security asymmetric encryption using 4096-bit RSA keys"
    ),

    ECC(
        algorithm = "ECC",
        displayName = "Elliptic Curve Cryptography",
        description = "Efficient modern public-key cryptography"
    ),

    CHACHA20(
        algorithm = "ChaCha20",
        displayName = "ChaCha20",
        description = "Fast and secure stream cipher encryption"
    ),

    TLS_1_2(
        algorithm = "TLS 1.2",
        displayName = "TLS 1.2",
        description = "Secure transport layer encryption protocol"
    ),

    TLS_1_3(
        algorithm = "TLS 1.3",
        displayName = "TLS 1.3",
        description = "Latest secure transport layer encryption protocol"
    ),

    END_TO_END(
        algorithm = "E2EE",
        displayName = "End-to-End Encryption",
        description = "Encryption where only communicating users can access data"
    ),

    HASH_SHA256(
        algorithm = "SHA-256",
        displayName = "SHA-256",
        description = "Cryptographic hashing using SHA-256 algorithm"
    ),

    HASH_SHA512(
        algorithm = "SHA-512",
        displayName = "SHA-512",
        description = "Cryptographic hashing using SHA-512 algorithm"
    ),

    NONE(
        algorithm = "NONE",
        displayName = "No Encryption",
        description = "Data is stored or transmitted without encryption"
    );

    /**
     * Returns true if encryption mode is symmetric
     */
    fun isSymmetric(): Boolean {
        return this == AES_128 ||
               this == AES_256 ||
               this == CHACHA20
    }

    /**
     * Returns true if encryption mode is asymmetric
     */
    fun isAsymmetric(): Boolean {
        return this == RSA_2048 ||
               this == RSA_4096 ||
               this == ECC
    }

    /**
     * Returns true if mode is hashing-only
     */
    fun isHashingAlgorithm(): Boolean {
        return this == HASH_SHA256 ||
               this == HASH_SHA512
    }

    /**
     * Returns true if mode provides strong modern security
     */
    fun isRecommended(): Boolean {
        return this == AES_256 ||
               this == RSA_4096 ||
               this == ECC ||
               this == CHACHA20 ||
               this == TLS_1_3 ||
               this == END_TO_END
    }
}
