package com.sentrix.core.exceptions

/**
 * Exception thrown when encryption or decryption operations fail.
 */
class EncryptionException : Exception {

    constructor() : super()

    constructor(message: String) : super(message)

    constructor(message: String, cause: Throwable) : super(message, cause)

    constructor(cause: Throwable) : super(cause)
}
