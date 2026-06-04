package com.sentrix.core.exceptions

/**
 * Exception thrown when a device, file, network,
 * or malware scan operation fails.
 */
class ScanException : Exception {

    constructor() : super()

    constructor(message: String) : super(message)

    constructor(message: String, cause: Throwable) : super(message, cause)

    constructor(cause: Throwable) : super(cause)
}
