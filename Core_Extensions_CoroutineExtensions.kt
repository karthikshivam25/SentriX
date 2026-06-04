package com.sentrix.core.extensions

import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext

/**
 * Coroutine Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Dispatcher Helpers
 * ------------------------------------------------------------------------- */

suspend inline fun <T> withIo(
    crossinline block: suspend CoroutineScope.() -> T
): T {
    return withContext(Dispatchers.IO) {
        block()
    }
}

suspend inline fun <T> withDefault(
    crossinline block: suspend CoroutineScope.() -> T
): T {
    return withContext(Dispatchers.Default) {
        block()
    }
}

suspend inline fun <T> withMain(
    crossinline block: suspend CoroutineScope.() -> T
): T {
    return withContext(Dispatchers.Main) {
        block()
    }
}

suspend inline fun <T> withUnconfined(
    crossinline block: suspend CoroutineScope.() -> T
): T {
    return withContext(Dispatchers.Unconfined) {
        block()
    }
}

/* -------------------------------------------------------------------------
 * Scope Launch Helpers
 * ------------------------------------------------------------------------- */

fun CoroutineScope.launchIo(
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launch(Dispatchers.IO) {
        block()
    }
}

fun CoroutineScope.launchDefault(
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launch(Dispatchers.Default) {
        block()
    }
}

fun CoroutineScope.launchMain(
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launch(Dispatchers.Main) {
        block()
    }
}

/* -------------------------------------------------------------------------
 * Async Helpers
 * ------------------------------------------------------------------------- */

fun <T> CoroutineScope.asyncIo(
    block: suspend CoroutineScope.() -> T
): Deferred<T> {
    return async(Dispatchers.IO) {
        block()
    }
}

fun <T> CoroutineScope.asyncDefault(
    block: suspend CoroutineScope.() -> T
): Deferred<T> {
    return async(Dispatchers.Default) {
        block()
    }
}

/* -------------------------------------------------------------------------
 * Safe Launch
 * ------------------------------------------------------------------------- */

fun CoroutineScope.launchSafe(
    context: CoroutineContext = Dispatchers.IO,
    onError: (Throwable) -> Unit = {},
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launch(context) {
        try {
            block()
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (exception: Exception) {
            onError(exception)
        }
    }
}

/* -------------------------------------------------------------------------
 * Retry Helpers
 * ------------------------------------------------------------------------- */

suspend fun <T> retryOperation(
    retries: Int = 3,
    delayMillis: Long = 1000L,
    block: suspend () -> T
): T {

    repeat(retries - 1) {
        try {
            return block()
        } catch (_: Exception) {
            delay(delayMillis)
        }
    }

    return block()
}

/* -------------------------------------------------------------------------
 * Timeout Helpers
 * ------------------------------------------------------------------------- */

suspend fun <T> runWithTimeout(
    timeoutMillis: Long,
    block: suspend CoroutineScope.() -> T
): T? {
    return withTimeoutOrNull(timeoutMillis) {
        block()
    }
}

/* -------------------------------------------------------------------------
 * Delay Helpers
 * ------------------------------------------------------------------------- */

fun CoroutineScope.launchDelayed(
    delayMillis: Long,
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launch {
        delay(delayMillis)
        block()
    }
}

suspend fun waitFor(
    delayMillis: Long
) {
    delay(delayMillis)
}

/* -------------------------------------------------------------------------
 * Parallel Execution Helpers
 * ------------------------------------------------------------------------- */

suspend fun <A, B> parallel(
    taskA: suspend () -> A,
    taskB: suspend () -> B
): Pair<A, B> = coroutineScope {

    val first = async { taskA() }
    val second = async { taskB() }

    Pair(
        first.await(),
        second.await()
    )
}

suspend fun <A, B, C> parallel(
    taskA: suspend () -> A,
    taskB: suspend () -> B,
    taskC: suspend () -> C
): Triple<A, B, C> = coroutineScope {

    val first = async { taskA() }
    val second = async { taskB() }
    val third = async { taskC() }

    Triple(
        first.await(),
        second.await(),
        third.await()
    )
}

/* -------------------------------------------------------------------------
 * Job Helpers
 * ------------------------------------------------------------------------- */

fun Job?.cancelSafely() {
    this?.takeIf { it.isActive }?.cancel()
}

fun Job?.isRunning(): Boolean {
    return this?.isActive == true
}

fun Job?.isCompletedSafely(): Boolean {
    return this?.isCompleted == true
}

/* -------------------------------------------------------------------------
 * Deferred Helpers
 * ------------------------------------------------------------------------- */

suspend fun <T> Deferred<T>.awaitOrNull(): T? {
    return try {
        await()
    } catch (_: Exception) {
        null
    }
}

/* -------------------------------------------------------------------------
 * Security Task Helpers
 * ------------------------------------------------------------------------- */

fun CoroutineScope.launchThreatScan(
    onError: (Throwable) -> Unit = {},
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launchSafe(
        context = Dispatchers.IO,
        onError = onError,
        block = block
    )
}

fun CoroutineScope.launchFileAnalysis(
    onError: (Throwable) -> Unit = {},
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launchSafe(
        context = Dispatchers.Default,
        onError = onError,
        block = block
    )
}

fun CoroutineScope.launchNetworkMonitor(
    onError: (Throwable) -> Unit = {},
    block: suspend CoroutineScope.() -> Unit
): Job {
    return launchSafe(
        context = Dispatchers.IO,
        onError = onError,
        block = block
    )
}

/* -------------------------------------------------------------------------
 * Supervisor Helpers
 * ------------------------------------------------------------------------- */

fun createSupervisorScope(): CoroutineScope {
    return CoroutineScope(
        SupervisorJob() + Dispatchers.IO
    )
}

suspend fun runSupervisor(
    block: suspend CoroutineScope.() -> Unit
) {
    supervisorScope {
        block()
    }
}

/* -------------------------------------------------------------------------
 * Utility Helpers
 * ------------------------------------------------------------------------- */

fun CoroutineScope.cancelChildrenSafely() {
    coroutineContext.cancelChildren()
}

fun CoroutineScope.isActiveScope(): Boolean {
    return coroutineContext[Job]?.isActive == true
}

suspend fun <T> measureExecutionTime(
    block: suspend () -> T
): Pair<T, Long> {

    val start = System.currentTimeMillis()

    val result = block()

    val end = System.currentTimeMillis()

    return Pair(
        result,
        end - start
    )
}
