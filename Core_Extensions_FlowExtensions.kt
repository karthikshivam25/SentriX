package com.sentrix.core.extensions

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

/**
 * Flow Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Collection Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.launchCollect(
    scope: CoroutineScope,
    action: suspend (T) -> Unit
) {
    scope.launch {
        collect(action)
    }
}

fun <T> Flow<T>.launchCollectLatest(
    scope: CoroutineScope,
    action: suspend (T) -> Unit
) {
    scope.launch {
        collectLatest(action)
    }
}

/* -------------------------------------------------------------------------
 * Filtering Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T?>.filterNotNullValue(): Flow<T> {
    return filterNotNull()
}

fun Flow<String>.filterNotBlank(): Flow<String> {
    return filter { it.isNotBlank() }
}

/* -------------------------------------------------------------------------
 * Debounce Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.debounceSearch(
    timeoutMillis: Long = 500L
): Flow<T> {
    return debounce(timeoutMillis)
}

/* -------------------------------------------------------------------------
 * Distinct Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.distinctValues(): Flow<T> {
    return distinctUntilChanged()
}

/* -------------------------------------------------------------------------
 * Dispatcher Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.onIo(): Flow<T> {
    return flowOn(Dispatchers.IO)
}

fun <T> Flow<T>.onDefault(): Flow<T> {
    return flowOn(Dispatchers.Default)
}

/* -------------------------------------------------------------------------
 * StateFlow Helpers
 * ------------------------------------------------------------------------- */

fun <T> MutableStateFlow<T>.updateState(
    value: T
) {
    this.value = value
}

fun <T> MutableStateFlow<T>.updateIfChanged(
    value: T
) {
    if (this.value != value) {
        this.value = value
    }
}

/* -------------------------------------------------------------------------
 * SharedFlow Helpers
 * ------------------------------------------------------------------------- */

suspend fun <T> MutableSharedFlow<T>.emitEvent(
    value: T
) {
    emit(value)
}

fun <T> MutableSharedFlow<T>.tryEmitEvent(
    value: T
): Boolean {
    return tryEmit(value)
}

/* -------------------------------------------------------------------------
 * Result Wrappers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.catchSafely(
    onError: suspend (Throwable) -> Unit
): Flow<T> {
    return catch { throwable ->
        onError(throwable)
    }
}

fun <T> Flow<T>.retrySafely(
    retries: Long = 3
): Flow<T> {
    return retry(retries)
}

/* -------------------------------------------------------------------------
 * Loading State Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.onLoading(
    action: suspend () -> Unit
): Flow<T> {
    return onStart {
        action()
    }
}

fun <T> Flow<T>.onCompletionAction(
    action: suspend () -> Unit
): Flow<T> {
    return onCompletion {
        action()
    }
}

/* -------------------------------------------------------------------------
 * Mapping Helpers
 * ------------------------------------------------------------------------- */

fun <T, R> Flow<T>.mapSafely(
    transform: suspend (T) -> R
): Flow<R> {
    return map {
        transform(it)
    }
}

fun <T, R> Flow<T>.mapLatestSafely(
    transform: suspend (T) -> R
): Flow<R> {
    return mapLatest {
        transform(it)
    }
}

/* -------------------------------------------------------------------------
 * Side Effect Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.onEachSafely(
    action: suspend (T) -> Unit
): Flow<T> {
    return onEach {
        action(it)
    }
}

/* -------------------------------------------------------------------------
 * State Conversion Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.toStateFlow(
    scope: CoroutineScope,
    initialValue: T
): StateFlow<T> {
    return stateIn(
        scope = scope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = initialValue
    )
}

fun <T> Flow<T>.toSharedFlow(
    scope: CoroutineScope,
    replay: Int = 0
): SharedFlow<T> {
    return shareIn(
        scope = scope,
        started = SharingStarted.WhileSubscribed(5000),
        replay = replay
    )
}

/* -------------------------------------------------------------------------
 * Security Event Helpers
 * ------------------------------------------------------------------------- */

fun <T> Flow<T>.logFlowEvents(
    logger: (String) -> Unit
): Flow<T> {
    return onEach {
        logger("Flow Event: $it")
    }
}

fun <T> Flow<T>.trackThreatEvents(
    tracker: (T) -> Unit
): Flow<T> {
    return onEach {
        tracker(it)
    }
}

/* -------------------------------------------------------------------------
 * Utility Helpers
 * ------------------------------------------------------------------------- */

fun <T> T.asFlowValue(): Flow<T> {
    return flowOf(this)
}

fun <T> List<T>.asFlowList(): Flow<List<T>> {
    return flowOf(this)
}

fun <T> Flow<T>.takeUntil(
    predicate: suspend (T) -> Boolean
): Flow<T> {
    return transformWhile { value ->
        emit(value)
        !predicate(value)
    }
}
