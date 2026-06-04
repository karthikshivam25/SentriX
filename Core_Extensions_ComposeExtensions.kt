package com.sentrix.core.extensions

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.AnimationVector1D
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * SentriX Compose Extensions
 */

/**
 * Safe Click Modifier
 */
fun Modifier.safeClickable(
    debounceTime: Long = 1000L,
    onClick: () -> Unit
): Modifier = composed {

    var lastClickTime by remember { mutableStateOf(0L) }

    clickable(
        indication = null,
        interactionSource = remember { MutableInteractionSource() }
    ) {
        val currentTime = System.currentTimeMillis()

        if (currentTime - lastClickTime > debounceTime) {
            lastClickTime = currentTime
            onClick()
        }
    }
}

/**
 * Conditional Modifier
 */
inline fun Modifier.applyIf(
    condition: Boolean,
    modifier: Modifier.() -> Modifier
): Modifier {
    return if (condition) {
        then(modifier(Modifier))
    } else {
        this
    }
}

/**
 * Alpha Visibility Modifier
 */
fun Modifier.visible(
    isVisible: Boolean
): Modifier {
    return this.alpha(
        if (isVisible) 1f else 0f
    )
}

/**
 * Remember Boolean State
 */
@Composable
fun rememberBooleanState(
    initialValue: Boolean = false
): MutableState<Boolean> {
    return remember {
        mutableStateOf(initialValue)
    }
}

/**
 * Remember String State
 */
@Composable
fun rememberStringState(
    initialValue: String = ""
): MutableState<String> {
    return remember {
        mutableStateOf(initialValue)
    }
}

/**
 * Remember Int State
 */
@Composable
fun rememberIntState(
    initialValue: Int = 0
): MutableState<Int> {
    return remember {
        mutableStateOf(initialValue)
    }
}

/**
 * Launch Delayed Action
 */
@Composable
fun LaunchDelayedEffect(
    delayMillis: Long,
    action: () -> Unit
) {
    LaunchedEffect(Unit) {
        delay(delayMillis)
        action()
    }
}

/**
 * One-Time Launch Effect
 */
@Composable
fun LaunchOnce(
    action: suspend () -> Unit
) {
    LaunchedEffect(Unit) {
        action()
    }
}

/**
 * Remember Coroutine Launcher
 */
@Composable
fun rememberLaunchAction(
    block: suspend () -> Unit
): () -> Unit {

    val scope = rememberCoroutineScope()

    return remember {
        {
            scope.launch {
                block()
            }
        }
    }
}

/**
 * Toggle State Extension
 */
fun MutableState<Boolean>.toggle() {
    value = !value
}

/**
 * Update State Extension
 */
fun <T> MutableState<T>.update(
    newValue: T
) {
    value = newValue
}

/**
 * Animatable Helpers
 */
suspend fun Animatable<Float, AnimationVector1D>.animateToZero() {
    animateTo(0f)
}

suspend fun Animatable<Float, AnimationVector1D>.animateToOne() {
    animateTo(1f)
}

/**
 * Color Helpers
 */
fun Color.withAlphaValue(
    alpha: Float
): Color {
    return copy(alpha = alpha)
}

/**
 * Dp Helpers
 */
val Int.dpValue
    get() = this.dp

val Float.dpValue
    get() = this.dp

/**
 * Null-Safe Compose State
 */
@Composable
fun <T> rememberState(
    initialValue: T
): MutableState<T> {
    return remember {
        mutableStateOf(initialValue)
    }
}

/**
 * Execute Action If True
 */
inline fun Boolean.ifTrue(
    action: () -> Unit
) {
    if (this) action()
}

/**
 * Execute Action If False
 */
inline fun Boolean.ifFalse(
    action: () -> Unit
) {
    if (!this) action()
}

/**
 * Generic State Mapper
 */
fun <T, R> State<T>.map(
    transform: (T) -> R
): R {
    return transform(value)
}
