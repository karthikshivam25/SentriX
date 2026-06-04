package com.sentrix.core.extensions

import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import androidx.core.view.isVisible

/**
 * View Visibility Extensions
 */
fun View.show() {
    visibility = View.VISIBLE
}

fun View.hide() {
    visibility = View.GONE
}

fun View.makeInvisible() {
    visibility = View.INVISIBLE
}

fun View.showIf(condition: Boolean) {
    visibility = if (condition) View.VISIBLE else View.GONE
}

fun View.invisibleIf(condition: Boolean) {
    visibility = if (condition) View.INVISIBLE else View.VISIBLE
}

fun View.toggleVisibility() {
    visibility = if (visibility == View.VISIBLE) {
        View.GONE
    } else {
        View.VISIBLE
    }
}

/**
 * Enable / Disable
 */
fun View.enable() {
    isEnabled = true
    alpha = 1f
}

fun View.disable() {
    isEnabled = false
    alpha = 0.5f
}

/**
 * Safe Click Listener
 */
fun View.setSafeClickListener(
    interval: Long = 1000L,
    onSafeClick: (View) -> Unit
) {
    var lastClickTime = 0L

    setOnClickListener {
        val currentTime = SystemClock.elapsedRealtime()

        if (currentTime - lastClickTime >= interval) {
            lastClickTime = currentTime
            onSafeClick(it)
        }
    }
}

/**
 * Fade Animations
 */
fun View.fadeIn(duration: Long = 300L) {
    alpha = 0f
    visibility = View.VISIBLE

    animate()
        .alpha(1f)
        .setDuration(duration)
        .start()
}

fun View.fadeOut(duration: Long = 300L) {
    animate()
        .alpha(0f)
        .setDuration(duration)
        .withEndAction {
            visibility = View.GONE
        }
        .start()
}

/**
 * Scale Animations
 */
fun View.scaleIn(duration: Long = 250L) {
    scaleX = 0.8f
    scaleY = 0.8f
    alpha = 0f
    visibility = View.VISIBLE

    animate()
        .alpha(1f)
        .scaleX(1f)
        .scaleY(1f)
        .setDuration(duration)
        .start()
}

fun View.scaleOut(duration: Long = 250L) {
    animate()
        .alpha(0f)
        .scaleX(0.8f)
        .scaleY(0.8f)
        .setDuration(duration)
        .withEndAction {
            visibility = View.GONE
        }
        .start()
}

/**
 * Padding Helpers
 */
fun View.setPaddingAll(value: Int) {
    setPadding(value, value, value, value)
}

fun View.setHorizontalPadding(value: Int) {
    setPadding(value, paddingTop, value, paddingBottom)
}

fun View.setVerticalPadding(value: Int) {
    setPadding(paddingLeft, value, paddingRight, value)
}

/**
 * Margin Helpers
 */
fun View.setMargins(
    left: Int = 0,
    top: Int = 0,
    right: Int = 0,
    bottom: Int = 0
) {
    val params = layoutParams

    if (params is ViewGroup.MarginLayoutParams) {
        params.setMargins(left, top, right, bottom)
        layoutParams = params
    }
}

/**
 * Rotation Helper
 */
fun View.rotate(
    angle: Float,
    duration: Long = 300L
) {
    animate()
        .rotation(angle)
        .setDuration(duration)
        .start()
}

/**
 * View State Helpers
 */
fun View.isShownView(): Boolean {
    return visibility == View.VISIBLE
}

fun View.isHiddenView(): Boolean {
    return visibility == View.GONE
}

fun View.isInvisibleView(): Boolean {
    return visibility == View.INVISIBLE
}

/**
 * Toggle Enable State
 */
fun View.toggleEnabled() {
    isEnabled = !isEnabled
}

/**
 * Prevent Multiple Rapid Taps
 */
fun View.singleClick(
    delay: Long = 800L,
    action: () -> Unit
) {
    setSafeClickListener(delay) {
        action()
    }
}
