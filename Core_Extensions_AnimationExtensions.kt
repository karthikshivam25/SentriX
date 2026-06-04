package com.sentrix.core.extensions

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.AlphaAnimation
import android.view.animation.Animation
import android.view.animation.AnimationUtils
import android.view.animation.DecelerateInterpolator
import android.view.animation.LinearInterpolator
import androidx.annotation.AnimRes

/**
 * Animation Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Fade Animations
 * ------------------------------------------------------------------------- */

fun View.fadeIn(
    duration: Long = 300L,
    onEnd: (() -> Unit)? = null
) {
    alpha = 0f
    visibility = View.VISIBLE

    animate()
        .alpha(1f)
        .setDuration(duration)
        .setInterpolator(DecelerateInterpolator())
        .withEndAction {
            onEnd?.invoke()
        }
        .start()
}

fun View.fadeOut(
    duration: Long = 300L,
    onEnd: (() -> Unit)? = null
) {
    animate()
        .alpha(0f)
        .setDuration(duration)
        .setInterpolator(DecelerateInterpolator())
        .withEndAction {
            visibility = View.GONE
            onEnd?.invoke()
        }
        .start()
}

/* -------------------------------------------------------------------------
 * Scale Animations
 * ------------------------------------------------------------------------- */

fun View.scaleIn(
    duration: Long = 300L
) {
    scaleX = 0.8f
    scaleY = 0.8f
    alpha = 0f

    animate()
        .scaleX(1f)
        .scaleY(1f)
        .alpha(1f)
        .setDuration(duration)
        .setInterpolator(DecelerateInterpolator())
        .start()
}

fun View.scaleOut(
    duration: Long = 300L
) {
    animate()
        .scaleX(0.8f)
        .scaleY(0.8f)
        .alpha(0f)
        .setDuration(duration)
        .setInterpolator(DecelerateInterpolator())
        .withEndAction {
            visibility = View.GONE
        }
        .start()
}

/* -------------------------------------------------------------------------
 * Rotation Animations
 * ------------------------------------------------------------------------- */

fun View.rotate(
    degrees: Float,
    duration: Long = 300L
) {
    animate()
        .rotation(degrees)
        .setDuration(duration)
        .setInterpolator(AccelerateDecelerateInterpolator())
        .start()
}

fun View.startInfiniteRotation(
    duration: Long = 2000L
): ObjectAnimator {

    return ObjectAnimator.ofFloat(
        this,
        View.ROTATION,
        0f,
        360f
    ).apply {
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        this.duration = duration
        start()
    }
}

/* -------------------------------------------------------------------------
 * Translation Animations
 * ------------------------------------------------------------------------- */

fun View.slideUp(
    duration: Long = 300L
) {
    translationY = height.toFloat()

    animate()
        .translationY(0f)
        .setDuration(duration)
        .start()
}

fun View.slideDown(
    duration: Long = 300L
) {
    animate()
        .translationY(height.toFloat())
        .setDuration(duration)
        .start()
}

fun View.slideLeft(
    distance: Float = width.toFloat(),
    duration: Long = 300L
) {
    animate()
        .translationX(-distance)
        .setDuration(duration)
        .start()
}

fun View.slideRight(
    distance: Float = width.toFloat(),
    duration: Long = 300L
) {
    animate()
        .translationX(distance)
        .setDuration(duration)
        .start()
}

/* -------------------------------------------------------------------------
 * Pulse Animation
 * ------------------------------------------------------------------------- */

fun View.pulse(
    duration: Long = 600L
) {

    animate()
        .scaleX(1.1f)
        .scaleY(1.1f)
        .setDuration(duration / 2)
        .withEndAction {

            animate()
                .scaleX(1f)
                .scaleY(1f)
                .setDuration(duration / 2)
                .start()
        }
        .start()
}

/* -------------------------------------------------------------------------
 * Shake Animation
 * ------------------------------------------------------------------------- */

fun View.shake(
    duration: Long = 500L
) {

    ObjectAnimator.ofFloat(
        this,
        View.TRANSLATION_X,
        0f,
        25f,
        -25f,
        20f,
        -20f,
        10f,
        -10f,
        0f
    ).apply {
        this.duration = duration
        start()
    }
}

/* -------------------------------------------------------------------------
 * Bounce Animation
 * ------------------------------------------------------------------------- */

fun View.bounce(
    duration: Long = 600L
) {

    animate()
        .translationY(-50f)
        .setDuration(duration / 2)
        .withEndAction {

            animate()
                .translationY(0f)
                .setDuration(duration / 2)
                .start()
        }
        .start()
}

/* -------------------------------------------------------------------------
 * Blink Animation
 * ------------------------------------------------------------------------- */

fun View.blink(
    duration: Long = 500L,
    repeatCount: Int = Animation.INFINITE
): AlphaAnimation {

    return AlphaAnimation(
        1f,
        0f
    ).apply {
        this.duration = duration
        this.repeatMode = Animation.REVERSE
        this.repeatCount = repeatCount
        startAnimation(this)
    }
}

/* -------------------------------------------------------------------------
 * Width / Height Animation
 * ------------------------------------------------------------------------- */

fun View.animateHeight(
    targetHeight: Int,
    duration: Long = 300L
) {

    val startHeight = height

    ValueAnimator.ofInt(
        startHeight,
        targetHeight
    ).apply {

        this.duration = duration

        addUpdateListener { animator ->

            layoutParams.height =
                animator.animatedValue as Int

            requestLayout()
        }

        start()
    }
}

fun View.animateWidth(
    targetWidth: Int,
    duration: Long = 300L
) {

    val startWidth = width

    ValueAnimator.ofInt(
        startWidth,
        targetWidth
    ).apply {

        this.duration = duration

        addUpdateListener { animator ->

            layoutParams.width =
                animator.animatedValue as Int

            requestLayout()
        }

        start()
    }
}

/* -------------------------------------------------------------------------
 * Resource Animation
 * ------------------------------------------------------------------------- */

fun View.startAnimationResource(
    @AnimRes animRes: Int
) {
    startAnimation(
        AnimationUtils.loadAnimation(
            context,
            animRes
        )
    )
}

/* -------------------------------------------------------------------------
 * Visibility Animations
 * ------------------------------------------------------------------------- */

fun View.showAnimated(
    duration: Long = 300L
) {
    visibility = View.VISIBLE
    fadeIn(duration)
}

fun View.hideAnimated(
    duration: Long = 300L
) {
    fadeOut(duration)
}

/* -------------------------------------------------------------------------
 * Security Dashboard Helpers
 * ------------------------------------------------------------------------- */

fun View.threatAlertAnimation() {
    shake()
    pulse()
}

fun View.scanInProgressAnimation(): ObjectAnimator {
    return startInfiniteRotation()
}

fun View.scanCompletedAnimation() {
    bounce()
}

fun View.networkActivityAnimation() {
    blink(duration = 700L)
}

/* -------------------------------------------------------------------------
 * Animation Cleanup
 * ------------------------------------------------------------------------- */

fun View.clearAllAnimations() {
    clearAnimation()
    animate().cancel()
}

fun Animator.onEnd(
    action: () -> Unit
) {
    addListener(
        object : AnimatorListenerAdapter() {
            override fun onAnimationEnd(animation: Animator) {
                action()
            }
        }
    )
}
