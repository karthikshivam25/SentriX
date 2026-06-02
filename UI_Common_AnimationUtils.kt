package com.sentrix.ui.common

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.EaseInOut
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.keyframes
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale

object AnimationUtils {

    // ----------------------------------------------------------------
    // FADE IN ANIMATION
    // ----------------------------------------------------------------

    @Composable
    fun fadeInAnimation(): EnterTransition {

        return fadeIn(
            animationSpec = tween(
                durationMillis =
                UIConstants.AnimationDurationMedium
            )
        )
    }

    // ----------------------------------------------------------------
    // FADE OUT ANIMATION
    // ----------------------------------------------------------------

    @Composable
    fun fadeOutAnimation(): ExitTransition {

        return fadeOut(
            animationSpec = tween(
                durationMillis =
                UIConstants.AnimationDurationShort
            )
        )
    }

    // ----------------------------------------------------------------
    // SLIDE UP ANIMATION
    // ----------------------------------------------------------------

    @Composable
    fun slideUpAnimation(): EnterTransition {

        return slideInVertically(
            initialOffsetY = { it / 2 },
            animationSpec = tween(
                durationMillis = 600,
                easing = FastOutSlowInEasing
            )
        )
    }

    // ----------------------------------------------------------------
    // SLIDE DOWN EXIT
    // ----------------------------------------------------------------

    @Composable
    fun slideDownExitAnimation(): ExitTransition {

        return slideOutVertically(
            targetOffsetY = { it / 2 },
            animationSpec = tween(
                durationMillis = 400
            )
        )
    }

    // ----------------------------------------------------------------
    // SCALE IN ANIMATION
    // ----------------------------------------------------------------

    @Composable
    fun scaleInAnimation(): EnterTransition {

        return scaleIn(
            initialScale = 0.92f,
            animationSpec = spring(
                dampingRatio =
                Spring.DampingRatioMediumBouncy,
                stiffness =
                Spring.StiffnessLow
            )
        )
    }

    // ----------------------------------------------------------------
    // SCALE OUT ANIMATION
    // ----------------------------------------------------------------

    @Composable
    fun scaleOutAnimation(): ExitTransition {

        return scaleOut(
            targetScale = 0.92f,
            animationSpec = tween(
                durationMillis = 250
            )
        )
    }

    // ----------------------------------------------------------------
    // EXPAND ANIMATION
    // ----------------------------------------------------------------

    @Composable
    fun expandAnimation(): EnterTransition {

        return expandVertically(
            animationSpec = tween(
                durationMillis = 500,
                easing = EaseInOut
            )
        )
    }

    // ----------------------------------------------------------------
    // FLOATING EFFECT
    // ----------------------------------------------------------------

    @Composable
    fun floatingModifier(
        modifier: Modifier = Modifier
    ): Modifier {

        val infiniteTransition =
            rememberInfiniteTransition(
                label = "floating_animation"
            )

        val scale by infiniteTransition.animateFloat(
            initialValue = 1f,
            targetValue = 1.03f,
            animationSpec = infiniteRepeatable(
                animation = tween(
                    durationMillis = 1800,
                    easing = EaseInOut
                ),
                repeatMode = RepeatMode.Reverse
            ),
            label = "floating_scale"
        )

        return modifier.scale(scale)
    }

    // ----------------------------------------------------------------
    // PULSE EFFECT
    // ----------------------------------------------------------------

    @Composable
    fun pulseModifier(
        modifier: Modifier = Modifier
    ): Modifier {

        val infiniteTransition =
            rememberInfiniteTransition(
                label = "pulse_animation"
            )

        val alpha by infiniteTransition.animateFloat(
            initialValue = 0.65f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(
                    durationMillis = 1000,
                    easing = LinearEasing
                ),
                repeatMode = RepeatMode.Reverse
            ),
            label = "pulse_alpha"
        )

        return modifier.alpha(alpha)
    }

    // ----------------------------------------------------------------
    // ROTATION EFFECT
    // ----------------------------------------------------------------

    @Composable
    fun rotatingModifier(
        modifier: Modifier = Modifier
    ): Modifier {

        val infiniteTransition =
            rememberInfiniteTransition(
                label = "rotation_animation"
            )

        val rotation by infiniteTransition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(
                    durationMillis = 4000,
                    easing = LinearEasing
                ),
                repeatMode = RepeatMode.Restart
            ),
            label = "rotation"
        )

        return modifier.rotate(rotation)
    }

    // ----------------------------------------------------------------
    // SHIMMER EFFECT
    // ----------------------------------------------------------------

    @Composable
    fun shimmerAlpha(): Float {

        val infiniteTransition =
            rememberInfiniteTransition(
                label = "shimmer_animation"
            )

        val alpha by infiniteTransition.animateFloat(
            initialValue = 0.25f,
            targetValue = 0.95f,
            animationSpec = infiniteRepeatable(
                animation = keyframes {

                    durationMillis = 1400

                    0.25f at 0
                    0.95f at 700
                    0.25f at 1400
                },
                repeatMode = RepeatMode.Restart
            ),
            label = "shimmer_alpha"
        )

        return alpha
    }

    // ----------------------------------------------------------------
    // ANIMATED VISIBILITY WRAPPER
    // ----------------------------------------------------------------

    @Composable
    fun SentrixAnimatedVisibility(
        visible: Boolean,
        content: @Composable () -> Unit
    ) {

        AnimatedVisibility(
            visible = visible,
            enter =
            fadeInAnimation() +
                    slideUpAnimation() +
                    scaleInAnimation(),

            exit =
            fadeOutAnimation() +
                    slideDownExitAnimation() +
                    scaleOutAnimation()
        ) {

            content()
        }
    }

    // ----------------------------------------------------------------
    // ANIMATABLE FLOAT
    // ----------------------------------------------------------------

    fun createAnimatableFloat(
        initialValue: Float = 0f
    ): Animatable<Float, *> {

        return Animatable(initialValue)
    }
}
