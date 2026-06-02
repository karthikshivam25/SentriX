package com.sentrix.ui.common

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

// ----------------------------------------------------------------
// CLICK EFFECT
// ----------------------------------------------------------------

fun Modifier.sentrixClickable(
    onClick: () -> Unit
): Modifier {

    return this.clickable(
        interactionSource = remember {
            MutableInteractionSource()
        },
        indication = ripple(),
        onClick = onClick
    )
}

// ----------------------------------------------------------------
// GLASS BACKGROUND
// ----------------------------------------------------------------

fun Modifier.glassBackground(): Modifier {

    return this
        .clip(RoundedCornerShape(24.dp))
        .background(
            brush = Brush.linearGradient(
                colors = listOf(
                    Color.White.copy(alpha = 0.06f),
                    Color.White.copy(alpha = 0.02f)
                )
            )
        )
}

// ----------------------------------------------------------------
// CARD STYLE
// ----------------------------------------------------------------

fun Modifier.sentrixCard(): Modifier {

    return this
        .clip(RoundedCornerShape(22.dp))
        .background(UIConstants.SurfaceDark)
        .padding(18.dp)
}

// ----------------------------------------------------------------
// CYBER GLOW EFFECT
// ----------------------------------------------------------------

fun Modifier.cyberGlow(
    glowColor: Color = UIConstants.SecondaryBlue,
    alpha: Float = 0.18f
): Modifier {

    return this.background(
        color = glowColor.copy(alpha = alpha),
        shape = RoundedCornerShape(22.dp)
    )
}

// ----------------------------------------------------------------
// PULSE ANIMATION
// ----------------------------------------------------------------

@Composable
fun PulseAnimationBox(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "pulse_animation"
    )

    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.04f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1200,
                easing = LinearOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_scale"
    )

    Box(
        modifier = modifier.scale(scale)
    ) {

        content()
    }
}

// ----------------------------------------------------------------
// FADE VISIBILITY
// ----------------------------------------------------------------

@Composable
fun SentrixAnimatedVisibility(
    visible: Boolean,
    content: @Composable () -> Unit
) {

    AnimatedVisibility(
        visible = visible
    ) {

        content()
    }
}

// ----------------------------------------------------------------
// SECURITY STATUS COLOR
// ----------------------------------------------------------------

fun getSecurityStatusColor(
    status: String
): Color {

    return when (status) {

        UIConstants.SECURITY_SECURED -> {
            UIConstants.SuccessGreen
        }

        UIConstants.SECURITY_WARNING -> {
            UIConstants.WarningYellow
        }

        UIConstants.SECURITY_CRITICAL -> {
            UIConstants.DangerRed
        }

        else -> {
            UIConstants.TextMuted
        }
    }
}

// ----------------------------------------------------------------
// THREAT LEVEL COLOR
// ----------------------------------------------------------------

fun getThreatLevelColor(
    level: String
): Color {

    return when (level) {

        UIConstants.THREAT_LOW -> {
            UIConstants.SuccessGreen
        }

        UIConstants.THREAT_MEDIUM -> {
            UIConstants.WarningYellow
        }

        UIConstants.THREAT_HIGH -> {
            UIConstants.DangerRed
        }

        else -> {
            UIConstants.TextMuted
        }
    }
}

// ----------------------------------------------------------------
// ALPHA MODIFIER
// ----------------------------------------------------------------

fun Modifier.sentrixDisabled(
    disabled: Boolean
): Modifier {

    return if (disabled) {
        this.alpha(0.45f)
    } else {
        this
    }
}

// ----------------------------------------------------------------
// PREMIUM GRADIENT
// ----------------------------------------------------------------

fun premiumGradientBrush(): Brush {

    return Brush.linearGradient(
        colors = listOf(
            UIConstants.PrimaryBlue,
            UIConstants.SecondaryBlue
        )
    )
}

// ----------------------------------------------------------------
// CYBER BACKGROUND GRADIENT
// ----------------------------------------------------------------

fun cyberBackgroundBrush(): Brush {

    return Brush.verticalGradient(
        colors = listOf(
            UIConstants.BackgroundDark,
            UIConstants.SurfaceDark,
            UIConstants.CardDark
        )
    )
}
