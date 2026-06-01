package com.sentrix.ui.theme

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.unit.dp

/*
|--------------------------------------------------------------------------
| SENTRIX EFFECT ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Centralized visual effects engine for SentriX.
|
| This file controls:
|
| ✔ Shadows
| ✔ Glow Effects
| ✔ Glassmorphism
| ✔ Holographic Effects
| ✔ Neon Effects
| ✔ Animated Pulse Effects
| ✔ AI Scanner Effects
| ✔ Cyber Grid Effects
| ✔ Blur Layers
| ✔ Gradient Overlays
| ✔ Threat Alert Animations
| ✔ Floating Panels
| ✔ GPU Friendly Animations
|
|--------------------------------------------------------------------------
| WHY THIS FILE EXISTS
|--------------------------------------------------------------------------
|
| Enterprise applications should NEVER directly hardcode:
|
| - shadows
| - blur values
| - glow layers
| - alpha systems
| - holographic effects
|
| Instead everything must come from a centralized engine.
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SHADOW SYSTEM
   ========================================================= */

object SentriXShadow {

    val Tiny = 2.dp

    val Small = 6.dp

    val Medium = 12.dp

    val Large = 20.dp

    val Huge = 32.dp

    val Massive = 48.dp
}



/* =========================================================
   BLUR SYSTEM
   ========================================================= */

object SentriXBlur {

    val None = 0.dp

    val Light = 4.dp

    val Medium = 10.dp

    val Strong = 18.dp

    val Ultra = 28.dp
}



/* =========================================================
   ALPHA SYSTEM
   ========================================================= */

object SentriXAlpha {

    const val Invisible = 0f

    const val Low = 0.15f

    const val Soft = 0.35f

    const val Medium = 0.55f

    const val High = 0.80f

    const val Full = 1f
}



/* =========================================================
   GLOW COLOR SYSTEM
   ========================================================= */

object GlowColors {

    val Blue = Color(0xFF00B0FF)

    val Cyan = Color(0xFF00E5FF)

    val Purple = Color(0xFF8B5CF6)

    val Green = Color(0xFF00E676)

    val Red = Color(0xFFFF1744)

    val Orange = Color(0xFFFF9100)
}



/* =========================================================
   CYBER GRADIENT EFFECTS
   ========================================================= */

object EffectGradients {

    val CyberGradient = Brush.linearGradient(
        colors = listOf(
            Color(0xFF00E5FF),
            Color(0xFF0066FF),
            Color(0xFF7B2FFF)
        )
    )

    val ThreatGradient = Brush.horizontalGradient(
        colors = listOf(
            Color(0xFFFF1744),
            Color(0xFFFF9100)
        )
    )

    val AIGradient = Brush.linearGradient(
        colors = listOf(
            Color(0xFF00E5FF),
            Color(0xFF7C4DFF)
        )
    )

    val GlassGradient = Brush.verticalGradient(
        colors = listOf(
            Color(0x44FFFFFF),
            Color(0x11FFFFFF)
        )
    )
}



/* =========================================================
   GLASSMORPHISM EFFECTS
   ========================================================= */

object GlassEffects {

    fun glassCardModifier(): Modifier {

        return Modifier
            .clip(RoundedCornerShape(24.dp))
            .background(
                color = Color(0x22FFFFFF)
            )
            .border(
                width = 1.dp,
                color = Color(0x33FFFFFF),
                shape = RoundedCornerShape(24.dp)
            )
            .blur(SentriXBlur.Light)
    }

    fun premiumGlassModifier(): Modifier {

        return Modifier
            .clip(RoundedCornerShape(32.dp))
            .background(
                brush = EffectGradients.GlassGradient
            )
            .border(
                width = 1.2.dp,
                color = Color(0x55FFFFFF),
                shape = RoundedCornerShape(32.dp)
            )
            .shadow(
                elevation = SentriXShadow.Large
            )
    }
}



/* =========================================================
   GLOW EFFECTS
   ========================================================= */

object GlowEffects {

    fun blueGlow(): Modifier {

        return Modifier.shadow(
            elevation = 20.dp,
            ambientColor = GlowColors.Blue,
            spotColor = GlowColors.Blue
        )
    }

    fun cyanGlow(): Modifier {

        return Modifier.shadow(
            elevation = 24.dp,
            ambientColor = GlowColors.Cyan,
            spotColor = GlowColors.Cyan
        )
    }

    fun dangerGlow(): Modifier {

        return Modifier.shadow(
            elevation = 28.dp,
            ambientColor = GlowColors.Red,
            spotColor = GlowColors.Red
        )
    }

    fun AIGlow(): Modifier {

        return Modifier.shadow(
            elevation = 26.dp,
            ambientColor = GlowColors.Purple,
            spotColor = GlowColors.Purple
        )
    }
}



/* =========================================================
   FLOATING PANEL EFFECTS
   ========================================================= */

object FloatingEffects {

    fun floatingCard(): Modifier {

        return Modifier
            .shadow(
                elevation = SentriXShadow.Huge,
                shape = RoundedCornerShape(28.dp)
            )
            .graphicsLayer {

                translationY = -4f
            }
    }

    fun hoverPanel(): Modifier {

        return Modifier.graphicsLayer {

            scaleX = 1.02f

            scaleY = 1.02f
        }
    }
}



/* =========================================================
   NEON BORDER EFFECTS
   ========================================================= */

object NeonEffects {

    fun cyanBorder(): Modifier {

        return Modifier.border(
            width = 1.5.dp,
            brush = Brush.linearGradient(
                colors = listOf(
                    Color(0xFF00E5FF),
                    Color(0xFF0066FF)
                )
            ),
            shape = RoundedCornerShape(18.dp)
        )
    }

    fun dangerBorder(): Modifier {

        return Modifier.border(
            width = 2.dp,
            brush = EffectGradients.ThreatGradient,
            shape = RoundedCornerShape(18.dp)
        )
    }
}



/* =========================================================
   ANIMATED PULSE EFFECTS
   ========================================================= */

object PulseEffects {

    @Composable
    fun pulseAlpha(): Float {

        val infiniteTransition = rememberInfiniteTransition()

        val alpha by infiniteTransition.animateFloat(

            initialValue = 0.4f,

            targetValue = 1f,

            animationSpec = infiniteRepeatable(

                animation = tween(
                    durationMillis = 1200
                ),

                repeatMode = RepeatMode.Reverse
            )
        )

        return alpha
    }

    @Composable
    fun threatPulse(): Float {

        val infiniteTransition = rememberInfiniteTransition()

        val scale by infiniteTransition.animateFloat(

            initialValue = 1f,

            targetValue = 1.08f,

            animationSpec = infiniteRepeatable(

                animation = tween(
                    durationMillis = 800
                ),

                repeatMode = RepeatMode.Reverse
            )
        )

        return scale
    }
}



/* =========================================================
   AI SCANNER EFFECTS
   ========================================================= */

object AIScannerEffects {

    @Composable
    fun scanningLineAlpha(): Float {

        val transition = rememberInfiniteTransition()

        val alpha by transition.animateFloat(

            initialValue = 0.2f,

            targetValue = 1f,

            animationSpec = infiniteRepeatable(

                animation = tween(700),

                repeatMode = RepeatMode.Reverse
            )
        )

        return alpha
    }

    @Composable
    fun scannerMovement(): Float {

        val transition = rememberInfiniteTransition()

        val movement by transition.animateFloat(

            initialValue = 0f,

            targetValue = 1000f,

            animationSpec = infiniteRepeatable(

                animation = tween(3000),

                repeatMode = RepeatMode.Restart
            )
        )

        return movement
    }
}



/* =========================================================
   THREAT ALERT EFFECTS
   ========================================================= */

object ThreatEffects {

    @Composable
    fun alertBlink(): Float {

        val transition = rememberInfiniteTransition()

        val alpha by transition.animateFloat(

            initialValue = 0.3f,

            targetValue = 1f,

            animationSpec = infiniteRepeatable(

                animation = tween(400),

                repeatMode = RepeatMode.Reverse
            )
        )

        return alpha
    }
}



/* =========================================================
   HOLOGRAPHIC EFFECTS
   ========================================================= */

object HolographicEffects {

    val hologramBrush = Brush.linearGradient(

        colors = listOf(

            Color(0x4400E5FF),

            Color(0x228B5CF6),

            Color(0x4400B0FF)
        )
    )

    fun hologramModifier(): Modifier {

        return Modifier
            .background(
                brush = hologramBrush
            )
            .alpha(0.92f)
    }
}



/* =========================================================
   ENTERPRISE EFFECT PRESETS
   ========================================================= */

object EffectPresets {

    fun cyberPanel(): Modifier {

        return Modifier
            .then(
                GlassEffects.premiumGlassModifier()
            )
            .then(
                GlowEffects.cyanGlow()
            )
    }

    fun threatCard(): Modifier {

        return Modifier
            .then(
                NeonEffects.dangerBorder()
            )
            .then(
                GlowEffects.dangerGlow()
            )
    }

    fun aiPanel(): Modifier {

        return Modifier
            .then(
                GlassEffects.glassCardModifier()
            )
            .then(
                GlowEffects.AIGlow()
            )
    }
}



/* =========================================================
   ADVANCED COMPONENTS
   ========================================================= */

@Composable
fun SentriXGlassCard(

    modifier: Modifier = Modifier,

    shape: Shape = RoundedCornerShape(28.dp),

    content: @Composable () -> Unit
) {

    Card(

        modifier = modifier
            .background(
                color = Color(0x22FFFFFF)
            )
            .border(
                width = 1.dp,
                color = Color(0x33FFFFFF),
                shape = shape
            ),

        shape = shape,

        colors = CardDefaults.cardColors(
            containerColor = Color(0x22111A2B)
        )

    ) {

        Box(
            modifier = Modifier
                .blur(1.dp)
        ) {

            content()
        }
    }
}



/* =========================================================
   FUTURE EFFECT ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ GPU accelerated holograms
| ✔ Dynamic runtime effects
| ✔ AI adaptive animation system
| ✔ Particle rendering engine
| ✔ Cyber-grid live renderer
| ✔ 3D panel depth system
| ✔ Foldable device effect engine
| ✔ VR/AR effect pipeline
| ✔ Dynamic neon renderer
| ✔ Threat visualization overlays
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX EFFECT ENGINE
|--------------------------------------------------------------------------
*/
