package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.graphicsLayer
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX GLASS CONTAINER
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise glassmorphism container system for SentriX.
|
| FEATURES:
|
| ✔ Premium Glassmorphism
| ✔ Blur Rendering
| ✔ Neon Border Glow
| ✔ Floating Glass Panels
| ✔ Holographic Effects
| ✔ Dynamic Glow Animation
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ AI Panel Compatible
| ✔ Enterprise UI Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| GlassContainer {
|
|     Text("SentriX")
|
| }
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   GLASS CONTAINER TYPES
   ========================================================= */

enum class GlassContainerType {

    DEFAULT,

    PREMIUM,

    AI,

    THREAT,

    CYBERPUNK,

    AMOLED,

    FLOATING
}



/* =========================================================
   GLASS STYLE MODEL
   ========================================================= */

data class GlassContainerStyle(

    val backgroundBrush: Brush,

    val borderColor: Color,

    val glowColor: Color,

    val shadowColor: Color
)



/* =========================================================
   GLASS STYLE ENGINE
   ========================================================= */

object GlassContainerEngine {

    fun style(
        type: GlassContainerType
    ): GlassContainerStyle {

        return when (type) {

            GlassContainerType.DEFAULT ->

                GlassContainerStyle(

                    backgroundBrush =
                        GlassGradients.FrostedGlass,

                    borderColor =
                        Color.White.copy(
                            alpha = 0.14f
                        ),

                    glowColor =
                        SentriX_AccentCyan,

                    shadowColor =
                        SentriX_AccentCyan
                            .copy(
                                alpha = 0.14f
                            )
                )

            GlassContainerType.PREMIUM ->

                GlassContainerStyle(

                    backgroundBrush =
                        GlassGradients.PremiumGlass,

                    borderColor =
                        SentriX_AccentCyan
                            .copy(
                                alpha = 0.25f
                            ),

                    glowColor =
                        SentriX_AccentCyan,

                    shadowColor =
                        SentriX_AccentCyan
                            .copy(
                                alpha = 0.22f
                            )
                )

            GlassContainerType.AI ->

                GlassContainerStyle(

                    backgroundBrush =
                        AIGradients.Neural,

                    borderColor =
                        AI_Active.copy(
                            alpha = 0.35f
                        ),

                    glowColor =
                        AI_Active,

                    shadowColor =
                        AI_Active.copy(
                            alpha = 0.20f
                        )
                )

            GlassContainerType.THREAT ->

                GlassContainerStyle(

                    backgroundBrush =
                        ThreatGradients.CriticalThreat,

                    borderColor =
                        Threat_Critical
                            .copy(
                                alpha = 0.34f
                            ),

                    glowColor =
                        Threat_Critical,

                    shadowColor =
                        Threat_Critical
                            .copy(
                                alpha = 0.22f
                            )
                )

            GlassContainerType.CYBERPUNK ->

                GlassContainerStyle(

                    backgroundBrush =
                        CyberpunkGradients
                            .Hologram,

                    borderColor =
                        Color(0xFFFF00FF)
                            .copy(
                                alpha = 0.32f
                            ),

                    glowColor =
                        Color(0xFFFF00FF),

                    shadowColor =
                        Color(0xFFFF00FF)
                            .copy(
                                alpha = 0.22f
                            )
                )

            GlassContainerType.AMOLED ->

                GlassContainerStyle(

                    backgroundBrush =
                        BackgroundGradients
                            .AMOLEDBackground,

                    borderColor =
                        Color.White.copy(
                            alpha = 0.08f
                        ),

                    glowColor =
                        Color.White,

                    shadowColor =
                        Color.Black
                )

            GlassContainerType.FLOATING ->

                GlassContainerStyle(

                    backgroundBrush =
                        GlassGradients
                            .PremiumGlass,

                    borderColor =
                        SentriX_AccentPurple
                            .copy(
                                alpha = 0.28f
                            ),

                    glowColor =
                        SentriX_AccentPurple,

                    shadowColor =
                        SentriX_AccentPurple
                            .copy(
                                alpha = 0.20f
                            )
                )
        }
    }
}



/* =========================================================
   MAIN GLASS CONTAINER
   ========================================================= */

@Composable
fun GlassContainer(

    modifier: Modifier = Modifier,

    glassType: GlassContainerType =
        GlassContainerType.DEFAULT,

    shape: Shape =
        CardShapes.Premium,

    enableGlow: Boolean = true,

    enableFloatingEffect: Boolean = true,

    enablePulseEffect: Boolean = true,

    padding: PaddingValues =
        PaddingValues(
            SentriXSpacing.ExtraLarge
        ),

    content: @Composable ColumnScope.() -> Unit
) {

    val style =
        GlassContainerEngine.style(
            glassType
        )



    /*
    |--------------------------------------------------------------------------
    | PULSE GLOW ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.35f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1400),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | FLOATING ANIMATION
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -4f,

            targetValue = 4f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(3000),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED BORDER COLOR
    |--------------------------------------------------------------------------
    */

    val animatedBorderColor by animateColorAsState(

        targetValue =
            style.borderColor,

        animationSpec =
            tween(600)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN GLASS CARD
    |--------------------------------------------------------------------------
    */

    Card(

        modifier = modifier
            .graphicsLayer {

                if (
                    enableFloatingEffect
                ) {

                    translationY =
                        floatingOffset
                }
            }
            .shadow(

                elevation = if (
                    enableGlow
                )

                    SentriXShadow.Huge

                else

                    SentriXShadow.Small,

                shape = shape,

                ambientColor =
                    style.shadowColor.copy(

                        alpha = if (
                            enablePulseEffect
                        )

                            pulseAlpha

                        else

                            0.22f
                    ),

                spotColor =
                    style.shadowColor.copy(

                        alpha = if (
                            enablePulseEffect
                        )

                            pulseAlpha

                        else

                            0.22f
                    )
            )
            .clip(shape)
            .background(

                brush =
                    style.backgroundBrush
            )
            .border(

                width = 1.2.dp,

                color =
                    animatedBorderColor,

                shape = shape
            )
            .blur(0.15.dp),

        shape = shape,

        colors = CardDefaults.cardColors(

            containerColor =
                Color.Transparent
        )

    ) {

        /*
        |--------------------------------------------------------------------------
        | INNER GLASS LAYER
        |--------------------------------------------------------------------------
        */

        Column(

            modifier = Modifier
                .fillMaxWidth()
                .background(

                    color =
                        Color.White.copy(
                            alpha = 0.03f
                        )
                )
                .padding(padding),

            content = content
        )
    }
}



/* =========================================================
   GLASS PANEL HEADER
   ========================================================= */

@Composable
fun GlassContainerHeader(

    title: String,

    subtitle: String = "",

    glowColor: Color =
        SentriX_AccentCyan
) {

    Column {

        Row(

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            /*
            |--------------------------------------------------------------------------
            | LIVE GLOW DOT
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape)
                    .background(
                        glowColor
                    )
            )

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )



            /*
            |--------------------------------------------------------------------------
            | TITLE
            |--------------------------------------------------------------------------
            */

            Text(

                text = title,

                style =
                    DashboardTypography
                        .WidgetTitle,

                color =
                    Text_Primary,

                fontWeight =
                    FontWeight.Bold
            )
        }



        if (
            subtitle.isNotEmpty()
        ) {

            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Small
                )
            )

            Text(

                text = subtitle,

                style =
                    BodyTypography.Small,

                color =
                    Text_Secondary
            )
        }
    }
}



/* =========================================================
   MINI GLASS CONTAINER
   ========================================================= */

@Composable
fun MiniGlassContainer(

    modifier: Modifier = Modifier,

    content: @Composable ColumnScope.() -> Unit
) {

    GlassContainer(

        modifier = modifier,

        glassType =
            GlassContainerType.DEFAULT,

        enableFloatingEffect = false,

        padding = PaddingValues(
            SentriXSpacing.Medium
        ),

        content = content
    )
}



/* =========================================================
   AI GLASS CONTAINER
   ========================================================= */

@Composable
fun AIGlassContainer(

    modifier: Modifier = Modifier,

    content: @Composable ColumnScope.() -> Unit
) {

    GlassContainer(

        modifier = modifier,

        glassType =
            GlassContainerType.AI,

        content = content
    )
}



/* =========================================================
   THREAT GLASS CONTAINER
   ========================================================= */

@Composable
fun ThreatGlassContainer(

    modifier: Modifier = Modifier,

    content: @Composable ColumnScope.() -> Unit
) {

    GlassContainer(

        modifier = modifier,

        glassType =
            GlassContainerType.THREAT,

        content = content
    )
}



/* =========================================================
   FUTURE GLASS ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time holographic rendering
| ✔ GPU accelerated blur engine
| ✔ Dynamic neon reflections
| ✔ AI adaptive glass intensity
| ✔ Runtime transparency control
| ✔ Quantum holographic panels
| ✔ VR/AR glass rendering
| ✔ Interactive cyber-grid layers
| ✔ Dynamic light reflections
| ✔ 3D floating glass system
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX GLASS CONTAINER
|--------------------------------------------------------------------------
*/
