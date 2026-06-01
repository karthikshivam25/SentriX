package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.*
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX LOADING SHIMMER ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Premium futuristic shimmer loading animation framework for SentriX.
|
| FEATURES:
|
| ✔ Smooth Animated Shimmer Effect
| ✔ Cyberpunk Compatible
| ✔ AI Reactive Loading Visuals
| ✔ AMOLED Optimized
| ✔ GPU-Friendly Rendering
| ✔ Enterprise Skeleton Loading
| ✔ Dynamic Gradient Motion
| ✔ Reusable Modifier APIs
| ✔ Dashboard Ready
| ✔ Expandable Loading Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| LoadingShimmerBox()
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SHIMMER TYPES
   ========================================================= */

enum class LoadingShimmerType {

    DEFAULT,

    SECURITY,

    AI,

    NETWORK,

    THREAT,

    CYBERPUNK,

    QUANTUM
}



/* =========================================================
   SHIMMER STYLE MODEL
   ========================================================= */

data class LoadingShimmerStyle(

    val baseColor: Color,

    val shimmerColor: Color,

    val glowColor: Color,

    val shimmerBrush: List<Color>
)



/* =========================================================
   SHIMMER STYLE ENGINE
   ========================================================= */

object LoadingShimmerEngine {

    fun style(
        type: LoadingShimmerType
    ): LoadingShimmerStyle {

        return when (type) {

            LoadingShimmerType.DEFAULT ->

                LoadingShimmerStyle(

                    baseColor =
                        Color(0xFF1B1F2A),

                    shimmerColor =
                        SentriX_AccentBlue,

                    glowColor =
                        SentriX_AccentCyan,

                    shimmerBrush =
                        listOf(

                            Color(0xFF1B1F2A),

                            SentriX_AccentBlue.copy(
                                alpha = 0.35f
                            ),

                            Color(0xFF1B1F2A)
                        )
                )

            LoadingShimmerType.SECURITY ->

                LoadingShimmerStyle(

                    baseColor =
                        Color(0xFF18251D),

                    shimmerColor =
                        Threat_Low,

                    glowColor =
                        SentriX_AccentGreen,

                    shimmerBrush =
                        listOf(

                            Color(0xFF18251D),

                            Threat_Low.copy(
                                alpha = 0.35f
                            ),

                            Color(0xFF18251D)
                        )
                )

            LoadingShimmerType.AI ->

                LoadingShimmerStyle(

                    baseColor =
                        Color(0xFF201B2D),

                    shimmerColor =
                        AI_Active,

                    glowColor =
                        SentriX_AccentPurple,

                    shimmerBrush =
                        listOf(

                            Color(0xFF201B2D),

                            AI_Active.copy(
                                alpha = 0.4f
                            ),

                            Color(0xFF201B2D)
                        )
                )

            LoadingShimmerType.NETWORK ->

                LoadingShimmerStyle(

                    baseColor =
                        Color(0xFF16222C),

                    shimmerColor =
                        Network_Incoming,

                    glowColor =
                        SentriX_AccentBlue,

                    shimmerBrush =
                        listOf(

                            Color(0xFF16222C),

                            Network_Incoming.copy(
                                alpha = 0.35f
                            ),

                            Color(0xFF16222C)
                        )
                )

            LoadingShimmerType.THREAT ->

                LoadingShimmerStyle(

                    baseColor =
                        Color(0xFF2A1515),

                    shimmerColor =
                        Threat_Critical,

                    glowColor =
                        Threat_High,

                    shimmerBrush =
                        listOf(

                            Color(0xFF2A1515),

                            Threat_Critical.copy(
                                alpha = 0.45f
                            ),

                            Color(0xFF2A1515)
                        )
                )

            LoadingShimmerType.CYBERPUNK ->

                LoadingShimmerStyle(

                    baseColor =
                        Color(0xFF1E1025),

                    shimmerColor =
                        Color(0xFFFF00FF),

                    glowColor =
                        Color(0xFF00FFFF),

                    shimmerBrush =
                        listOf(

                            Color(0xFF1E1025),

                            Color(0xFFFF00FF)
                                .copy(
                                    alpha = 0.45f
                                ),

                            Color(0xFF1E1025)
                        )
                )

            LoadingShimmerType.QUANTUM ->

                LoadingShimmerStyle(

                    baseColor =
                        Color(0xFF161A33),

                    shimmerColor =
                        Color(0xFF7C4DFF),

                    glowColor =
                        Color(0xFF00E5FF),

                    shimmerBrush =
                        listOf(

                            Color(0xFF161A33),

                            Color(0xFF7C4DFF)
                                .copy(
                                    alpha = 0.45f
                                ),

                            Color(0xFF161A33)
                        )
                )
        }
    }
}



/* =========================================================
   MAIN SHIMMER BOX
   ========================================================= */

@Composable
fun LoadingShimmerBox(

    modifier: Modifier = Modifier,

    shimmerType: LoadingShimmerType =
        LoadingShimmerType.DEFAULT,

    cornerRadius: Int = 22,

    shimmerDuration: Int = 1800,

    enableGlow: Boolean = true,

    enableBlur: Boolean = true
) {

    val style =
        LoadingShimmerEngine.style(
            shimmerType
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATION ENGINE
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | SHIMMER OFFSET
    |--------------------------------------------------------------------------
    */

    val shimmerOffset by infiniteTransition
        .animateFloat(

            initialValue = -1000f,

            targetValue = 1200f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            shimmerDuration,

                        easing =
                            LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | GLOW PULSE
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.05f,

            targetValue = 0.18f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | SHIMMER BRUSH
    |--------------------------------------------------------------------------
    */

    val animatedBrush =
        Brush.linearGradient(

            colors =
                style.shimmerBrush,

            start =
                Offset(
                    shimmerOffset,
                    shimmerOffset
                ),

            end =
                Offset(
                    shimmerOffset + 500f,
                    shimmerOffset + 500f
                )
        )



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
    |--------------------------------------------------------------------------
    */

    Box(

        modifier = modifier
    ) {

        /*
        |--------------------------------------------------------------------------
        | OUTER GLOW
        |--------------------------------------------------------------------------
        */

        if (enableGlow) {

            Box(

                modifier = Modifier
                    .matchParentSize()
                    .alpha(glowAlpha)
                    .blur(20.dp)
                    .clip(
                        RoundedCornerShape(
                            cornerRadius.dp
                        )
                    )
                    .background(
                        style.glowColor
                    )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | SHIMMER SURFACE
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .fillMaxSize()
                .then(

                    if (enableBlur)

                        Modifier.blur(0.15.dp)

                    else

                        Modifier
                )
                .clip(

                    RoundedCornerShape(
                        cornerRadius.dp
                    )
                )
                .background(

                    brush =
                        animatedBrush
                )
        )
    }
}



/* =========================================================
   SHIMMER CARD PLACEHOLDER
   ========================================================= */

@Composable
fun LoadingShimmerCard(

    modifier: Modifier = Modifier
) {

    LoadingShimmerBox(

        modifier = modifier
            .size(

                width = 320.dp,

                height = 180.dp
            ),

        shimmerType =
            LoadingShimmerType.DEFAULT
    )
}



/* =========================================================
   AI SHIMMER
   ========================================================= */

@Composable
fun AIShimmerBox(

    modifier: Modifier = Modifier
) {

    LoadingShimmerBox(

        modifier = modifier,

        shimmerType =
            LoadingShimmerType.AI
    )
}



/* =========================================================
   THREAT SHIMMER
   ========================================================= */

@Composable
fun ThreatShimmerBox(

    modifier: Modifier = Modifier
) {

    LoadingShimmerBox(

        modifier = modifier,

        shimmerType =
            LoadingShimmerType.THREAT,

        shimmerDuration = 900
    )
}



/* =========================================================
   CYBERPUNK SHIMMER
   ========================================================= */

@Composable
fun CyberpunkShimmerBox(

    modifier: Modifier = Modifier
) {

    LoadingShimmerBox(

        modifier = modifier,

        shimmerType =
            LoadingShimmerType.CYBERPUNK
    )
}



/* =========================================================
   MINI SHIMMER
   ========================================================= */

@Composable
fun MiniShimmerBox(

    modifier: Modifier = Modifier
) {

    LoadingShimmerBox(

        modifier = modifier
            .size(72.dp),

        cornerRadius = 16,

        enableGlow = false
    )
}



/* =========================================================
   FUTURE SHIMMER ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive shimmer intelligence
| ✔ GPU accelerated shimmer rendering
| ✔ Quantum loading visualization
| ✔ Dynamic threat-aware shimmer
| ✔ VR/AR loading environments
| ✔ Neural skeleton rendering
| ✔ Runtime shimmer optimization
| ✔ Holographic loading engine
| ✔ Multi-layer shimmer framework
| ✔ Global cyber loading system
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX LOADING SHIMMER ENGINE
|--------------------------------------------------------------------------
*/
