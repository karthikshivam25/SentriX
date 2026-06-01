package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.sentrix.ui.geometry.Offset
import com.sentrix.ui.text.TextStyle
import com.sentrix.ui.text.android.InternalPlatformTextApi
import com.sentrix.ui.text.drawText
import com.sentrix.ui.theme.*
import kotlin.random.Random

/*
|--------------------------------------------------------------------------
| SENTRIX MATRIX FLOW ANIMATION
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic matrix-style cyber data stream engine for SentriX.
|
| FEATURES:
|
| ✔ Matrix Data Flow Rendering
| ✔ AI Neural Stream Visualization
| ✔ Cyberpunk Compatible
| ✔ Dynamic Falling Data Streams
| ✔ Neon Glow Effects
| ✔ AMOLED Optimized
| ✔ GPU-Friendly Rendering
| ✔ Enterprise Security Backgrounds
| ✔ Real-Time Data Visualization
| ✔ Expandable Matrix Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| MatrixFlowAnimation(
|     matrixType = MatrixFlowType.AI
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   MATRIX TYPES
   ========================================================= */

enum class MatrixFlowType {

    DEFAULT,

    SECURITY,

    AI,

    NETWORK,

    THREAT,

    CYBERPUNK,

    QUANTUM
}



/* =========================================================
   MATRIX STYLE MODEL
   ========================================================= */

data class MatrixFlowStyle(

    val primaryColor: Color,

    val secondaryColor: Color,

    val glowColor: Color,

    val backgroundGlow: Color
)



/* =========================================================
   MATRIX STYLE ENGINE
   ========================================================= */

object MatrixFlowEngine {

    fun style(
        type: MatrixFlowType
    ): MatrixFlowStyle {

        return when (type) {

            MatrixFlowType.DEFAULT ->

                MatrixFlowStyle(

                    primaryColor =
                        SentriX_AccentBlue,

                    secondaryColor =
                        SentriX_AccentCyan,

                    glowColor =
                        SentriX_AccentBlue,

                    backgroundGlow =
                        SentriX_AccentCyan
                )

            MatrixFlowType.SECURITY ->

                MatrixFlowStyle(

                    primaryColor =
                        Threat_Low,

                    secondaryColor =
                        SentriX_AccentGreen,

                    glowColor =
                        Threat_Low,

                    backgroundGlow =
                        SentriX_AccentGreen
                )

            MatrixFlowType.AI ->

                MatrixFlowStyle(

                    primaryColor =
                        AI_Active,

                    secondaryColor =
                        SentriX_AccentPurple,

                    glowColor =
                        AI_Active,

                    backgroundGlow =
                        SentriX_AccentPurple
                )

            MatrixFlowType.NETWORK ->

                MatrixFlowStyle(

                    primaryColor =
                        Network_Incoming,

                    secondaryColor =
                        SentriX_AccentBlue,

                    glowColor =
                        Network_Incoming,

                    backgroundGlow =
                        SentriX_AccentBlue
                )

            MatrixFlowType.THREAT ->

                MatrixFlowStyle(

                    primaryColor =
                        Threat_Critical,

                    secondaryColor =
                        Threat_High,

                    glowColor =
                        Threat_Critical,

                    backgroundGlow =
                        Threat_High
                )

            MatrixFlowType.CYBERPUNK ->

                MatrixFlowStyle(

                    primaryColor =
                        Color(0xFFFF00FF),

                    secondaryColor =
                        Color(0xFF00FFFF),

                    glowColor =
                        Color(0xFFFF00FF),

                    backgroundGlow =
                        Color(0xFF00FFFF)
                )

            MatrixFlowType.QUANTUM ->

                MatrixFlowStyle(

                    primaryColor =
                        Color(0xFF7C4DFF),

                    secondaryColor =
                        Color(0xFF00E5FF),

                    glowColor =
                        Color(0xFF7C4DFF),

                    backgroundGlow =
                        Color(0xFF00E5FF)
                )
        }
    }
}



/* =========================================================
   DATA STREAM MODEL
   ========================================================= */

data class MatrixStream(

    val xPosition: Float,

    val speed: Float,

    val characterCount: Int,

    val randomSeed: Int
)



/* =========================================================
   MATRIX CHARACTERS
   ========================================================= */

private val SentriXMatrixCharacters = listOf(

    "0", "1",

    "A", "I",

    "X", "Z",

    "#", "@",

    "∆", "Ω",

    "Ξ", "λ",

    "7", "9"
)



/* =========================================================
   MAIN MATRIX FLOW ANIMATION
   ========================================================= */

@OptIn(InternalPlatformTextApi::class)
@Composable
fun MatrixFlowAnimation(

    modifier: Modifier = Modifier,

    matrixType: MatrixFlowType =
        MatrixFlowType.DEFAULT,

    streamCount: Int = 40,

    animationSpeed: Int = 5000,

    characterSize: Int = 14,

    enableBackgroundGlow: Boolean = true,

    enableBlur: Boolean = true
) {

    val style =
        MatrixFlowEngine.style(
            matrixType
        )



    /*
    |--------------------------------------------------------------------------
    | MATRIX STREAM GENERATION
    |--------------------------------------------------------------------------
    */

    val streams = remember {

        List(streamCount) {

            MatrixStream(

                xPosition =
                    Random.nextFloat() * 1200f,

                speed =
                    Random.nextFloat() * 1200f + 200f,

                characterCount =
                    Random.nextInt(8, 28),

                randomSeed =
                    Random.nextInt()
            )
        }
    }



    /*
    |--------------------------------------------------------------------------
    | ANIMATION ENGINE
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | FLOW MOVEMENT
    |--------------------------------------------------------------------------
    */

    val animationOffset by infiniteTransition
        .animateFloat(

            initialValue = -200f,

            targetValue = 2400f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            animationSpeed,

                        easing =
                            LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | GLOW ANIMATION
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.04f,

            targetValue = 0.16f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
    |--------------------------------------------------------------------------
    */

    Box(

        modifier = modifier
            .fillMaxSize()
    ) {

        /*
        |--------------------------------------------------------------------------
        | BACKGROUND GLOW
        |--------------------------------------------------------------------------
        */

        if (enableBackgroundGlow) {

            Box(

                modifier = Modifier
                    .fillMaxSize()
                    .alpha(glowAlpha)
                    .blur(42.dp)
                    .background(
                        style.backgroundGlow
                    )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | MATRIX CANVAS
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .fillMaxSize()
                .then(

                    if (enableBlur)

                        Modifier.blur(0.2.dp)

                    else

                        Modifier
                )
        ) {

            streams.forEach { stream ->

                val random =
                    Random(stream.randomSeed)

                val dynamicOffset =
                    (
                        animationOffset *
                            (stream.speed / 1000f)
                        ) % (size.height + 600f)

                for (
                    index in 0 until
                            stream.characterCount
                ) {

                    val character =
                        SentriXMatrixCharacters
                            .random(random)

                    val yPosition =
                        dynamicOffset -
                                (index * 34f)

                    val alphaValue =
                        (
                            1f -
                                    (
                                        index.toFloat() /
                                                stream.characterCount
                                        )
                            ) * 0.95f

                    drawIntoCanvas { canvas ->

                        drawText(

                            canvas = canvas,

                            text = character,

                            topLeft = Offset(

                                stream.xPosition,

                                yPosition
                            ),

                            style = TextStyle(

                                color =
                                    if (index == 0)

                                        style.secondaryColor
                                            .copy(
                                                alpha =
                                                    alphaValue
                                            )

                                    else

                                        style.primaryColor
                                            .copy(
                                                alpha =
                                                    alphaValue
                                            ),

                                fontSize =
                                    characterSize.sp,

                                fontWeight =
                                    FontWeight.Bold
                            )
                        )
                    }
                }
            }
        }
    }
}



/* =========================================================
   AI MATRIX FLOW
   ========================================================= */

@Composable
fun AIMatrixFlow(

    modifier: Modifier = Modifier
) {

    MatrixFlowAnimation(

        modifier = modifier,

        matrixType =
            MatrixFlowType.AI
    )
}



/* =========================================================
   SECURITY MATRIX FLOW
   ========================================================= */

@Composable
fun SecurityMatrixFlow(

    modifier: Modifier = Modifier
) {

    MatrixFlowAnimation(

        modifier = modifier,

        matrixType =
            MatrixFlowType.SECURITY
    )
}



/* =========================================================
   THREAT MATRIX FLOW
   ========================================================= */

@Composable
fun ThreatMatrixFlow(

    modifier: Modifier = Modifier
) {

    MatrixFlowAnimation(

        modifier = modifier,

        matrixType =
            MatrixFlowType.THREAT,

        animationSpeed = 2400
    )
}



/* =========================================================
   CYBERPUNK MATRIX FLOW
   ========================================================= */

@Composable
fun CyberpunkMatrixFlow(

    modifier: Modifier = Modifier
) {

    MatrixFlowAnimation(

        modifier = modifier,

        matrixType =
            MatrixFlowType.CYBERPUNK
    )
}



/* =========================================================
   MINI MATRIX FLOW
   ========================================================= */

@Composable
fun MiniMatrixFlow(

    modifier: Modifier = Modifier
) {

    MatrixFlowAnimation(

        modifier = modifier,

        streamCount = 12,

        characterSize = 9,

        enableBackgroundGlow = false
    )
}



/* =========================================================
   FUTURE MATRIX ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive matrix intelligence
| ✔ GPU accelerated stream rendering
| ✔ Quantum data visualization
| ✔ Dynamic neural data streams
| ✔ VR/AR cyber backgrounds
| ✔ Real-time threat stream engine
| ✔ Holographic matrix rendering
| ✔ Multi-layer data flow engine
| ✔ Runtime AI visualization
| ✔ Global cyber telemetry rendering
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX MATRIX FLOW ANIMATION
|--------------------------------------------------------------------------
*/
