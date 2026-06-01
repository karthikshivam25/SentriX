package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.graphicsLayer
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX ANIMATED GRADIENT BUTTON
|--------------------------------------------------------------------------
|
| PURPOSE:
| Advanced futuristic animated button engine for SentriX.
|
| FEATURES:
|
| ✔ Animated Gradient Rendering
| ✔ Dynamic Glow Effects
| ✔ Neon Border Animation
| ✔ Pulse Interaction Feedback
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Glassmorphism Support
| ✔ AI Interaction Ready
| ✔ Dashboard Action Buttons
| ✔ Enterprise UI Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| AnimatedGradientButton(
|     text = "Start Scan",
|     buttonType = GradientButtonType.AI
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   BUTTON TYPES
   ========================================================= */

enum class GradientButtonType {

    PRIMARY,

    AI,

    SUCCESS,

    WARNING,

    DANGER,

    CYBERPUNK,

    MILITARY
}



/* =========================================================
   BUTTON STYLE MODEL
   ========================================================= */

data class GradientButtonStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val textColor: Color,

    val icon: ImageVector
)



/* =========================================================
   BUTTON STYLE ENGINE
   ========================================================= */

object AnimatedGradientButtonEngine {

    fun style(
        type: GradientButtonType
    ): GradientButtonStyle {

        return when (type) {

            GradientButtonType.PRIMARY ->

                GradientButtonStyle(

                    gradient =
                        BrandGradients.Primary,

                    glowColor =
                        SentriX_AccentCyan,

                    borderColor =
                        SentriX_AccentCyan,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.ArrowForward
                )

            GradientButtonType.AI ->

                GradientButtonStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.Memory
                )

            GradientButtonType.SUCCESS ->

                GradientButtonStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.VerifiedUser
                )

            GradientButtonType.WARNING ->

                GradientButtonStyle(

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    borderColor =
                        Threat_Medium,

                    textColor =
                        Text_Dark,

                    icon =
                        Icons.Default.Warning
                )

            GradientButtonType.DANGER ->

                GradientButtonStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.GppBad
                )

            GradientButtonType.CYBERPUNK ->

                GradientButtonStyle(

                    gradient =
                        CyberpunkGradients
                            .NeonPurple,

                    glowColor =
                        Color(0xFFFF00FF),

                    borderColor =
                        Color(0xFFFF00FF),

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.Bolt
                )

            GradientButtonType.MILITARY ->

                GradientButtonStyle(

                    gradient =
                        MilitaryGradients
                            .TacticalGreen,

                    glowColor =
                        Color(0xFF95D5B2),

                    borderColor =
                        Color(0xFF95D5B2),

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.Security
                )
        }
    }
}



/* =========================================================
   MAIN ANIMATED GRADIENT BUTTON
   ========================================================= */

@Composable
fun AnimatedGradientButton(

    modifier: Modifier = Modifier,

    text: String,

    onClick: () -> Unit,

    buttonType: GradientButtonType =
        GradientButtonType.PRIMARY,

    enabled: Boolean = true,

    loading: Boolean = false,

    fullWidth: Boolean = true,

    enableGlow: Boolean = true,

    enablePulseAnimation: Boolean = true,

    leftIcon: ImageVector? = null
) {

    val style =
        AnimatedGradientButtonEngine
            .style(buttonType)



    /*
    |--------------------------------------------------------------------------
    | INTERACTION SOURCE
    |--------------------------------------------------------------------------
    */

    val interactionSource =
        remember {
            MutableInteractionSource()
        }



    /*
    |--------------------------------------------------------------------------
    | PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val pulseScale by infiniteTransition
        .animateFloat(

            initialValue = 1f,

            targetValue = 1.04f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1300),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | GLOW ANIMATION
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.45f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1000),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | BORDER COLOR ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedBorderColor by animateColorAsState(

        targetValue = if (enabled)

            style.borderColor

        else

            Button_Disabled,

        animationSpec = tween(400)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN BUTTON
    |--------------------------------------------------------------------------
    */

    Button(

        onClick = onClick,

        enabled = enabled && !loading,

        interactionSource =
            interactionSource,

        modifier = modifier
            .then(

                if (fullWidth)

                    Modifier.fillMaxWidth()

                else

                    Modifier.wrapContentWidth()
            )
            .height(
                ButtonDimensions
                    .LargeHeight
            )
            .graphicsLayer {

                if (
                    enablePulseAnimation
                ) {

                    scaleX = pulseScale

                    scaleY = pulseScale
                }
            }
            .shadow(

                elevation = if (
                    enableGlow
                )

                    SentriXShadow.Huge

                else

                    SentriXShadow.Small,

                shape =
                    ButtonShapes.Pill,

                ambientColor =
                    style.glowColor.copy(
                        alpha = glowAlpha
                    ),

                spotColor =
                    style.glowColor.copy(
                        alpha = glowAlpha
                    )
            )
            .border(

                width = 1.4.dp,

                color =
                    animatedBorderColor,

                shape =
                    ButtonShapes.Pill
            ),

        shape =
            ButtonShapes.Pill,

        border = BorderStroke(

            width = 1.dp,

            color =
                style.borderColor.copy(
                    alpha = 0.35f
                )
        ),

        colors =
            ButtonDefaults.buttonColors(

                containerColor =
                    Color.Transparent,

                disabledContainerColor =
                    Button_Disabled
            ),

        contentPadding =
            PaddingValues(

                horizontal =
                    SentriXSpacing
                        .ExtraLarge,

                vertical =
                    SentriXSpacing
                        .Medium
            )

    ) {

        /*
        |--------------------------------------------------------------------------
        | GRADIENT BACKGROUND
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .fillMaxSize()
                .clip(
                    ButtonShapes.Pill
                )
                .background(

                    brush =
                        style.gradient
                )
        )



        /*
        |--------------------------------------------------------------------------
        | BUTTON CONTENT
        |--------------------------------------------------------------------------
        */

        Row(

            modifier = Modifier
                .fillMaxWidth()
                .padding(

                    horizontal =
                        SentriXSpacing
                            .Small
                ),

            horizontalArrangement =
                Arrangement.Center,

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            /*
            |--------------------------------------------------------------------------
            | LOADING INDICATOR
            |--------------------------------------------------------------------------
            */

            if (loading) {

                CircularProgressIndicator(

                    modifier = Modifier
                        .size(22.dp),

                    color =
                        style.textColor,

                    strokeWidth = 2.dp
                )

            } else {

                /*
                |--------------------------------------------------------------------------
                | ICON SECTION
                |--------------------------------------------------------------------------
                */

                Box(

                    modifier = Modifier
                        .size(28.dp)
                        .clip(
                            CircleShape
                        )
                        .background(

                            color =
                                Color.White.copy(
                                    alpha = 0.12f
                                )
                        ),

                    contentAlignment =
                        Alignment.Center
                ) {

                    Icon(

                        imageVector =

                            leftIcon
                                ?: style.icon,

                        contentDescription =
                            null,

                        tint =
                            style.textColor,

                        modifier = Modifier.size(
                            IconDimensions
                                .Small
                        )
                    )
                }

                Spacer(
                    modifier = Modifier.width(
                        SentriXSpacing
                            .Medium
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | BUTTON TEXT
                |--------------------------------------------------------------------------
                */

                Text(

                    text = text,

                    style =
                        ButtonTypography
                            .Large,

                    color =
                        style.textColor,

                    fontWeight =
                        FontWeight.Bold
                )
            }
        }
    }
}



/* =========================================================
   MINI ANIMATED BUTTON
   ========================================================= */

@Composable
fun MiniAnimatedGradientButton(

    text: String,

    onClick: () -> Unit
) {

    AnimatedGradientButton(

        text = text,

        onClick = onClick,

        enableGlow = false,

        enablePulseAnimation = false,

        fullWidth = false
    )
}



/* =========================================================
   AI ACTION BUTTON
   ========================================================= */

@Composable
fun AIAnimatedButton(

    text: String,

    loading: Boolean = false,

    onClick: () -> Unit
) {

    AnimatedGradientButton(

        text = text,

        buttonType =
            GradientButtonType.AI,

        loading = loading,

        onClick = onClick
    )
}



/* =========================================================
   DANGER ACTION BUTTON
   ========================================================= */

@Composable
fun DangerAnimatedButton(

    text: String,

    onClick: () -> Unit
) {

    AnimatedGradientButton(

        text = text,

        buttonType =
            GradientButtonType.DANGER,

        onClick = onClick
    )
}



/* =========================================================
   CYBERPUNK BUTTON
   ========================================================= */

@Composable
fun CyberpunkAnimatedButton(

    text: String,

    onClick: () -> Unit
) {

    AnimatedGradientButton(

        text = text,

        buttonType =
            GradientButtonType.CYBERPUNK,

        onClick = onClick
    )
}



/* =========================================================
   FUTURE BUTTON ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ GPU accelerated gradients
| ✔ AI adaptive animations
| ✔ Real-time holographic buttons
| ✔ Dynamic neon reflections
| ✔ Runtime interaction engine
| ✔ Gesture reactive controls
| ✔ Voice activated actions
| ✔ Quantum cyber rendering
| ✔ VR/AR interaction buttons
| ✔ Dynamic cyber-grid buttons
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX ANIMATED GRADIENT BUTTON
|--------------------------------------------------------------------------
*/
