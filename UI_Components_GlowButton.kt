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
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Security
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
| SENTRIX GLOW BUTTON COMPONENT
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise premium animated button system for SentriX.
|
| FEATURES:
|
| ✔ Neon Glow Effects
| ✔ Animated Pulse Effects
| ✔ AI Style Buttons
| ✔ Cyberpunk Ready
| ✔ Military Ready
| ✔ AMOLED Optimized
| ✔ Glassmorphism Compatible
| ✔ Loading States
| ✔ Hover Effects
| ✔ Press Animations
| ✔ Gradient Rendering
| ✔ Enterprise Dashboard Support
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| GlowButton(
|     text = "Activate Protection",
|     onClick = { }
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   BUTTON TYPES
   ========================================================= */

enum class GlowButtonType {

    PRIMARY,

    SUCCESS,

    WARNING,

    DANGER,

    AI,

    CYBERPUNK,

    MILITARY
}



/* =========================================================
   BUTTON STYLE DATA
   ========================================================= */

data class GlowButtonStyle(

    val backgroundGradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val textColor: Color,

    val icon: ImageVector
)



/* =========================================================
   BUTTON STYLE ENGINE
   ========================================================= */

object GlowButtonEngine {

    fun style(
        type: GlowButtonType
    ): GlowButtonStyle {

        return when (type) {

            GlowButtonType.PRIMARY -> GlowButtonStyle(

                backgroundGradient =
                    BrandGradients.Primary,

                glowColor = SentriX_AccentCyan,

                borderColor = SentriX_AccentCyan,

                textColor = Text_Primary,

                icon = Icons.Default.ArrowForward
            )

            GlowButtonType.SUCCESS -> GlowButtonStyle(

                backgroundGradient =
                    ThreatGradients.LowThreat,

                glowColor = Threat_Low,

                borderColor = Threat_Low,

                textColor = Text_Primary,

                icon = Icons.Default.Security
            )

            GlowButtonType.WARNING -> GlowButtonStyle(

                backgroundGradient =
                    ThreatGradients.MediumThreat,

                glowColor = Threat_Medium,

                borderColor = Threat_Medium,

                textColor = Text_Dark,

                icon = Icons.Default.Lock
            )

            GlowButtonType.DANGER -> GlowButtonStyle(

                backgroundGradient =
                    ThreatGradients.CriticalThreat,

                glowColor = Threat_Critical,

                borderColor = Threat_Critical,

                textColor = Text_Primary,

                icon = Icons.Default.PowerSettingsNew
            )

            GlowButtonType.AI -> GlowButtonStyle(

                backgroundGradient =
                    AIGradients.Neural,

                glowColor = AI_Active,

                borderColor = AI_Active,

                textColor = Text_Primary,

                icon = Icons.Default.Security
            )

            GlowButtonType.CYBERPUNK -> GlowButtonStyle(

                backgroundGradient =
                    CyberpunkGradients.NeonPurple,

                glowColor = Color(0xFFFF00FF),

                borderColor = Color(0xFF00E5FF),

                textColor = Text_Primary,

                icon = Icons.Default.ArrowForward
            )

            GlowButtonType.MILITARY -> GlowButtonStyle(

                backgroundGradient =
                    MilitaryGradients.TacticalGreen,

                glowColor = Color(0xFF95D5B2),

                borderColor = Color(0xFF95D5B2),

                textColor = Text_Primary,

                icon = Icons.Default.Security
            )
        }
    }
}



/* =========================================================
   MAIN GLOW BUTTON
   ========================================================= */

@Composable
fun GlowButton(

    modifier: Modifier = Modifier,

    text: String,

    onClick: () -> Unit,

    buttonType: GlowButtonType =
        GlowButtonType.PRIMARY,

    enabled: Boolean = true,

    loading: Boolean = false,

    fullWidth: Boolean = true,

    enableGlow: Boolean = true,

    enablePulseAnimation: Boolean = true,

    leftIcon: ImageVector? = null
) {

    val style =
        GlowButtonEngine.style(
            buttonType
        )



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

    val animatedScale by infiniteTransition.animateFloat(

        initialValue = 1f,

        targetValue = 1.03f,

        animationSpec = infiniteRepeatable(

            animation = tween(
                durationMillis = 1200
            ),

            repeatMode = RepeatMode.Reverse
        )
    )



    /*
    |--------------------------------------------------------------------------
    | GLOW ANIMATION
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition.animateFloat(

        initialValue = 0.45f,

        targetValue = 1f,

        animationSpec = infiniteRepeatable(

            animation = tween(1000),

            repeatMode = RepeatMode.Reverse
        )
    )



    /*
    |--------------------------------------------------------------------------
    | ENABLED COLOR STATE
    |--------------------------------------------------------------------------
    */

    val animatedBorderColor by animateColorAsState(

        targetValue = if (enabled)
            style.borderColor
        else
            Button_Disabled
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN BUTTON
    |--------------------------------------------------------------------------
    */

    Button(

        onClick = onClick,

        enabled = enabled && !loading,

        interactionSource = interactionSource,

        modifier = modifier
            .then(

                if (fullWidth)
                    Modifier.fillMaxWidth()
                else
                    Modifier.wrapContentWidth()
            )
            .height(
                ButtonDimensions.LargeHeight
            )
            .graphicsLayer {

                if (
                    enablePulseAnimation
                ) {

                    scaleX = animatedScale

                    scaleY = animatedScale
                }
            }
            .shadow(

                elevation = if (enableGlow)
                    SentriXShadow.Large
                else
                    SentriXShadow.Small,

                shape = ButtonShapes.Pill,

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

                color = animatedBorderColor,

                shape = ButtonShapes.Pill
            ),

        shape = ButtonShapes.Pill,

        border = BorderStroke(

            width = 1.dp,

            color =
                style.borderColor.copy(
                    alpha = 0.4f
                )
        ),

        colors = ButtonDefaults.buttonColors(

            containerColor =
                Color.Transparent,

            disabledContainerColor =
                Button_Disabled
        ),

        contentPadding = PaddingValues(

            horizontal =
                SentriXSpacing.ExtraLarge,

            vertical =
                SentriXSpacing.Medium
        )

    ) {

        /*
        |--------------------------------------------------------------------------
        | BACKGROUND LAYER
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .fillMaxSize()
                .clip(ButtonShapes.Pill)
                .background(
                    brush =
                        style.backgroundGradient
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
                        SentriXSpacing.Small
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

                    color = style.textColor,

                    strokeWidth = 2.dp
                )

            } else {

                /*
                |--------------------------------------------------------------------------
                | LEFT ICON
                |--------------------------------------------------------------------------
                */

                Icon(

                    imageVector =
                        leftIcon ?: style.icon,

                    contentDescription = null,

                    tint = style.textColor,

                    modifier = Modifier.size(
                        IconDimensions.Medium
                    )
                )

                Spacer(
                    modifier = Modifier.width(
                        SentriXSpacing.Medium
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
                        ButtonTypography.Large,

                    color = style.textColor,

                    fontWeight =
                        FontWeight.Bold
                )
            }
        }
    }
}



/* =========================================================
   MINI GLOW BUTTON
   ========================================================= */

@Composable
fun MiniGlowButton(

    text: String,

    onClick: () -> Unit,

    modifier: Modifier = Modifier
) {

    GlowButton(

        modifier = modifier,

        text = text,

        onClick = onClick,

        fullWidth = false,

        enableGlow = false,

        enablePulseAnimation = false
    )
}



/* =========================================================
   AI ACTION BUTTON
   ========================================================= */

@Composable
fun AIActionButton(

    text: String,

    onClick: () -> Unit,

    loading: Boolean = false
) {

    GlowButton(

        text = text,

        onClick = onClick,

        buttonType =
            GlowButtonType.AI,

        loading = loading
    )
}



/* =========================================================
   DANGER ACTION BUTTON
   ========================================================= */

@Composable
fun DangerActionButton(

    text: String,

    onClick: () -> Unit
) {

    GlowButton(

        text = text,

        onClick = onClick,

        buttonType =
            GlowButtonType.DANGER
    )
}



/* =========================================================
   CYBERPUNK BUTTON
   ========================================================= */

@Composable
fun CyberpunkButton(

    text: String,

    onClick: () -> Unit
) {

    GlowButton(

        text = text,

        onClick = onClick,

        buttonType =
            GlowButtonType.CYBERPUNK
    )
}



/* =========================================================
   FUTURE GLOW BUTTON EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Holographic buttons
| ✔ GPU neon rendering
| ✔ Runtime gradient engine
| ✔ AI adaptive animations
| ✔ Gesture reactive glow
| ✔ Voice activated effects
| ✔ 3D hover animations
| ✔ Dynamic cyber-grid buttons
| ✔ Live pulse rendering
| ✔ VR/AR interaction buttons
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX GLOW BUTTON COMPONENT
|--------------------------------------------------------------------------
*/
