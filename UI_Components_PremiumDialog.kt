package com.sentrix.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.AlertDialog
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX PREMIUM DIALOG
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise futuristic dialog system for SentriX.
|
| FEATURES:
|
| ✔ Premium Animated Dialogs
| ✔ Cyberpunk Glow Effects
| ✔ AI Alert System
| ✔ Glassmorphism Rendering
| ✔ Dynamic Status Dialogs
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Threat Warning Dialogs
| ✔ Animated Entry Effects
| ✔ Enterprise UX Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| PremiumDialog(
|     visible = true,
|     title = "Threat Detected",
|     message = "Suspicious process identified"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   DIALOG TYPES
   ========================================================= */

enum class PremiumDialogType {

    DEFAULT,

    SUCCESS,

    WARNING,

    DANGER,

    AI,

    CYBERPUNK,

    NETWORK,

    ANALYTICS
}



/* =========================================================
   DIALOG STYLE MODEL
   ========================================================= */

data class PremiumDialogStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val icon: ImageVector
)



/* =========================================================
   DIALOG STYLE ENGINE
   ========================================================= */

object PremiumDialogEngine {

    fun style(
        type: PremiumDialogType
    ): PremiumDialogStyle {

        return when (type) {

            PremiumDialogType.DEFAULT ->

                PremiumDialogStyle(

                    gradient =
                        BrandGradients.Primary,

                    glowColor =
                        SentriX_AccentCyan,

                    borderColor =
                        SentriX_AccentCyan,

                    icon =
                        Icons.Default.Info
                )

            PremiumDialogType.SUCCESS ->

                PremiumDialogStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.VerifiedUser
                )

            PremiumDialogType.WARNING ->

                PremiumDialogStyle(

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    borderColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.WarningAmber
                )

            PremiumDialogType.DANGER ->

                PremiumDialogStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad
                )

            PremiumDialogType.AI ->

                PremiumDialogStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    icon =
                        Icons.Default.Memory
                )

            PremiumDialogType.CYBERPUNK ->

                PremiumDialogStyle(

                    gradient =
                        CyberpunkGradients.Hologram,

                    glowColor =
                        Color(0xFFFF00FF),

                    borderColor =
                        Color(0xFFFF00FF),

                    icon =
                        Icons.Default.Bolt
                )

            PremiumDialogType.NETWORK ->

                PremiumDialogStyle(

                    gradient =
                        AnalyticsGradients.NetworkTraffic,

                    glowColor =
                        Network_Incoming,

                    borderColor =
                        Network_Incoming,

                    icon =
                        Icons.Default.Wifi
                )

            PremiumDialogType.ANALYTICS ->

                PremiumDialogStyle(

                    gradient =
                        AnalyticsGradients.Traffic,

                    glowColor =
                        SentriX_AccentPurple,

                    borderColor =
                        SentriX_AccentPurple,

                    icon =
                        Icons.Default.Analytics
                )
        }
    }
}



/* =========================================================
   MAIN PREMIUM DIALOG
   ========================================================= */

@Composable
fun PremiumDialog(

    visible: Boolean,

    title: String,

    message: String,

    modifier: Modifier = Modifier,

    dialogType: PremiumDialogType =
        PremiumDialogType.DEFAULT,

    confirmButtonText: String = "Confirm",

    dismissButtonText: String = "Cancel",

    showDismissButton: Boolean = true,

    showCloseIcon: Boolean = true,

    dismissOnBackPress: Boolean = true,

    dismissOnOutsideClick: Boolean = false,

    onConfirm: () -> Unit,

    onDismiss: () -> Unit
) {

    val style =
        PremiumDialogEngine.style(
            dialogType
        )



    /*
    |--------------------------------------------------------------------------
    | LIVE ANIMATION ENGINE
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

                    animation = tween(1200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | FLOATING ICON ANIMATION
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -5f,

            targetValue = 5f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2400),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | MAIN DIALOG
    |--------------------------------------------------------------------------
    */

    if (visible) {

        Dialog(

            onDismissRequest = onDismiss,

            properties = DialogProperties(

                dismissOnBackPress =
                    dismissOnBackPress,

                dismissOnClickOutside =
                    dismissOnOutsideClick
            )
        ) {

            AnimatedVisibility(

                visible = visible,

                enter = fadeIn() + scaleIn(

                    initialScale = 0.85f
                ),

                exit = fadeOut() + scaleOut(

                    targetScale = 0.85f
                )
            ) {

                Surface(

                    modifier = modifier
                        .fillMaxWidth()
                        .shadow(

                            elevation =
                                SentriXShadow.Huge,

                            shape =
                                RoundedCornerShape(
                                    32.dp
                                ),

                            ambientColor =
                                style.glowColor.copy(
                                    alpha = pulseAlpha
                                ),

                            spotColor =
                                style.glowColor.copy(
                                    alpha = pulseAlpha
                                )
                        )
                        .clip(
                            RoundedCornerShape(
                                32.dp
                            )
                        )
                        .background(

                            color =
                                Background_Main
                        )
                        .border(

                            width = 1.5.dp,

                            color =
                                style.borderColor.copy(
                                    alpha = 0.28f
                                ),

                            shape =
                                RoundedCornerShape(
                                    32.dp
                                )
                        )
                        .blur(0.2.dp),

                    color = Background_Card
                ) {

                    Column(

                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(
                                SentriXSpacing
                                    .ExtraLarge
                            ),

                        horizontalAlignment =
                            Alignment.CenterHorizontally
                    ) {

                        /*
                        |--------------------------------------------------------------------------
                        | CLOSE BUTTON
                        |--------------------------------------------------------------------------
                        */

                        if (showCloseIcon) {

                            Row(

                                modifier = Modifier
                                    .fillMaxWidth(),

                                horizontalArrangement =
                                    Arrangement.End
                            ) {

                                Box(

                                    modifier = Modifier
                                        .size(40.dp)
                                        .clip(
                                            CircleShape
                                        )
                                        .background(

                                            color =
                                                Background_Secondary
                                        )
                                        .border(

                                            width = 1.dp,

                                            color =
                                                style.borderColor
                                                    .copy(
                                                        alpha = 0.16f
                                                    ),

                                            shape =
                                                CircleShape
                                        ),

                                    contentAlignment =
                                        Alignment.Center
                                ) {

                                    Icon(

                                        imageVector =
                                            Icons.Default.Close,

                                        contentDescription =
                                            "Close",

                                        tint =
                                            Text_Secondary,

                                        modifier = Modifier
                                            .padding(8.dp)
                                    )
                                }
                            }
                        }



                        /*
                        |--------------------------------------------------------------------------
                        | ICON CONTAINER
                        |--------------------------------------------------------------------------
                        */

                        Box(

                            modifier = Modifier
                                .offset(
                                    y = floatingOffset.dp
                                )
                                .size(120.dp)
                                .shadow(

                                    elevation =
                                        SentriXShadow.Huge,

                                    shape =
                                        CircleShape,

                                    ambientColor =
                                        style.glowColor.copy(
                                            alpha = pulseAlpha
                                        )
                                )
                                .clip(
                                    CircleShape
                                )
                                .background(

                                    brush =
                                        style.gradient
                                )
                                .border(

                                    width = 1.5.dp,

                                    color =
                                        style.borderColor
                                            .copy(
                                                alpha = 0.32f
                                            ),

                                    shape =
                                        CircleShape
                                ),

                            contentAlignment =
                                Alignment.Center
                        ) {

                            /*
                            |--------------------------------------------------------------------------
                            | INNER CIRCLE
                            |--------------------------------------------------------------------------
                            */

                            Box(

                                modifier = Modifier
                                    .size(84.dp)
                                    .alpha(0.14f)
                                    .clip(
                                        CircleShape
                                    )
                                    .background(
                                        Color.White
                                    )
                            )



                            /*
                            |--------------------------------------------------------------------------
                            | MAIN ICON
                            |--------------------------------------------------------------------------
                            */

                            Icon(

                                imageVector =
                                    style.icon,

                                contentDescription =
                                    null,

                                tint =
                                    Text_Primary,

                                modifier = Modifier.size(
                                    IconDimensions.Huge
                                )
                            )
                        }



                        Spacer(
                            modifier = Modifier.height(
                                SentriXSpacing
                                    .ExtraLarge
                            )
                        )



                        /*
                        |--------------------------------------------------------------------------
                        | LIVE INDICATOR
                        |--------------------------------------------------------------------------
                        */

                        Row(

                            verticalAlignment =
                                Alignment.CenterVertically
                        ) {

                            Box(

                                modifier = Modifier
                                    .size(10.dp)
                                    .alpha(
                                        pulseAlpha
                                    )
                                    .clip(
                                        CircleShape
                                    )
                                    .background(
                                        style.glowColor
                                    )
                            )

                            Spacer(
                                modifier = Modifier.width(
                                    SentriXSpacing
                                        .Small
                                )
                            )

                            Text(

                                text = "SYSTEM ALERT",

                                style =
                                    TerminalTypography
                                        .Body,

                                color =
                                    style.glowColor
                            )
                        }



                        Spacer(
                            modifier = Modifier.height(
                                SentriXSpacing
                                    .Large
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
                                HeadlineTypography
                                    .Medium,

                            color =
                                Text_Primary,

                            fontWeight =
                                FontWeight.ExtraBold,

                            textAlign =
                                TextAlign.Center
                        )



                        Spacer(
                            modifier = Modifier.height(
                                SentriXSpacing
                                    .Medium
                            )
                        )



                        /*
                        |--------------------------------------------------------------------------
                        | MESSAGE
                        |--------------------------------------------------------------------------
                        */

                        Text(

                            text = message,

                            style =
                                BodyTypography
                                    .Medium,

                            color =
                                Text_Secondary,

                            textAlign =
                                TextAlign.Center
                        )



                        Spacer(
                            modifier = Modifier.height(
                                SentriXSpacing
                                    .ExtraLarge
                            )
                        )



                        /*
                        |--------------------------------------------------------------------------
                        | ACTION BUTTONS
                        |--------------------------------------------------------------------------
                        */

                        Row(

                            modifier = Modifier
                                .fillMaxWidth(),

                            horizontalArrangement =
                                Arrangement.spacedBy(
                                    SentriXSpacing
                                        .Medium
                                )
                        ) {

                            /*
                            |--------------------------------------------------------------------------
                            | DISMISS BUTTON
                            |--------------------------------------------------------------------------
                            */

                            if (showDismissButton) {

                                AnimatedGradientButton(

                                    modifier = Modifier
                                        .weight(1f),

                                    text =
                                        dismissButtonText,

                                    onClick =
                                        onDismiss,

                                    buttonType =
                                        GradientButtonType
                                            .WARNING
                                )
                            }



                            /*
                            |--------------------------------------------------------------------------
                            | CONFIRM BUTTON
                            |--------------------------------------------------------------------------
                            */

                            AnimatedGradientButton(

                                modifier = Modifier
                                    .weight(1f),

                                text =
                                    confirmButtonText,

                                onClick =
                                    onConfirm,

                                buttonType = when (

                                    dialogType
                                ) {

                                    PremiumDialogType
                                        .DANGER ->

                                        GradientButtonType
                                            .DANGER

                                    PremiumDialogType
                                        .AI ->

                                        GradientButtonType
                                            .AI

                                    PremiumDialogType
                                        .CYBERPUNK ->

                                        GradientButtonType
                                            .CYBERPUNK

                                    else ->

                                        GradientButtonType
                                            .PRIMARY
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}



/* =========================================================
   SUCCESS DIALOG
   ========================================================= */

@Composable
fun SuccessDialog(

    visible: Boolean,

    title: String,

    message: String,

    onDismiss: () -> Unit
) {

    PremiumDialog(

        visible = visible,

        title = title,

        message = message,

        dialogType =
            PremiumDialogType.SUCCESS,

        confirmButtonText =
            "Continue",

        showDismissButton = false,

        onConfirm = onDismiss,

        onDismiss = onDismiss
    )
}



/* =========================================================
   DANGER DIALOG
   ========================================================= */

@Composable
fun DangerDialog(

    visible: Boolean,

    title: String,

    message: String,

    onConfirm: () -> Unit,

    onDismiss: () -> Unit
) {

    PremiumDialog(

        visible = visible,

        title = title,

        message = message,

        dialogType =
            PremiumDialogType.DANGER,

        confirmButtonText =
            "Resolve Threat",

        dismissButtonText =
            "Ignore",

        onConfirm = onConfirm,

        onDismiss = onDismiss
    )
}



/* =========================================================
   AI DIALOG
   ========================================================= */

@Composable
fun AIDialog(

    visible: Boolean,

    title: String,

    message: String,

    onConfirm: () -> Unit,

    onDismiss: () -> Unit
) {

    PremiumDialog(

        visible = visible,

        title = title,

        message = message,

        dialogType =
            PremiumDialogType.AI,

        confirmButtonText =
            "Analyze",

        onConfirm = onConfirm,

        onDismiss = onDismiss
    )
}



/* =========================================================
   FUTURE DIALOG ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive dialog system
| ✔ GPU holographic rendering
| ✔ Dynamic cyber-grid overlays
| ✔ Voice assistant dialogs
| ✔ Runtime interactive alerts
| ✔ Quantum security popups
| ✔ VR/AR dialog rendering
| ✔ Threat visualization dialogs
| ✔ Live system monitoring alerts
| ✔ Dynamic storytelling engine
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX PREMIUM DIALOG
|--------------------------------------------------------------------------
*/
