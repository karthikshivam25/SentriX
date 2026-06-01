package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX CYBER SEARCH BAR
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise futuristic search component for SentriX.
|
| FEATURES:
|
| ✔ Cyberpunk Search Design
| ✔ AI Search Indicator
| ✔ Neon Glow Effects
| ✔ Animated Focus States
| ✔ Live Search Pulse
| ✔ Glassmorphism Rendering
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Enterprise Search UI
| ✔ Threat Intelligence Search
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| CyberSearchBar(
|     query = query,
|     onQueryChange = { }
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SEARCH BAR TYPES
   ========================================================= */

enum class CyberSearchBarType {

    DEFAULT,

    AI,

    THREAT,

    ANALYTICS,

    CYBERPUNK
}



/* =========================================================
   SEARCH STYLE MODEL
   ========================================================= */

data class SearchBarStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val cursorColor: Color,

    val iconColor: Color
)



/* =========================================================
   SEARCH STYLE ENGINE
   ========================================================= */

object CyberSearchEngine {

    fun style(
        type: CyberSearchBarType
    ): SearchBarStyle {

        return when (type) {

            CyberSearchBarType.DEFAULT ->

                SearchBarStyle(

                    gradient =
                        GlassGradients
                            .PremiumGlass,

                    glowColor =
                        SentriX_AccentCyan,

                    borderColor =
                        SentriX_AccentCyan,

                    cursorColor =
                        SentriX_AccentCyan,

                    iconColor =
                        SentriX_AccentCyan
                )

            CyberSearchBarType.AI ->

                SearchBarStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    cursorColor =
                        AI_Active,

                    iconColor =
                        AI_Active
                )

            CyberSearchBarType.THREAT ->

                SearchBarStyle(

                    gradient =
                        ThreatGradients
                            .CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    cursorColor =
                        Threat_Critical,

                    iconColor =
                        Threat_Critical
                )

            CyberSearchBarType.ANALYTICS ->

                SearchBarStyle(

                    gradient =
                        AnalyticsGradients
                            .Traffic,

                    glowColor =
                        SentriX_AccentPurple,

                    borderColor =
                        SentriX_AccentPurple,

                    cursorColor =
                        SentriX_AccentPurple,

                    iconColor =
                        SentriX_AccentPurple
                )

            CyberSearchBarType.CYBERPUNK ->

                SearchBarStyle(

                    gradient =
                        CyberpunkGradients
                            .Hologram,

                    glowColor =
                        Color(0xFFFF00FF),

                    borderColor =
                        Color(0xFFFF00FF),

                    cursorColor =
                        Color(0xFFFF00FF),

                    iconColor =
                        Color(0xFFFF00FF)
                )
        }
    }
}



/* =========================================================
   MAIN CYBER SEARCH BAR
   ========================================================= */

@Composable
fun CyberSearchBar(

    modifier: Modifier = Modifier,

    query: String,

    onQueryChange: (String) -> Unit,

    placeholder: String =
        "Search threats, analytics, logs...",

    searchType: CyberSearchBarType =
        CyberSearchBarType.DEFAULT,

    enabled: Boolean = true,

    showAIPulse: Boolean = true,

    showVoiceSearch: Boolean = true,

    onSearchClick: () -> Unit = {},

    onVoiceClick: () -> Unit = {}
) {

    val style =
        CyberSearchEngine.style(
            searchType
        )



    /*
    |--------------------------------------------------------------------------
    | SEARCH FOCUS STATE
    |--------------------------------------------------------------------------
    */

    var isFocused by remember {

        mutableStateOf(false)
    }



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
    | LIVE PULSE ANIMATION
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

                    animation = tween(1000),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | GLOW ANIMATION
    |--------------------------------------------------------------------------
    */

    val glowScale by infiniteTransition
        .animateFloat(

            initialValue = 1f,

            targetValue = 1.02f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1800),

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

        targetValue = if (
            isFocused
        )

            style.borderColor

        else

            style.borderColor.copy(
                alpha = 0.25f
            ),

        animationSpec =
            tween(400)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN SEARCH CONTAINER
    |--------------------------------------------------------------------------
    */

    Row(

        modifier = modifier
            .fillMaxWidth()
            .graphicsLayer {

                scaleX = glowScale

                scaleY = glowScale
            }
            .shadow(

                elevation =
                    if (isFocused)

                        SentriXShadow.Huge

                    else

                        SentriXShadow.Medium,

                shape =
                    RoundedCornerShape(
                        24.dp
                    ),

                ambientColor =
                    style.glowColor.copy(

                        alpha = if (
                            showAIPulse
                        )

                            pulseAlpha

                        else

                            0.18f
                    ),

                spotColor =
                    style.glowColor.copy(

                        alpha = if (
                            showAIPulse
                        )

                            pulseAlpha

                        else

                            0.18f
                    )
            )
            .clip(
                RoundedCornerShape(
                    24.dp
                )
            )
            .background(

                brush =
                    style.gradient
            )
            .border(

                width = if (
                    isFocused
                )

                    1.4.dp

                else

                    1.dp,

                color =
                    animatedBorderColor,

                shape =
                    RoundedCornerShape(
                        24.dp
                    )
            )
            .blur(0.15.dp)
            .padding(

                horizontal =
                    SentriXSpacing
                        .Large,

                vertical =
                    SentriXSpacing
                        .Medium
            ),

        verticalAlignment =
            Alignment.CenterVertically
    ) {

        /*
        |--------------------------------------------------------------------------
        | SEARCH ICON
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .size(42.dp)
                .clip(
                    CircleShape
                )
                .background(

                    color =
                        style.iconColor.copy(
                            alpha = 0.14f
                        )
                )
                .border(

                    width = 1.dp,

                    color =
                        style.iconColor.copy(
                            alpha = 0.25f
                        ),

                    shape =
                        CircleShape
                ),

            contentAlignment =
                Alignment.Center
        ) {

            Icon(

                imageVector =
                    Icons.Default.Search,

                contentDescription =
                    "Search",

                tint =
                    style.iconColor
            )
        }



        Spacer(
            modifier = Modifier.width(
                SentriXSpacing.Large
            )
        )



        /*
        |--------------------------------------------------------------------------
        | SEARCH FIELD
        |--------------------------------------------------------------------------
        */

        BasicTextField(

            value = query,

            onValueChange =
                onQueryChange,

            enabled = enabled,

            singleLine = true,

            textStyle = TextStyle(

                color =
                    Text_Primary,

                fontSize =
                    BodyTypography.Medium
                        .fontSize,

                fontWeight =
                    FontWeight.Medium
            ),

            interactionSource =
                interactionSource,

            modifier = Modifier
                .weight(1f)
                .onFocusChanged {

                    isFocused =
                        it.isFocused
                },

            cursorBrush =
                Brush.verticalGradient(

                    colors = listOf(

                        style.cursorColor,

                        style.cursorColor
                    )
                ),

            decorationBox = {

                innerTextField ->

                if (
                    query.isEmpty()
                ) {

                    Text(

                        text = placeholder,

                        style =
                            BodyTypography
                                .Medium,

                        color =
                            Text_Secondary
                    )
                }

                innerTextField()
            }
        )



        /*
        |--------------------------------------------------------------------------
        | AI LIVE INDICATOR
        |--------------------------------------------------------------------------
        */

        if (showAIPulse) {

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )

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
        }



        /*
        |--------------------------------------------------------------------------
        | CLEAR BUTTON
        |--------------------------------------------------------------------------
        */

        if (
            query.isNotEmpty()
        ) {

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )

            IconButton(

                onClick = {

                    onQueryChange("")
                }

            ) {

                Icon(

                    imageVector =
                        Icons.Default.Close,

                    contentDescription =
                        "Clear Search",

                    tint =
                        Text_Secondary
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | VOICE SEARCH
        |--------------------------------------------------------------------------
        */

        if (showVoiceSearch) {

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )

            Box(

                modifier = Modifier
                    .size(44.dp)
                    .clip(
                        CircleShape
                    )
                    .background(

                        color =
                            style.iconColor.copy(
                                alpha = 0.14f
                            )
                    )
                    .border(

                        width = 1.dp,

                        color =
                            style.iconColor.copy(
                                alpha = 0.22f
                            ),

                        shape =
                            CircleShape
                    ),

                contentAlignment =
                    Alignment.Center
            ) {

                IconButton(

                    onClick =
                        onVoiceClick
                ) {

                    Icon(

                        imageVector =
                            Icons.Default.Mic,

                        contentDescription =
                            "Voice Search",

                        tint =
                            style.iconColor
                    )
                }
            }
        }
    }
}



/* =========================================================
   MINI SEARCH BAR
   ========================================================= */

@Composable
fun MiniCyberSearchBar(

    query: String,

    onQueryChange: (String) -> Unit
) {

    CyberSearchBar(

        query = query,

        onQueryChange =
            onQueryChange,

        showVoiceSearch = false,

        showAIPulse = false
    )
}



/* =========================================================
   AI SEARCH BAR
   ========================================================= */

@Composable
fun AISearchBar(

    query: String,

    onQueryChange: (String) -> Unit
) {

    CyberSearchBar(

        query = query,

        onQueryChange =
            onQueryChange,

        searchType =
            CyberSearchBarType.AI,

        placeholder =
            "Ask SentriX AI..."
    )
}



/* =========================================================
   THREAT SEARCH BAR
   ========================================================= */

@Composable
fun ThreatSearchBar(

    query: String,

    onQueryChange: (String) -> Unit
) {

    CyberSearchBar(

        query = query,

        onQueryChange =
            onQueryChange,

        searchType =
            CyberSearchBarType.THREAT,

        placeholder =
            "Search active threats..."
    )
}



/* =========================================================
   FUTURE SEARCH ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI predictive search
| ✔ Voice AI search engine
| ✔ GPU holographic search UI
| ✔ Threat intelligence search
| ✔ Dynamic cyber-grid overlays
| ✔ Runtime adaptive search engine
| ✔ Quantum analytics search
| ✔ VR/AR search rendering
| ✔ Real-time global threat lookup
| ✔ Neural command interface
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX CYBER SEARCH BAR
|--------------------------------------------------------------------------
*/
