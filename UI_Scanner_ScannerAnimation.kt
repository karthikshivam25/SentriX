package com.sentrix.ui.scanner

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.unit.dp

@Composable
fun ScannerAnimation(
    modifier: Modifier = Modifier,
    scannerColor: Color = Color.Cyan
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "scanner_animation"
    )

    // Rotating Sweep
    val rotationAnimation = infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2600,
                easing = LinearEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    // Pulse Effect
    val pulseAnimation = infiniteTransition.animateFloat(
        initialValue = 0.65f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1400,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )

    // Radar Sweep Alpha
    val radarAlphaAnimation = infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1600
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "alpha"
    )

    Box(
        modifier = modifier
            .size(220.dp),
        contentAlignment = Alignment.Center
    ) {

        // Outer Pulse Circle
        Box(
            modifier = Modifier
                .size(220.dp)
                .alpha(pulseAnimation.value * 0.25f)
                .clip(CircleShape)
                .background(scannerColor)
        )

        // Middle Pulse Circle
        Box(
            modifier = Modifier
                .size(170.dp)
                .alpha(pulseAnimation.value * 0.18f)
                .clip(CircleShape)
                .background(scannerColor)
        )

        // Radar Canvas
        Canvas(
            modifier = Modifier.size(180.dp)
        ) {

            drawCircle(
                color = scannerColor.copy(alpha = 0.12f),
                style = Stroke(
                    width = 6.dp.toPx()
                )
            )

            drawArc(
                brush = Brush.sweepGradient(
                    listOf(
                        scannerColor.copy(alpha = 0.05f),
                        scannerColor.copy(alpha = radarAlphaAnimation.value),
                        scannerColor.copy(alpha = 0.05f)
                    )
                ),
                startAngle = rotationAnimation.value,
                sweepAngle = 90f,
                useCenter = false,
                style = Stroke(
                    width = 10.dp.toPx(),
                    cap = StrokeCap.Round
                )
            )
        }

        // Core Scanner Ring
        Box(
            modifier = Modifier
                .size(110.dp)
                .clip(CircleShape)
                .background(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            Color(0xFF172554),
                            Color(0xFF0F172A)
                        )
                    )
                ),
            contentAlignment = Alignment.Center
        ) {

            // Rotating Shield
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = null,
                tint = scannerColor,
                modifier = Modifier
                    .size(54.dp)
                    .graphicsLayer {
                        rotationZ = rotationAnimation.value
                    }
            )
        }
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

ScannerAnimation()

OR

ScannerAnimation(
    scannerColor = Color(0xFF00E676)
)

---------------------------------------------------
OPTIONAL SCREEN PREVIEW
---------------------------------------------------

Box(
    modifier = Modifier
        .fillMaxSize()
        .background(Color(0xFF0B1120)),
    contentAlignment = Alignment.Center
) {

    ScannerAnimation()
}

*/
