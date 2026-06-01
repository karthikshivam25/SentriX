package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun VPNConnectAnimation(
    modifier: Modifier = Modifier,
    isConnected: Boolean = false
) {

    val infiniteTransition = rememberInfiniteTransition(label = "vpn_connect")

    // Pulse animation
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 1.4f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1800,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_scale"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.6f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1800),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_alpha"
    )

    // Rotating ring
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 6000,
                easing = LinearEasing
            )
        ),
        label = "rotation"
    )

    // Scanning effect
    val scanSweep by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2500,
                easing = LinearEasing
            )
        ),
        label = "scan_sweep"
    )

    val mainColor = if (isConnected) {
        Color(0xFF00E676)
    } else {
        Color(0xFF00D9FF)
    }

    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {

        Canvas(
            modifier = Modifier.size(260.dp)
        ) {

            val canvasWidth = size.width
            val canvasHeight = size.height
            val center = Offset(canvasWidth / 2, canvasHeight / 2)

            // OUTER PULSE
            drawCircle(
                color = mainColor.copy(alpha = pulseAlpha),
                radius = size.minDimension * 0.35f * pulseScale,
                center = center,
                style = Stroke(width = 6f)
            )

            // SECOND PULSE
            drawCircle(
                color = mainColor.copy(alpha = pulseAlpha * 0.5f),
                radius = size.minDimension * 0.28f * pulseScale,
                center = center,
                style = Stroke(width = 3f)
            )

            // MAIN CORE RING
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        mainColor.copy(alpha = 0.8f),
                        mainColor.copy(alpha = 0.1f)
                    )
                ),
                radius = size.minDimension * 0.23f,
                center = center
            )

            // STATIC OUTER RING
            drawCircle(
                color = mainColor.copy(alpha = 0.25f),
                radius = size.minDimension * 0.33f,
                center = center,
                style = Stroke(width = 4f)
            )

            // ROTATING CYBER DOTS
            repeat(8) { index ->

                val angle = Math.toRadians((rotation + (index * 45)).toDouble())

                val orbitRadius = size.minDimension * 0.33f

                val x = center.x + orbitRadius * cos(angle).toFloat()
                val y = center.y + orbitRadius * sin(angle).toFloat()

                drawCircle(
                    color = mainColor,
                    radius = 6f,
                    center = Offset(x, y)
                )
            }

            // SCANNING ARC
            drawArc(
                brush = Brush.sweepGradient(
                    colors = listOf(
                        Color.Transparent,
                        mainColor.copy(alpha = 0.9f),
                        Color.Transparent
                    )
                ),
                startAngle = scanSweep,
                sweepAngle = 45f,
                useCenter = false,
                topLeft = Offset(
                    center.x - size.minDimension * 0.28f,
                    center.y - size.minDimension * 0.28f
                ),
                size = Size(
                    size.minDimension * 0.56f,
                    size.minDimension * 0.56f
                ),
                style = Stroke(width = 8f)
            )

            // INNER CORE
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        Color.White,
                        mainColor
                    )
                ),
                radius = size.minDimension * 0.09f,
                center = center
            )
        }
 
        // CENTER LOCK ICON EFFECT
        Box(
            modifier = Modifier
                .size(42.dp)
                .background(
                    color = Color.White.copy(alpha = 0.08f),
                    shape = CircleShape
                ),
            contentAlignment = Alignment.Center
        ) {

            Canvas(
                modifier = Modifier.size(22.dp)
            ) {

                val stroke = 3f
                val lockColor = mainColor

                // Lock body
                drawRoundRect(
                    color = lockColor,
                    topLeft = Offset(size.width * 0.2f, size.height * 0.45f),
                    size = Size(size.width * 0.6f, size.height * 0.4f),
                    cornerRadius = CornerRadius(6f, 6f)
                )

                // Lock shackle
                drawArc(
                    color = lockColor,
                    startAngle = 180f,
                    sweepAngle = 180f,
                    useCenter = false,
                    topLeft = Offset(size.width * 0.28f, size.height * 0.1f),
                    size = Size(size.width * 0.44f, size.height * 0.5f),
                    style = Stroke(width = stroke)
                )
            }
        }
    }
}
