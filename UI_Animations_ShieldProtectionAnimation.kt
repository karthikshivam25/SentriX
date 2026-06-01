package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.unit.dp
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun ShieldProtectionAnimation(
    modifier: Modifier = Modifier,
    isProtected: Boolean = true
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "shield_protection_animation"
    )

    // Shield glow pulse
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.25f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1800,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    // Rotating ring
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 10000,
                easing = LinearEasing
            )
        ),
        label = "rotation"
    )

    // Scanning pulse
    val scanPulse by infiniteTransition.animateFloat(
        initialValue = 0.9f,
        targetValue = 1.1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2200,
                easing = EaseInOutCubic
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scan_pulse"
    )

    val primaryColor = if (isProtected) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFF5252)
    }

    val secondaryColor = if (isProtected) {
        Color(0xFF00C853)
    } else {
        Color(0xFFFF1744)
    }

    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {

        // OUTER GLOW
        Box(
            modifier = Modifier
                .size(240.dp)
                .blur(40.dp)
                .background(
                    color = primaryColor.copy(alpha = glowAlpha * 0.25f),
                    shape = CircleShape
                )
        )

        Canvas(
            modifier = Modifier.size(260.dp)
        ) {

            val center = Offset(size.width / 2f, size.height / 2f)
            val radius = size.minDimension / 2.5f

            // OUTER CYBER RING
            drawCircle(
                color = primaryColor.copy(alpha = 0.18f),
                radius = radius * 1.15f,
                center = center,
                style = Stroke(width = 5f)
            )

            // ROTATING SEGMENT RING
            rotate(rotation) {

                repeat(12) { index ->

                    val angle = Math.toRadians((index * 30).toDouble())

                    val startX =
                        center.x + (radius * 1.05f * cos(angle)).toFloat()

                    val startY =
                        center.y + (radius * 1.05f * sin(angle)).toFloat()

                    val endX =
                        center.x + (radius * 1.18f * cos(angle)).toFloat()

                    val endY =
                        center.y + (radius * 1.18f * sin(angle)).toFloat()

                    drawLine(
                        brush = Brush.linearGradient(
                            colors = listOf(
                                primaryColor.copy(alpha = 0.2f),
                                primaryColor
                            )
                        ),
                        start = Offset(startX, startY),
                        end = Offset(endX, endY),
                        strokeWidth = 5f,
                        cap = StrokeCap.Round
                    )
                }
            }

            // INNER SHIELD GLOW
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        primaryColor.copy(alpha = 0.35f),
                        Color.Transparent
                    )
                ),
                radius = radius * scanPulse,
                center = center
            )

            // SHIELD BODY
            val shieldPath = Path().apply {

                moveTo(center.x, center.y - radius * 0.72f)

                cubicTo(
                    center.x + radius * 0.72f,
                    center.y - radius * 0.5f,
                    center.x + radius * 0.72f,
                    center.y + radius * 0.2f,
                    center.x,
                    center.y + radius * 0.85f
                )

                cubicTo(
                    center.x - radius * 0.72f,
                    center.y + radius * 0.2f,
                    center.x - radius * 0.72f,
                    center.y - radius * 0.5f,
                    center.x,
                    center.y - radius * 0.72f
                )

                close()
            }

            // SHIELD FILL
            drawPath(
                path = shieldPath,
                brush = Brush.verticalGradient(
                    colors = listOf(
                        primaryColor.copy(alpha = 0.9f),
                        secondaryColor.copy(alpha = 0.5f)
                    )
                )
            )

            // SHIELD BORDER
            drawPath(
                path = shieldPath,
                color = Color.White.copy(alpha = 0.75f),
                style = Stroke(
                    width = 4f
                )
            )

            // CYBER GRID LINES
            drawLine(
                color = Color.White.copy(alpha = 0.18f),
                start = Offset(center.x, center.y - radius * 0.52f),
                end = Offset(center.x, center.y + radius * 0.55f),
                strokeWidth = 2f
            )

            drawLine(
                color = Color.White.copy(alpha = 0.12f),
                start = Offset(center.x - radius * 0.35f, center.y),
                end = Offset(center.x + radius * 0.35f, center.y),
                strokeWidth = 2f
            )

            // SECURITY CHECK ICON
            if (isProtected) {

                val checkPath = Path().apply {

                    moveTo(
                        center.x - radius * 0.22f,
                        center.y + radius * 0.02f
                    )

                    lineTo(
                        center.x - radius * 0.05f,
                        center.y + radius * 0.22f
                    )

                    lineTo(
                        center.x + radius * 0.25f,
                        center.y - radius * 0.16f
                    )
                }

                drawPath(
                    path = checkPath,
                    color = Color.White,
                    style = Stroke(
                        width = 10f,
                        cap = StrokeCap.Round,
                        join = StrokeJoin.Round
                    )
                )
            } else {

                // WARNING SYMBOL
                drawRoundRect(
                    color = Color.White,
                    topLeft = Offset(
                        center.x - 5f,
                        center.y - radius * 0.2f
                    ),
                    size = Size(
                        10f,
                        radius * 0.32f
                    ),
                    cornerRadius = CornerRadius(5f)
                )

                drawCircle(
                    color = Color.White,
                    radius = 7f,
                    center = Offset(
                        center.x,
                        center.y + radius * 0.28f
                    )
                )
            }

            // PARTICLE ORBITS
            repeat(6) { index ->

                val angle = Math.toRadians(
                    (rotation * 1.5f + index * 60).toDouble()
                )

                val orbitRadius = radius * 1.28f

                val x =
                    center.x + orbitRadius * cos(angle).toFloat()

                val y =
                    center.y + orbitRadius * sin(angle).toFloat()

                drawCircle(
                    color = primaryColor.copy(alpha = 0.9f),
                    radius = 5f,
                    center = Offset(x, y)
                )
            }
        }
    }
}
