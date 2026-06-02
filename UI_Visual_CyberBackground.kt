package com.sentrix.ui.visual

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import kotlin.random.Random

@Composable
fun CyberBackground() {

    val infiniteTransition = rememberInfiniteTransition(
        label = "cyber_background_animation"
    )

    val animatedOffset by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1200f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 12000,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "cyber_offset"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF020617),
                        Color(0xFF0F172A),
                        Color(0xFF111827)
                    )
                )
            )
    ) {

        Canvas(
            modifier = Modifier.fillMaxSize()
        ) {

            val randomSeed = Random(42)

            repeat(80) {

                val startX =
                    randomSeed.nextFloat() * size.width

                val startY =
                    (randomSeed.nextFloat() * size.height) +
                            (animatedOffset % size.height)

                val endX =
                    startX + randomSeed.nextInt(-180, 180)

                val endY =
                    startY + randomSeed.nextInt(40, 220)

                drawLine(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF38BDF8).copy(alpha = 0.10f),
                            Color(0xFF2563EB).copy(alpha = 0.04f)
                        )
                    ),
                    start = Offset(
                        x = startX,
                        y = startY % size.height
                    ),
                    end = Offset(
                        x = endX,
                        y = endY % size.height
                    ),
                    strokeWidth = 2f,
                    pathEffect = PathEffect.dashPathEffect(
                        intervals = floatArrayOf(14f, 10f),
                        phase = animatedOffset
                    )
                )
            }

            repeat(45) {

                val circleX =
                    randomSeed.nextFloat() * size.width

                val circleY =
                    ((randomSeed.nextFloat() * size.height) +
                            animatedOffset * 0.15f) % size.height

                val radius =
                    randomSeed.nextInt(3, 10).toFloat()

                drawCircle(
                    color = Color(0xFF38BDF8).copy(alpha = 0.08f),
                    radius = radius,
                    center = Offset(circleX, circleY)
                )
            }

            repeat(18) {

                val squareX =
                    randomSeed.nextFloat() * size.width

                val squareY =
                    ((randomSeed.nextFloat() * size.height) -
                            animatedOffset * 0.08f) % size.height

                drawRect(
                    color = Color(0xFF22C55E).copy(alpha = 0.05f),
                    topLeft = Offset(squareX, squareY),
                    size = androidx.compose.ui.geometry.Size(
                        width = 18f,
                        height = 18f
                    ),
                    style = Stroke(width = 2f)
                )
            }
        }
    }
}
