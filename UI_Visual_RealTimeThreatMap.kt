package com.sentrix.ui.visual

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun RealTimeThreatMapCard() {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(24.dp)
            )
            .padding(20.dp)
    ) {

        Column {

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(
                            color = Color(0xFF1E293B),
                            shape = RoundedCornerShape(14.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Public,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8)
                    )
                }

                Column(
                    modifier = Modifier.padding(start = 14.dp)
                ) {

                    Text(
                        text = "Real-Time Threat Map",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Global live cyber activity monitoring",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(30.dp))

            ThreatMapVisualization()

            Spacer(modifier = Modifier.height(24.dp))

            ThreatMapLegend()
        }
    }
}

@Composable
fun ThreatMapVisualization() {

    val infiniteTransition = rememberInfiniteTransition(
        label = "threat_map_animation"
    )

    val animatedSweep by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 5000,
                easing = LinearEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "radar_sweep"
    )

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(320.dp)
    ) {

        val center = Offset(
            x = size.width / 2,
            y = size.height / 2
        )

        val radius = size.minDimension / 2.6f

        repeat(4) { level ->

            drawCircle(
                color = Color(0xFF1E293B),
                radius = radius * ((level + 1) / 4f),
                center = center,
                style = Stroke(width = 2f)
            )
        }

        repeat(8) { index ->

            val angle =
                Math.toRadians((index * 45).toDouble())

            val endX =
                center.x + cos(angle).toFloat() * radius

            val endY =
                center.y + sin(angle).toFloat() * radius

            drawLine(
                color = Color(0xFF233047),
                start = center,
                end = Offset(endX, endY),
                strokeWidth = 2f
            )
        }

        val sweepAngle =
            Math.toRadians(animatedSweep.toDouble())

        val sweepX =
            center.x + cos(sweepAngle).toFloat() * radius

        val sweepY =
            center.y + sin(sweepAngle).toFloat() * radius

        drawLine(
            brush = Brush.linearGradient(
                colors = listOf(
                    Color(0xFF38BDF8),
                    Color.Transparent
                )
            ),
            start = center,
            end = Offset(sweepX, sweepY),
            strokeWidth = 8f,
            cap = StrokeCap.Round
        )

        val threatPoints = listOf(
            Offset(center.x - 110f, center.y - 40f),
            Offset(center.x + 70f, center.y - 90f),
            Offset(center.x + 120f, center.y + 45f),
            Offset(center.x - 80f, center.y + 95f),
            Offset(center.x + 15f, center.y + 30f)
        )

        threatPoints.forEachIndexed { index, point ->

            val pointColor =
                when (index % 3) {
                    0 -> Color(0xFFEF4444)
                    1 -> Color(0xFFFACC15)
                    else -> Color(0xFF22C55E)
                }

            drawCircle(
                color = pointColor.copy(alpha = 0.18f),
                radius = 24f,
                center = point
            )

            drawCircle(
                color = pointColor,
                radius = 9f,
                center = point
            )

            drawCircle(
                color = Color.White,
                radius = 3f,
                center = point
            )
        }

        drawCircle(
            color = Color(0xFF38BDF8),
            radius = 16f,
            center = center
        )

        drawCircle(
            color = Color.White,
            radius = 5f,
            center = center
        )
    }
}

@Composable
fun ThreatMapLegend() {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        ThreatMapLegendItem(
            color = Color(0xFFEF4444),
            label = "Critical"
        )

        ThreatMapLegendItem(
            color = Color(0xFFFACC15),
            label = "Medium"
        )

        ThreatMapLegendItem(
            color = Color(0xFF22C55E),
            label = "Protected"
        )
    }
}

@Composable
fun ThreatMapLegendItem(
    color: Color,
    label: String
) {

    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(
            modifier = Modifier
                .size(12.dp)
                .background(
                    color = color,
                    shape = RoundedCornerShape(50)
                )
        )

        Spacer(modifier = Modifier.size(8.dp))

        Text(
            text = label,
            color = Color(0xFFCBD5E1),
            fontSize = 13.sp
        )
    }
}
