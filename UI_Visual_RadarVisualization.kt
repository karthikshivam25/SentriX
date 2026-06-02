package com.sentrix.ui.visual

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
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun RadarVisualizationCard() {

    val radarData = listOf(
        RadarMetric("Firewall", 0.92f),
        RadarMetric("Privacy", 0.81f),
        RadarMetric("Scanner", 0.96f),
        RadarMetric("Encryption", 0.74f),
        RadarMetric("Network", 0.88f)
    )

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
                        imageVector = Icons.Default.Radar,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8)
                    )
                }

                Column(
                    modifier = Modifier.padding(start = 14.dp)
                ) {

                    Text(
                        text = "Radar Visualization",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Advanced protection metrics overview",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(30.dp))

            RadarChart(
                data = radarData
            )

            Spacer(modifier = Modifier.height(28.dp))

            RadarLegendSection(
                data = radarData
            )
        }
    }
}

data class RadarMetric(
    val label: String,
    val value: Float
)

@Composable
fun RadarChart(
    data: List<RadarMetric>
) {

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(320.dp)
    ) {

        val centerX = size.width / 2
        val centerY = size.height / 2

        val radius = size.minDimension / 3

        val angleStep =
            (2 * Math.PI / data.size).toFloat()

        repeat(5) { level ->

            val levelRadius =
                radius * ((level + 1) / 5f)

            drawCircle(
                color = Color(0xFF1E293B),
                radius = levelRadius,
                center = Offset(centerX, centerY),
                style = Stroke(width = 2f)
            )
        }

        data.forEachIndexed { index, _ ->

            val angle = angleStep * index - (Math.PI / 2).toFloat()

            val endX =
                centerX + cos(angle) * radius

            val endY =
                centerY + sin(angle) * radius

            drawLine(
                color = Color(0xFF334155),
                start = Offset(centerX, centerY),
                end = Offset(endX, endY),
                strokeWidth = 2f
            )
        }

        val radarPath = Path()

        data.forEachIndexed { index, item ->

            val angle = angleStep * index - (Math.PI / 2).toFloat()

            val pointRadius = radius * item.value

            val x =
                centerX + cos(angle) * pointRadius

            val y =
                centerY + sin(angle) * pointRadius

            if (index == 0) {
                radarPath.moveTo(x, y)
            } else {
                radarPath.lineTo(x, y)
            }
        }

        radarPath.close()

        drawPath(
            path = radarPath,
            brush = Brush.radialGradient(
                colors = listOf(
                    Color(0xFF38BDF8).copy(alpha = 0.55f),
                    Color(0xFF2563EB).copy(alpha = 0.15f)
                ),
                center = Offset(centerX, centerY),
                radius = radius
            )
        )

        drawPath(
            path = radarPath,
            color = Color(0xFF38BDF8),
            style = Stroke(
                width = 5f,
                cap = StrokeCap.Round
            )
        )

        data.forEachIndexed { index, item ->

            val angle = angleStep * index - (Math.PI / 2).toFloat()

            val pointRadius = radius * item.value

            val x =
                centerX + cos(angle) * pointRadius

            val y =
                centerY + sin(angle) * pointRadius

            drawCircle(
                color = Color(0xFF7DD3FC),
                radius = 10f,
                center = Offset(x, y)
            )

            drawCircle(
                color = Color(0xFF0F172A),
                radius = 4f,
                center = Offset(x, y)
            )
        }
    }
}

@Composable
fun RadarLegendSection(
    data: List<RadarMetric>
) {

    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        data.forEach { metric ->

            RadarLegendItem(
                title = metric.label,
                percentage = "${(metric.value * 100).toInt()}%"
            )
        }
    }
}

@Composable
fun RadarLegendItem(
    title: String,
    percentage: String
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {

        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {

            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(
                        color = Color(0xFF38BDF8),
                        shape = RoundedCornerShape(50)
                    )
            )

            Spacer(modifier = Modifier.size(10.dp))

            Text(
                text = title,
                color = Color.White,
                fontWeight = FontWeight.Medium,
                fontSize = 14.sp
            )
        }

        Text(
            text = percentage,
            color = Color(0xFF7DD3FC),
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp
        )
    }
}
