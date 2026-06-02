package com.sentrix.ui.analytics

import androidx.compose.animation.core.animateFloatAsState
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
import androidx.compose.material.icons.rounded.ShowChart
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun ThreatGraph(
    modifier: Modifier = Modifier,
    graphData: List<Float> = listOf(18f, 42f, 30f, 75f, 52f, 90f, 66f),
    labels: List<String> = listOf("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
) {

    val animatedProgress by animateFloatAsState(
        targetValue = 1f,
        label = "ThreatGraphAnimation"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF151A24)
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 8.dp
        )
    ) {

        Column(
            modifier = Modifier.padding(20.dp)
        ) {

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {

                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .background(
                            brush = Brush.linearGradient(
                                colors = listOf(
                                    Color(0xFFFF5252),
                                    Color(0xFFFF1744)
                                )
                            ),
                            shape = RoundedCornerShape(16.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Rounded.ShowChart,
                        contentDescription = "Threat Graph",
                        tint = Color.White,
                        modifier = Modifier.size(28.dp)
                    )
                }

                Column {

                    Text(
                        text = "Threat Detection Graph",
                        color = Color.White,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Realtime security threat analytics",
                        color = Color(0xFF9AA4B2),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(220.dp)
            ) {

                val maxValue = graphData.maxOrNull() ?: 100f
                val minValue = graphData.minOrNull() ?: 0f

                val graphWidth = size.width
                val graphHeight = size.height

                val spacing = graphWidth / (graphData.size - 1)

                val points = graphData.mapIndexed { index, value ->

                    val x = spacing * index

                    val normalizedValue =
                        (value - minValue) / (maxValue - minValue)

                    val y =
                        graphHeight - (normalizedValue * graphHeight * 0.9f)

                    Offset(x, y)
                }

                // Grid lines
                repeat(5) { index ->

                    val y = graphHeight / 5 * index

                    drawLine(
                        color = Color(0x22FFFFFF),
                        start = Offset(0f, y),
                        end = Offset(graphWidth, y),
                        strokeWidth = 1.5f
                    )
                }

                // Gradient fill path
                val fillPath = Path().apply {

                    moveTo(points.first().x, graphHeight)

                    points.forEach { point ->
                        lineTo(point.x, point.y)
                    }

                    lineTo(points.last().x, graphHeight)
                    close()
                }

                drawPath(
                    path = fillPath,
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0x55FF5252),
                            Color.Transparent
                        )
                    )
                )

                // Main line path
                val linePath = Path().apply {

                    points.forEachIndexed { index, point ->

                        if (index == 0) {
                            moveTo(point.x, point.y)
                        } else {
                            lineTo(point.x, point.y)
                        }
                    }
                }

                drawPath(
                    path = linePath,
                    color = Color(0xFFFF5252),
                    style = Stroke(
                        width = 6f,
                        cap = StrokeCap.Round
                    )
                )

                // Points
                points.forEach { point ->

                    drawCircle(
                        color = Color.White,
                        radius = 10f * animatedProgress,
                        center = point
                    )

                    drawCircle(
                        color = Color(0xFFFF1744),
                        radius = 6f * animatedProgress,
                        center = point
                    )
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                labels.forEach { label ->

                    Text(
                        text = label,
                        color = Color(0xFF9AA4B2),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                ThreatLegendItem(
                    color = Color(0xFFFF5252),
                    title = "Critical Threats"
                )

                ThreatLegendItem(
                    color = Color(0xFF00E5FF),
                    title = "Network Events"
                )

                ThreatLegendItem(
                    color = Color(0xFF00E676),
                    title = "Protected"
                )
            }
        }
    }
}

@Composable
fun ThreatLegendItem(
    color: Color,
    title: String
) {

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {

        Box(
            modifier = Modifier
                .size(10.dp)
                .background(
                    color = color,
                    shape = RoundedCornerShape(50)
                )
        )

        Text(
            text = title,
            color = Color(0xFFD1D5DB),
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium
        )
    }
}
