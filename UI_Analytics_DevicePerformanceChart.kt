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
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun DevicePerformanceChart(
    modifier: Modifier = Modifier,
    cpuUsage: Float = 0.42f,
    ramUsage: Float = 0.63f,
    storageUsage: Float = 0.71f,
    performanceData: List<Float> = listOf(22f, 38f, 30f, 65f, 54f, 48f, 76f)
) {

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF131A24)
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 10.dp
        )
    ) {

        Column(
            modifier = Modifier.padding(22.dp)
        ) {

            // Header
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .background(
                            brush = Brush.linearGradient(
                                colors = listOf(
                                    Color(0xFF7C4DFF),
                                    Color(0xFF651FFF)
                                )
                            ),
                            shape = RoundedCornerShape(18.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Rounded.Speed,
                        contentDescription = "Performance Chart",
                        tint = Color.White,
                        modifier = Modifier.size(30.dp)
                    )
                }

                Spacer(modifier = Modifier.size(14.dp))

                Column {

                    Text(
                        text = "Device Performance",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Realtime device resource analytics",
                        color = Color(0xFF9CA3AF),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            // Graph
            PerformanceGraph(
                performanceData = performanceData
            )

            Spacer(modifier = Modifier.height(28.dp))

            // Metrics
            PerformanceMetricRow(
                icon = Icons.Rounded.Memory,
                title = "CPU Usage",
                progress = cpuUsage,
                color = Color(0xFF00E676)
            )

            Spacer(modifier = Modifier.height(18.dp))

            PerformanceMetricRow(
                icon = Icons.Rounded.Speed,
                title = "RAM Usage",
                progress = ramUsage,
                color = Color(0xFF00C6FF)
            )

            Spacer(modifier = Modifier.height(18.dp))

            PerformanceMetricRow(
                icon = Icons.Rounded.Storage,
                title = "Storage Usage",
                progress = storageUsage,
                color = Color(0xFFFFC107)
            )
        }
    }
}

@Composable
fun PerformanceGraph(
    performanceData: List<Float>
) {

    val animationProgress by animateFloatAsState(
        targetValue = 1f,
        label = "PerformanceGraphAnimation"
    )

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(220.dp)
    ) {

        val chartWidth = size.width
        val chartHeight = size.height

        val maxValue = performanceData.maxOrNull() ?: 100f
        val minValue = performanceData.minOrNull() ?: 0f

        val spacing = chartWidth / (performanceData.size - 1)

        val points = performanceData.mapIndexed { index, value ->

            val x = spacing * index

            val normalized =
                (value - minValue) / (maxValue - minValue)

            val y =
                chartHeight - (normalized * chartHeight * 0.85f)

            Offset(x, y)
        }

        // Grid lines
        repeat(5) { index ->

            val y = chartHeight / 5 * index

            drawLine(
                color = Color(0x20FFFFFF),
                start = Offset(0f, y),
                end = Offset(chartWidth, y),
                strokeWidth = 1.5f
            )
        }

        // Gradient fill
        val fillPath = Path().apply {

            moveTo(points.first().x, chartHeight)

            points.forEach { point ->
                lineTo(point.x, point.y)
            }

            lineTo(points.last().x, chartHeight)
            close()
        }

        drawPath(
            path = fillPath,
            brush = Brush.verticalGradient(
                colors = listOf(
                    Color(0x557C4DFF),
                    Color.Transparent
                )
            )
        )

        // Main line
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
            color = Color(0xFF7C4DFF),
            style = Stroke(
                width = 7f,
                cap = StrokeCap.Round
            )
        )

        // Points
        points.forEach { point ->

            drawCircle(
                color = Color.White,
                radius = 10f * animationProgress,
                center = point
            )

            drawCircle(
                color = Color(0xFF7C4DFF),
                radius = 6f * animationProgress,
                center = point
            )
        }
    }
}

@Composable
fun PerformanceMetricRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    progress: Float,
    color: Color
) {

    val animatedProgress by animateFloatAsState(
        targetValue = progress,
        label = title
    )

    Column {

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
                        .size(42.dp)
                        .background(
                            color = color.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(14.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = icon,
                        contentDescription = title,
                        tint = color,
                        modifier = Modifier.size(22.dp)
                    )
                }

                Spacer(modifier = Modifier.size(12.dp))

                Text(
                    text = title,
                    color = Color(0xFFE5E7EB),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium
                )
            }

            Text(
                text = "${(animatedProgress * 100).toInt()}%",
                color = color,
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        LinearProgressIndicator(
            progress = { animatedProgress },
            modifier = Modifier
                .fillMaxWidth()
                .height(8.dp),
            color = color,
            trackColor = Color(0xFF2A3342)
        )
    }
}
