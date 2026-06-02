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
import androidx.compose.material.icons.rounded.Insights
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
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
fun SecurityTrendChart(
    modifier: Modifier = Modifier,
    trendData: List<Float> = listOf(25f, 40f, 35f, 58f, 46f, 72f, 88f),
    labels: List<String> = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul")
) {

    val animationProgress by animateFloatAsState(
        targetValue = 1f,
        label = "SecurityTrendAnimation"
    )

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
                        .size(54.dp)
                        .background(
                            brush = Brush.linearGradient(
                                colors = listOf(
                                    Color(0xFF00C6FF),
                                    Color(0xFF0072FF)
                                )
                            ),
                            shape = RoundedCornerShape(16.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Rounded.Insights,
                        contentDescription = "Security Trends",
                        tint = Color.White,
                        modifier = Modifier.size(28.dp)
                    )
                }

                Spacer(modifier = Modifier.size(14.dp))

                Column {

                    Text(
                        text = "Security Trend Analysis",
                        color = Color.White,
                        fontSize = 19.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "AI powered protection insights",
                        color = Color(0xFF9CA3AF),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(30.dp))

            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(240.dp)
            ) {

                val chartWidth = size.width
                val chartHeight = size.height

                val maxValue = trendData.maxOrNull() ?: 100f
                val minValue = trendData.minOrNull() ?: 0f

                val spacing = chartWidth / (trendData.size - 1)

                val points = trendData.mapIndexed { index, value ->

                    val x = spacing * index

                    val normalized =
                        (value - minValue) / (maxValue - minValue)

                    val y =
                        chartHeight - (normalized * chartHeight * 0.85f)

                    Offset(x, y)
                }

                // Grid Lines
                repeat(5) { index ->

                    val y = chartHeight / 5 * index

                    drawLine(
                        color = Color(0x20FFFFFF),
                        start = Offset(0f, y),
                        end = Offset(chartWidth, y),
                        strokeWidth = 1.5f
                    )
                }

                // Gradient Area
                val areaPath = Path().apply {

                    moveTo(points.first().x, chartHeight)

                    points.forEach { point ->
                        lineTo(point.x, point.y)
                    }

                    lineTo(points.last().x, chartHeight)
                    close()
                }

                drawPath(
                    path = areaPath,
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0x5500C6FF),
                            Color.Transparent
                        )
                    )
                )

                // Main Line
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
                    color = Color(0xFF00C6FF),
                    style = Stroke(
                        width = 7f,
                        cap = StrokeCap.Round
                    )
                )

                // Data Points
                points.forEach { point ->

                    drawCircle(
                        color = Color.White,
                        radius = 11f * animationProgress,
                        center = point
                    )

                    drawCircle(
                        color = Color(0xFF0072FF),
                        radius = 6f * animationProgress,
                        center = point
                    )
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // Labels
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                labels.forEach { label ->

                    Text(
                        text = label,
                        color = Color(0xFF9CA3AF),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            Spacer(modifier = Modifier.height(26.dp))

            // Footer Stats
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                SecurityTrendStat(
                    title = "Threats Reduced",
                    value = "84%",
                    accentColor = Color(0xFF00E676)
                )

                SecurityTrendStat(
                    title = "AI Accuracy",
                    value = "98.2%",
                    accentColor = Color(0xFF00C6FF)
                )

                SecurityTrendStat(
                    title = "Realtime Scan",
                    value = "ACTIVE",
                    accentColor = Color(0xFFFF5252)
                )
            }
        }
    }
}

@Composable
fun SecurityTrendStat(
    title: String,
    value: String,
    accentColor: Color
) {

    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Text(
            text = value,
            color = accentColor,
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = title,
            color = Color(0xFFB0B7C3),
            fontSize = 11.sp
        )
    }
}
