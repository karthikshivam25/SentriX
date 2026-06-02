package com.sentrix.ui.threats

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.min

data class ThreatAnalyticsData(
    val totalThreats: Int,
    val blockedThreats: Int,
    val criticalThreats: Int,
    val protectionScore: Int,
    val weeklyThreatIncrease: Int
)

@Composable
fun ThreatAnalyticsCard(

    data: ThreatAnalyticsData,
    modifier: Modifier = Modifier
) {

    val protectionProgress by animateFloatAsState(
        targetValue = data.protectionScore / 100f,
        label = "protection_progress"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 6.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF1A1F35),
                            Color(0xFF101728)
                        )
                    )
                )
                .padding(22.dp)
        ) {

            Column {

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Icon(
                        imageVector = Icons.Default.Analytics,
                        contentDescription = null,
                        tint = Color(0xFF00E5FF)
                    )

                    Spacer(modifier = Modifier.width(10.dp))

                    Text(
                        text = "Threat Analytics",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(28.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    ThreatProtectionMeter(
                        protectionScore = data.protectionScore,
                        progress = protectionProgress
                    )

                    Column(
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {

                        AnalyticsStatItem(
                            title = "Total Threats",
                            value = data.totalThreats.toString(),
                            valueColor = Color.White
                        )

                        AnalyticsStatItem(
                            title = "Blocked",
                            value = data.blockedThreats.toString(),
                            valueColor = Color(0xFF00E676)
                        )

                        AnalyticsStatItem(
                            title = "Critical",
                            value = data.criticalThreats.toString(),
                            valueColor = Color(0xFFFF1744)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(26.dp))

                Surface(
                    shape = RoundedCornerShape(18.dp),
                    color = Color(0xFF111827)
                ) {

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(
                                horizontal = 18.dp,
                                vertical = 14.dp
                            ),
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = Color(0xFF00E5FF)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Column {

                            Text(
                                text = "Weekly Threat Activity",
                                color = Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = "+${data.weeklyThreatIncrease}% increase detected this week",
                                color = Color.LightGray,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ThreatProtectionMeter(

    protectionScore: Int,
    progress: Float
) {

    Box(
        modifier = Modifier.size(150.dp),
        contentAlignment = Alignment.Center
    ) {

        Canvas(
            modifier = Modifier.fillMaxSize()
        ) {

            val strokeWidth = 16.dp.toPx()

            drawArc(
                color = Color(0xFF2A3550),
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                style = Stroke(
                    width = strokeWidth,
                    cap = StrokeCap.Round
                ),
                size = Size(size.width, size.height)
            )

            drawArc(
                brush = Brush.sweepGradient(
                    colors = listOf(
                        Color(0xFF00E5FF),
                        Color(0xFF00E676)
                    )
                ),
                startAngle = 135f,
                sweepAngle = 270f * progress,
                useCenter = false,
                style = Stroke(
                    width = strokeWidth,
                    cap = StrokeCap.Round
                ),
                size = Size(size.width, size.height)
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = "$protectionScore%",
                color = Color.White,
                fontSize = 28.sp,
                fontWeight = FontWeight.ExtraBold
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Protection",
                color = Color.Gray,
                fontSize = 13.sp
            )
        }
    }
}

@Composable
fun AnalyticsStatItem(

    title: String,
    value: String,
    valueColor: Color
) {

    Column {

        Text(
            text = title,
            color = Color.Gray,
            fontSize = 12.sp
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = value,
            color = valueColor,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun ThreatAnalyticsPreviewData(): ThreatAnalyticsData {

    return ThreatAnalyticsData(
        totalThreats = 142,
        blockedThreats = 136,
        criticalThreats = 8,
        protectionScore = 96,
        weeklyThreatIncrease = 14
    )
}
