package com.sentrix.ui.analytics

import androidx.compose.animation.core.animateFloatAsState
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
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun RiskAnalyticsCard(
    modifier: Modifier = Modifier,
    overallRiskScore: Float = 0.32f,
    malwareRisk: Float = 0.68f,
    networkRisk: Float = 0.41f,
    privacyRisk: Float = 0.24f
) {

    val animatedOverallRisk by animateFloatAsState(
        targetValue = overallRiskScore,
        label = "OverallRiskAnimation"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF141B25)
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
                                    Color(0xFFFF9800),
                                    Color(0xFFFF5722)
                                )
                            ),
                            shape = RoundedCornerShape(18.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Rounded.WarningAmber,
                        contentDescription = "Risk Analytics",
                        tint = Color.White,
                        modifier = Modifier.size(30.dp)
                    )
                }

                Spacer(modifier = Modifier.size(14.dp))

                Column {

                    Text(
                        text = "Risk Analytics",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Advanced system vulnerability insights",
                        color = Color(0xFF9AA4B2),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            // Overall Risk Section
            Text(
                text = "Overall System Risk",
                color = Color.White,
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(10.dp))

            LinearProgressIndicator(
                progress = { animatedOverallRisk },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(10.dp),
                color = getRiskColor(animatedOverallRisk),
                trackColor = Color(0xFF2B3445)
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "${(animatedOverallRisk * 100).toInt()}% Risk Level",
                color = getRiskColor(animatedOverallRisk),
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(28.dp))

            // Detailed Risk Metrics
            RiskMetricRow(
                title = "Malware Exposure",
                progress = malwareRisk,
                color = Color(0xFFFF5252)
            )

            Spacer(modifier = Modifier.height(18.dp))

            RiskMetricRow(
                title = "Network Vulnerability",
                progress = networkRisk,
                color = Color(0xFF00C6FF)
            )

            Spacer(modifier = Modifier.height(18.dp))

            RiskMetricRow(
                title = "Privacy Threats",
                progress = privacyRisk,
                color = Color(0xFF00E676)
            )
        }
    }
}

@Composable
fun RiskMetricRow(
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

            Text(
                text = title,
                color = Color(0xFFE5E7EB),
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium
            )

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

fun getRiskColor(risk: Float): Color {

    return when {
        risk < 0.30f -> Color(0xFF00E676)
        risk < 0.60f -> Color(0xFFFFC107)
        else -> Color(0xFFFF5252)
    }
}
