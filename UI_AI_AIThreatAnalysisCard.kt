package com.sentrix.ui.ai

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberInfiniteTransition
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class AIThreatAnalysisData(
    val threatName: String,
    val threatType: String,
    val aiConfidence: Int,
    val riskLevel: AIThreatRiskLevel,
    val description: String,
    val mitigationStatus: String
)

enum class AIThreatRiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

@Composable
fun AIThreatAnalysisCard(

    data: AIThreatAnalysisData,
    modifier: Modifier = Modifier
) {

    val riskColor = when (data.riskLevel) {
        AIThreatRiskLevel.LOW -> Color(0xFF00E676)
        AIThreatRiskLevel.MEDIUM -> Color(0xFFFFC400)
        AIThreatRiskLevel.HIGH -> Color(0xFFFF9100)
        AIThreatRiskLevel.CRITICAL -> Color(0xFFFF1744)
    }

    val confidenceProgress = data.aiConfidence / 100f

    val infiniteTransition = rememberInfiniteTransition(
        label = "ai_analysis_animation"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.35f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1200,
                easing = EaseInOut
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
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
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(56.dp)
                            .clip(CircleShape)
                            .background(
                                riskColor.copy(alpha = 0.15f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.AutoAwesome,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(30.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = data.threatName,
                            color = Color.White,
                            fontSize = 19.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Box(
                                modifier = Modifier
                                    .size(10.dp)
                                    .clip(CircleShape)
                                    .background(riskColor)
                                    .alpha(pulseAlpha)
                            )

                            Spacer(modifier = Modifier.width(8.dp))

                            Text(
                                text = "${data.riskLevel.name} RISK",
                                color = riskColor,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    Icon(
                        imageVector = Icons.Default.WarningAmber,
                        contentDescription = null,
                        tint = riskColor
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Column(
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {

                        AIAnalysisInfoRow(
                            title = "Threat Type",
                            value = data.threatType
                        )

                        AIAnalysisInfoRow(
                            title = "Mitigation",
                            value = data.mitigationStatus
                        )
                    }

                    AIConfidenceMeter(
                        confidence = data.aiConfidence,
                        progress = confidenceProgress,
                        color = riskColor
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Surface(
                    shape = RoundedCornerShape(20.dp),
                    color = Color(0xFF111827)
                ) {

                    Column(
                        modifier = Modifier.padding(18.dp)
                    ) {

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
                                text = "AI Threat Analysis",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            )
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        Text(
                            text = data.description,
                            color = Color.LightGray,
                            fontSize = 14.sp,
                            lineHeight = 22.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(22.dp))

                Surface(
                    shape = RoundedCornerShape(18.dp),
                    color = riskColor.copy(alpha = 0.12f)
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
                            tint = riskColor
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Text(
                            text = "AI Shield completed behavioral analysis and response mitigation successfully.",
                            color = Color.White,
                            fontSize = 13.sp,
                            lineHeight = 20.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AIConfidenceMeter(

    confidence: Int,
    progress: Float,
    color: Color
) {

    Box(
        modifier = Modifier.size(120.dp),
        contentAlignment = Alignment.Center
    ) {

        Canvas(
            modifier = Modifier.fillMaxSize()
        ) {

            drawArc(
                color = Color(0xFF2A3550),
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                style = Stroke(
                    width = 14.dp.toPx(),
                    cap = StrokeCap.Round
                )
            )

            drawArc(
                brush = Brush.sweepGradient(
                    colors = listOf(
                        color,
                        Color(0xFF00E5FF)
                    )
                ),
                startAngle = 135f,
                sweepAngle = 270f * progress,
                useCenter = false,
                style = Stroke(
                    width = 14.dp.toPx(),
                    cap = StrokeCap.Round
                )
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = "$confidence%",
                color = Color.White,
                fontSize = 22.sp,
                fontWeight = FontWeight.ExtraBold
            )

            Spacer(modifier = Modifier.height(2.dp))

            Text(
                text = "AI Confidence",
                color = Color.Gray,
                fontSize = 10.sp
            )
        }
    }
}

@Composable
fun AIAnalysisInfoRow(

    title: String,
    value: String
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
            color = Color.White,
            fontSize = 15.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun AIThreatAnalysisPreviewData(): AIThreatAnalysisData {

    return AIThreatAnalysisData(
        threatName = "Trojan.XSilent.Injector",
        threatType = "Behavioral Malware",
        aiConfidence = 97,
        riskLevel = AIThreatRiskLevel.CRITICAL,
        description = "AI models detected suspicious runtime injection behavior attempting unauthorized privilege escalation and encrypted payload execution. Threat was isolated before persistence could occur.",
        mitigationStatus = "Threat Neutralized"
    )
}
