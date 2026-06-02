package com.sentrix.ui.ai

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.CheckCircle
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class AIInsightSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

data class AIInsightData(
    val id: Int,
    val title: String,
    val description: String,
    val severity: AIInsightSeverity,
    val timestamp: String,
    val resolved: Boolean
)

@Composable
fun AIInsightsCard(

    data: AIInsightData,
    modifier: Modifier = Modifier
) {

    val severityColor = when (data.severity) {
        AIInsightSeverity.LOW -> Color(0xFF00E676)
        AIInsightSeverity.MEDIUM -> Color(0xFFFFC400)
        AIInsightSeverity.HIGH -> Color(0xFFFF9100)
        AIInsightSeverity.CRITICAL -> Color(0xFFFF1744)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "ai_insight_animation"
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
            defaultElevation = 5.dp
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
                .padding(20.dp)
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
                                severityColor.copy(alpha = 0.15f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = if (data.resolved) {
                                Icons.Default.CheckCircle
                            } else {
                                Icons.Default.Analytics
                            },
                            contentDescription = null,
                            tint = severityColor,
                            modifier = Modifier.size(28.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = data.title,
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Box(
                                modifier = Modifier
                                    .size(10.dp)
                                    .clip(CircleShape)
                                    .background(severityColor)
                                    .alpha(pulseAlpha)
                            )

                            Spacer(modifier = Modifier.width(8.dp))

                            Text(
                                text = data.severity.name,
                                color = severityColor,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    Column(
                        horizontalAlignment = Alignment.End
                    ) {

                        Icon(
                            imageVector = Icons.Default.AutoAwesome,
                            contentDescription = null,
                            tint = Color(0xFF00E5FF)
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = data.timestamp,
                            color = Color.Gray,
                            fontSize = 11.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(22.dp))

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
                                imageVector = Icons.Default.WarningAmber,
                                contentDescription = null,
                                tint = severityColor,
                                modifier = Modifier.size(20.dp)
                            )

                            Spacer(modifier = Modifier.width(10.dp))

                            Text(
                                text = "AI Threat Insight",
                                color = Color.White,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold
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

                Spacer(modifier = Modifier.height(20.dp))

                Surface(
                    shape = RoundedCornerShape(18.dp),
                    color = if (data.resolved) {
                        Color(0x2200E676)
                    } else {
                        severityColor.copy(alpha = 0.12f)
                    }
                ) {

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(
                                horizontal = 16.dp,
                                vertical = 14.dp
                            ),
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = if (data.resolved) {
                                Icons.Default.CheckCircle
                            } else {
                                Icons.Default.WarningAmber
                            },
                            contentDescription = null,
                            tint = if (data.resolved) {
                                Color(0xFF00E676)
                            } else {
                                severityColor
                            },
                            modifier = Modifier.size(18.dp)
                        )

                        Spacer(modifier = Modifier.width(10.dp))

                        Text(
                            text = if (data.resolved) {
                                "AI mitigation completed successfully."
                            } else {
                                "Immediate review recommended by AI Shield."
                            },
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
fun AIInsightsPreviewData(): List<AIInsightData> {

    return listOf(

        AIInsightData(
            id = 1,
            title = "Credential Harvesting Attempt",
            description = "AI detected phishing behavior targeting browser-stored credentials through a fake authentication page.",
            severity = AIInsightSeverity.CRITICAL,
            timestamp = "2 mins ago",
            resolved = false
        ),

        AIInsightData(
            id = 2,
            title = "Suspicious Runtime Injection",
            description = "Behavioral analysis identified unauthorized memory injection attempts from a background application.",
            severity = AIInsightSeverity.HIGH,
            timestamp = "18 mins ago",
            resolved = false
        ),

        AIInsightData(
            id = 3,
            title = "Unsafe Network Access",
            description = "AI Shield automatically enabled VPN protection after detecting an unsecured public Wi-Fi connection.",
            severity = AIInsightSeverity.MEDIUM,
            timestamp = "1 hour ago",
            resolved = true
        )
    )
}
