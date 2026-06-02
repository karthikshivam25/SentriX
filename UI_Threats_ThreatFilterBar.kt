package com.sentrix.ui.threats

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.LinkOff
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class URLThreatData(
    val url: String,
    val threatType: String,
    val riskLevel: URLThreatRiskLevel,
    val detectedTime: String,
    val blocked: Boolean
)

enum class URLThreatRiskLevel {
    SAFE,
    SUSPICIOUS,
    DANGEROUS,
    CRITICAL
}

@Composable
fun URLThreatCard(

    data: URLThreatData,
    modifier: Modifier = Modifier,
    onInspectClick: () -> Unit = {}
) {

    val riskColor = when (data.riskLevel) {
        URLThreatRiskLevel.SAFE -> Color(0xFF00E676)
        URLThreatRiskLevel.SUSPICIOUS -> Color(0xFFFFC400)
        URLThreatRiskLevel.DANGEROUS -> Color(0xFFFF9100)
        URLThreatRiskLevel.CRITICAL -> Color(0xFFFF1744)
    }

    val infiniteTransition = rememberInfiniteTransition(label = "url_warning_pulse")

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1000,
                easing = EaseInOut
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(26.dp),
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
                            Color(0xFF1A2136),
                            Color(0xFF101827)
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
                            .size(54.dp)
                            .clip(CircleShape)
                            .background(
                                riskColor.copy(alpha = 0.15f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.LinkOff,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(28.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = "Malicious URL Detected",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp
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
                                text = data.riskLevel.name,
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

                URLThreatInfoRow(
                    icon = Icons.Default.Language,
                    label = "URL",
                    value = data.url
                )

                Spacer(modifier = Modifier.height(18.dp))

                URLThreatInfoRow(
                    icon = Icons.Default.Security,
                    label = "Threat Type",
                    value = data.threatType
                )

                Spacer(modifier = Modifier.height(24.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Column {

                        Text(
                            text = "Detected",
                            color = Color.Gray,
                            fontSize = 12.sp
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = data.detectedTime,
                            color = Color.White,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    URLThreatStatusBadge(
                        blocked = data.blocked
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                Button(
                    onClick = onInspectClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp),
                    shape = RoundedCornerShape(18.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = riskColor,
                        contentColor = Color.Black
                    )
                ) {

                    Text(
                        text = "Inspect Threat",
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun URLThreatInfoRow(

    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    value: String
) {

    Row(
        verticalAlignment = Alignment.Top
    ) {

        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = Color(0xFF00E5FF),
            modifier = Modifier.size(20.dp)
        )

        Spacer(modifier = Modifier.width(12.dp))

        Column {

            Text(
                text = label,
                color = Color.Gray,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = value,
                color = Color.White,
                fontSize = 14.sp,
                lineHeight = 22.sp,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun URLThreatStatusBadge(

    blocked: Boolean
) {

    val badgeColor = if (blocked) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFF5252)
    }

    val badgeText = if (blocked) {
        "BLOCKED"
    } else {
        "ACTIVE"
    }

    Surface(
        shape = RoundedCornerShape(50),
        color = badgeColor.copy(alpha = 0.15f)
    ) {

        Text(
            text = badgeText,
            modifier = Modifier.padding(
                horizontal = 14.dp,
                vertical = 8.dp
            ),
            color = badgeColor,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun URLThreatPreviewData(): URLThreatData {

    return URLThreatData(
        url = "http://secure-banking-verification-login.xyz",
        threatType = "Phishing / Credential Theft",
        riskLevel = URLThreatRiskLevel.CRITICAL,
        detectedTime = "Just now",
        blocked = true
    )
}
