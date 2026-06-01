package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class ThreatFeedItem(
    val id: Int,
    val title: String,
    val description: String,
    val severity: ThreatSeverity,
    val timestamp: String
)

enum class ThreatSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

@Composable
fun LiveThreatFeed(
    modifier: Modifier = Modifier,
    threatItems: List<ThreatFeedItem> = sampleThreatFeed()
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "live_feed_animation"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.18f,
        targetValue = 0.45f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2200,
                easing = LinearEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    Box(
        modifier = modifier
    ) {

        // BACKGROUND GLOW
        Box(
            modifier = Modifier
                .matchParentSize()
                .blur(35.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF00D9FF).copy(alpha = glowAlpha),
                            Color(0xFF0066FF).copy(alpha = glowAlpha * 0.4f)
                        )
                    )
                )
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(30.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF111827)
            )
        ) {

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(22.dp)
            ) {

                // ----------------------------------------
                // HEADER
                // ----------------------------------------

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = Icons.Default.WarningAmber,
                            contentDescription = "Threat Feed",
                            tint = Color(0xFFFF5252),
                            modifier = Modifier.size(28.dp)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Column {

                            Text(
                                text = "Live Threat Feed",
                                color = Color.White,
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = "Real-time security monitoring",
                                color = Color(0xFF9CA3AF),
                                fontSize = 13.sp
                            )
                        }
                    }

                    LiveIndicator()
                }

                Spacer(modifier = Modifier.height(22.dp))

                // ----------------------------------------
                // THREAT LIST
                // ----------------------------------------

                LazyColumn(
                    modifier = Modifier.heightIn(max = 400.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {

                    items(threatItems) { threat ->

                        ThreatFeedCard(
                            threat = threat
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun LiveIndicator() {

    val infiniteTransition = rememberInfiniteTransition(
        label = "live_indicator"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(900),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(
            modifier = Modifier
                .size(10.dp)
                .clip(CircleShape)
                .background(
                    Color(0xFFFF1744).copy(alpha = pulseAlpha)
                )
        )

        Spacer(modifier = Modifier.width(8.dp))

        Text(
            text = "LIVE",
            color = Color(0xFFFF5252),
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp
        )
    }
}

@Composable
private fun ThreatFeedCard(
    threat: ThreatFeedItem
) {

    val severityColor = when (threat.severity) {

        ThreatSeverity.LOW -> Color(0xFF00E676)

        ThreatSeverity.MEDIUM -> Color(0xFFFFC107)

        ThreatSeverity.HIGH -> Color(0xFFFF9100)

        ThreatSeverity.CRITICAL -> Color(0xFFFF1744)
    }

    val severityIcon = when (threat.severity) {

        ThreatSeverity.LOW -> Icons.Default.Verified

        ThreatSeverity.MEDIUM -> Icons.Default.Report

        ThreatSeverity.HIGH -> Icons.Default.Warning

        ThreatSeverity.CRITICAL -> Icons.Default.GppBad
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(22.dp))
            .background(
                Color.White.copy(alpha = 0.04f)
            )
            .padding(18.dp),
        verticalAlignment = Alignment.Top
    ) {

        Box(
            modifier = Modifier
                .size(46.dp)
                .clip(CircleShape)
                .background(
                    severityColor.copy(alpha = 0.15f)
                ),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = severityIcon,
                contentDescription = "Threat Level",
                tint = severityColor,
                modifier = Modifier.size(24.dp)
            )
        }

        Spacer(modifier = Modifier.width(16.dp))

        Column(
            modifier = Modifier.weight(1f)
        ) {

            Text(
                text = threat.title,
                color = Color.White,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = threat.description,
                color = Color(0xFF9CA3AF),
                fontSize = 13.sp,
                lineHeight = 20.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(14.dp))
                        .background(
                            severityColor.copy(alpha = 0.14f)
                        )
                        .padding(
                            horizontal = 12.dp,
                            vertical = 6.dp
                        )
                ) {

                    Text(
                        text = threat.severity.name,
                        color = severityColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp
                    )
                }

                Text(
                    text = threat.timestamp,
                    color = Color(0xFF6B7280),
                    fontSize = 11.sp
                )
            }
        }
    }
}

private fun sampleThreatFeed(): List<ThreatFeedItem> {

    return listOf(

        ThreatFeedItem(
            id = 1,
            title = "Suspicious Login Attempt",
            description = "Blocked unauthorized login attempt from unknown IP address.",
            severity = ThreatSeverity.CRITICAL,
            timestamp = "2 min ago"
        ),

        ThreatFeedItem(
            id = 2,
            title = "VPN Encryption Active",
            description = "Secure encrypted tunnel established successfully.",
            severity = ThreatSeverity.LOW,
            timestamp = "5 min ago"
        ),

        ThreatFeedItem(
            id = 3,
            title = "Potential Malware Detected",
            description = "Real-time scanner identified risky application behavior.",
            severity = ThreatSeverity.HIGH,
            timestamp = "12 min ago"
        ),

        ThreatFeedItem(
            id = 4,
            title = "Firewall Rule Updated",
            description = "Advanced network filtering rules synchronized.",
            severity = ThreatSeverity.MEDIUM,
            timestamp = "18 min ago"
        )
    )
}
