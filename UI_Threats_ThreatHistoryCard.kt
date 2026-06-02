package com.sentrix.ui.threats

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class ThreatHistoryItem(
    val id: Int,
    val title: String,
    val description: String,
    val detectedTime: String,
    val severity: ThreatSeverityLevel,
    val isResolved: Boolean
)

enum class ThreatSeverityLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

@Composable
fun ThreatHistoryCard(

    threat: ThreatHistoryItem,
    modifier: Modifier = Modifier,
    onClick: (ThreatHistoryItem) -> Unit = {}
) {

    val severityColor by animateColorAsState(
        targetValue = when (threat.severity) {
            ThreatSeverityLevel.LOW -> Color(0xFF00E676)
            ThreatSeverityLevel.MEDIUM -> Color(0xFFFFC400)
            ThreatSeverityLevel.HIGH -> Color(0xFFFF9100)
            ThreatSeverityLevel.CRITICAL -> Color(0xFFFF1744)
        },
        label = "severity_color"
    )

    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable {
                onClick(threat)
            },
        shape = RoundedCornerShape(24.dp),
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
                            Color(0xFF182235),
                            Color(0xFF111827)
                        )
                    )
                )
                .padding(18.dp)
        ) {

            Column {

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(14.dp)
                            .clip(CircleShape)
                            .background(severityColor)
                    )

                    Spacer(modifier = Modifier.width(10.dp))

                    Text(
                        text = threat.severity.name,
                        color = severityColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp
                    )

                    Spacer(modifier = Modifier.weight(1f))

                    Text(
                        text = threat.detectedTime,
                        color = Color.Gray,
                        fontSize = 12.sp
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                Text(
                    text = threat.title,
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = threat.description,
                    color = Color.LightGray,
                    fontSize = 14.sp,
                    lineHeight = 22.sp,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )

                Spacer(modifier = Modifier.height(18.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    ThreatStatusBadge(
                        isResolved = threat.isResolved
                    )

                    Spacer(modifier = Modifier.weight(1f))

                    Icon(
                        imageVector = Icons.Default.ArrowForward,
                        contentDescription = null,
                        tint = Color(0xFF00E5FF)
                    )
                }
            }
        }
    }
}

@Composable
fun ThreatStatusBadge(

    isResolved: Boolean
) {

    val badgeColor = if (isResolved) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFF5252)
    }

    val badgeText = if (isResolved) {
        "RESOLVED"
    } else {
        "ACTIVE"
    }

    val badgeIcon = if (isResolved) {
        Icons.Default.CheckCircle
    } else {
        Icons.Default.Error
    }

    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(
                badgeColor.copy(alpha = 0.15f)
            )
            .padding(
                horizontal = 14.dp,
                vertical = 8.dp
            ),
        verticalAlignment = Alignment.CenterVertically
    ) {

        Icon(
            imageVector = badgeIcon,
            contentDescription = null,
            tint = badgeColor,
            modifier = Modifier.size(14.dp)
        )

        Spacer(modifier = Modifier.width(6.dp))

        Text(
            text = badgeText,
            color = badgeColor,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun ThreatHistoryPreviewData(): List<ThreatHistoryItem> {

    return listOf(

        ThreatHistoryItem(
            id = 1,
            title = "Ransomware Execution Attempt",
            description = "A malicious executable attempted unauthorized encryption activity. SentriX blocked the execution before any system compromise occurred.",
            detectedTime = "2 mins ago",
            severity = ThreatSeverityLevel.CRITICAL,
            isResolved = false
        ),

        ThreatHistoryItem(
            id = 2,
            title = "Suspicious Network Connection",
            description = "Outbound communication was detected to a blacklisted IP address associated with malware activity.",
            detectedTime = "18 mins ago",
            severity = ThreatSeverityLevel.HIGH,
            isResolved = true
        ),

        ThreatHistoryItem(
            id = 3,
            title = "Unsafe APK Installation",
            description = "An application package with hidden malicious payloads was blocked during installation verification.",
            detectedTime = "1 hour ago",
            severity = ThreatSeverityLevel.MEDIUM,
            isResolved = true
        )
    )
}
