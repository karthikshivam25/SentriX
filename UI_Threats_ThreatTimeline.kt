package com.sentrix.ui.threats

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class TimelineThreatEvent(
    val id: Int,
    val title: String,
    val description: String,
    val timestamp: String,
    val status: ThreatEventStatus
)

enum class ThreatEventStatus {
    DETECTED,
    BLOCKED,
    RESOLVED
}

@Composable
fun ThreatTimeline(

    events: List<TimelineThreatEvent>,
    modifier: Modifier = Modifier
) {

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {

        items(events) { event ->

            ThreatTimelineItem(
                event = event,
                isLastItem = event == events.last()
            )
        }
    }
}

@Composable
fun ThreatTimelineItem(

    event: TimelineThreatEvent,
    isLastItem: Boolean
) {

    val statusColor by animateColorAsState(
        targetValue = when (event.status) {
            ThreatEventStatus.DETECTED -> Color(0xFFFF9800)
            ThreatEventStatus.BLOCKED -> Color(0xFFFF5252)
            ThreatEventStatus.RESOLVED -> Color(0xFF00E676)
        },
        label = "timeline_status_color"
    )

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Box(
                modifier = Modifier
                    .size(18.dp)
                    .clip(CircleShape)
                    .background(statusColor),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = when (event.status) {
                        ThreatEventStatus.DETECTED -> Icons.Default.Error
                        ThreatEventStatus.BLOCKED -> Icons.Default.Security
                        ThreatEventStatus.RESOLVED -> Icons.Default.CheckCircle
                    },
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(10.dp)
                )
            }

            if (!isLastItem) {

                Spacer(modifier = Modifier.height(4.dp))

                Box(
                    modifier = Modifier
                        .width(2.dp)
                        .height(80.dp)
                        .background(Color(0xFF2A3550))
                )
            }
        }

        Spacer(modifier = Modifier.width(14.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF151C2E)
            ),
            elevation = CardDefaults.cardElevation(
                defaultElevation = 4.dp
            )
        ) {

            Column(
                modifier = Modifier.padding(18.dp)
            ) {

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Text(
                        text = event.title,
                        color = Color.White,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Text(
                        text = event.timestamp,
                        color = Color.Gray,
                        fontSize = 12.sp
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = event.description,
                    color = Color.LightGray,
                    fontSize = 14.sp,
                    lineHeight = 22.sp
                )

                Spacer(modifier = Modifier.height(14.dp))

                ThreatStatusChip(
                    status = event.status,
                    color = statusColor
                )
            }
        }
    }
}

@Composable
fun ThreatStatusChip(

    status: ThreatEventStatus,
    color: Color
) {

    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.15f))
            .padding(
                horizontal = 14.dp,
                vertical = 7.dp
            )
    ) {

        Text(
            text = status.name,
            color = color,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun ThreatTimelinePreviewData(): List<TimelineThreatEvent> {

    return listOf(

        TimelineThreatEvent(
            id = 1,
            title = "Threat Signature Detected",
            description = "AI engine identified ransomware-like behavior from a suspicious application process.",
            timestamp = "10:21 AM",
            status = ThreatEventStatus.DETECTED
        ),

        TimelineThreatEvent(
            id = 2,
            title = "Execution Blocked",
            description = "Threat execution was stopped before encryption activities could begin.",
            timestamp = "10:22 AM",
            status = ThreatEventStatus.BLOCKED
        ),

        TimelineThreatEvent(
            id = 3,
            title = "Threat Neutralized",
            description = "Deep system cleanup completed successfully and malicious traces were removed.",
            timestamp = "10:25 AM",
            status = ThreatEventStatus.RESOLVED
        )
    )
}
