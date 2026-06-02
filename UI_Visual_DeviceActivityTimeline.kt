package com.sentrix.ui.visual

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccessTime
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun DeviceActivityTimelineCard() {

    val timelineEvents = listOf(
        DeviceActivityEvent(
            title = "Threat Blocked",
            description = "Suspicious application access denied",
            time = "2 min ago",
            iconColor = Color(0xFFEF4444),
            icon = Icons.Default.Warning
        ),
        DeviceActivityEvent(
            title = "Security Scan Completed",
            description = "No threats detected in recent scan",
            time = "18 min ago",
            iconColor = Color(0xFF22C55E),
            icon = Icons.Default.Security
        ),
        DeviceActivityEvent(
            title = "Cloud Sync Updated",
            description = "Protection data synchronized securely",
            time = "1 hour ago",
            iconColor = Color(0xFF38BDF8),
            icon = Icons.Default.Sync
        ),
        DeviceActivityEvent(
            title = "Background Monitoring",
            description = "Live device protection is active",
            time = "3 hours ago",
            iconColor = Color(0xFFFACC15),
            icon = Icons.Default.AccessTime
        )
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(24.dp)
            )
            .padding(20.dp)
    ) {

        Column {

            Text(
                text = "Device Activity Timeline",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Recent security and system activities",
                color = Color(0xFF94A3B8),
                fontSize = 13.sp
            )

            Spacer(modifier = Modifier.height(28.dp))

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(18.dp)
            ) {

                items(timelineEvents.size) { index ->

                    DeviceActivityTimelineItem(
                        event = timelineEvents[index],
                        isLast = index == timelineEvents.lastIndex
                    )
                }
            }
        }
    }
}

data class DeviceActivityEvent(
    val title: String,
    val description: String,
    val time: String,
    val iconColor: Color,
    val icon: androidx.compose.ui.graphics.vector.ImageVector
)

@Composable
fun DeviceActivityTimelineItem(
    event: DeviceActivityEvent,
    isLast: Boolean
) {

    Row(
        modifier = Modifier.fillMaxWidth()
    ) {

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Box(
                modifier = Modifier
                    .size(46.dp)
                    .background(
                        color = event.iconColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(14.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = event.icon,
                    contentDescription = null,
                    tint = event.iconColor,
                    modifier = Modifier.size(24.dp)
                )
            }

            if (!isLast) {

                Spacer(modifier = Modifier.height(6.dp))

                Box(
                    modifier = Modifier
                        .size(
                            width = 2.dp,
                            height = 58.dp
                        )
                        .background(
                            color = Color(0xFF1E293B)
                        )
                )
            }
        }

        Column(
            modifier = Modifier
                .padding(start = 16.dp)
                .weight(1f)
        ) {

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                Text(
                    text = event.title,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp
                )

                Text(
                    text = event.time,
                    color = Color(0xFF64748B),
                    fontSize = 12.sp
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = event.description,
                color = Color(0xFF94A3B8),
                fontSize = 13.sp,
                lineHeight = 20.sp
            )
        }
    }
}
