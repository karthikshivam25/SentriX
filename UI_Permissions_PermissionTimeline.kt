package com.sentrix.ui.permissions

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class PermissionTimelineItem(
    val title: String,
    val description: String,
    val timestamp: String,
    val status: PermissionTimelineStatus
)

enum class PermissionTimelineStatus {
    GRANTED,
    DENIED,
    WARNING
}

@Composable
fun PermissionTimeline(
    timelineItems: List<PermissionTimelineItem>,
    modifier: Modifier = Modifier
) {

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111827)
        )
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {

            Text(
                text = "Permission Activity Timeline",
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(18.dp))

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(18.dp)
            ) {

                items(timelineItems) { item ->
                    TimelineRow(item)
                }
            }
        }
    }
}

@Composable
private fun TimelineRow(
    item: PermissionTimelineItem
) {

    val statusColor = when (item.status) {
        PermissionTimelineStatus.GRANTED -> Color(0xFF00E676)
        PermissionTimelineStatus.DENIED -> Color(0xFFFF5252)
        PermissionTimelineStatus.WARNING -> Color(0xFFFFC107)
    }

    val statusIcon: ImageVector = when (item.status) {
        PermissionTimelineStatus.GRANTED -> Icons.Default.CheckCircle
        PermissionTimelineStatus.DENIED -> Icons.Default.Lock
        PermissionTimelineStatus.WARNING -> Icons.Default.Warning
    }

    Row(
        modifier = Modifier.fillMaxWidth()
    ) {

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Box(
                modifier = Modifier
                    .size(42.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = statusIcon,
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(22.dp)
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            HorizontalDivider(
                modifier = Modifier
                    .width(2.dp)
                    .height(60.dp),
                color = Color(0xFF263238)
            )
        }

        Spacer(modifier = Modifier.width(14.dp))

        Column(
            modifier = Modifier.weight(1f)
        ) {

            Text(
                text = item.title,
                color = Color.White,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = item.description,
                color = Color(0xFFB0BEC5),
                fontSize = 13.sp,
                lineHeight = 19.sp
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = item.timestamp,
                color = statusColor,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium
            )
        }
    }
}
