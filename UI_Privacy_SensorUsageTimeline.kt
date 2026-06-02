package com.sentrix.ui.privacy

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
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

data class SensorUsageTimelineModel(
    val appName: String,
    val sensorType: String,
    val accessTime: String,
    val usageDuration: String,
    val riskLevel: String,
    val icon: ImageVector
)

@Composable
fun SensorUsageTimeline(
    timeline: List<SensorUsageTimelineModel>,
    modifier: Modifier = Modifier
) {

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(26.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111827)
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 10.dp
        )
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(22.dp)
        ) {

            // Header
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(58.dp)
                        .clip(CircleShape)
                        .background(Color.Cyan.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Sensors,
                        contentDescription = null,
                        tint = Color.Cyan,
                        modifier = Modifier.size(30.dp)
                    )
                }

                Spacer(modifier = Modifier.width(16.dp))

                Column {

                    Text(
                        text = "Sensor Usage Timeline",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Real-time privacy sensor activity",
                        color = Color(0xFF90A4AE),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(18.dp)
            ) {

                items(timeline) { item ->

                    SensorTimelineItem(
                        item = item
                    )
                }
            }
        }
    }
}

@Composable
private fun SensorTimelineItem(
    item: SensorUsageTimelineModel
) {

    val riskColor = when (item.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        else -> Color(0xFF00E676)
    }

    Row(
        modifier = Modifier.fillMaxWidth()
    ) {

        // Timeline Indicator
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(riskColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = item.icon,
                    contentDescription = null,
                    tint = riskColor,
                    modifier = Modifier.size(22.dp)
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            HorizontalDivider(
                modifier = Modifier
                    .width(2.dp)
                    .height(68.dp),
                color = Color(0xFF334155)
            )
        }

        Spacer(modifier = Modifier.width(14.dp))

        // Content
        Card(
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF1E293B)
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

                    Column {

                        Text(
                            text = item.appName,
                            color = Color.White,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = item.sensorType,
                            color = Color(0xFFB0BEC5),
                            fontSize = 13.sp
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(50),
                        color = riskColor.copy(alpha = 0.15f)
                    ) {

                        Text(
                            text = item.riskLevel,
                            color = riskColor,
                            modifier = Modifier.padding(
                                horizontal = 12.dp,
                                vertical = 6.dp
                            ),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {

                    TimelineInfoItem(
                        label = "Access Time",
                        value = item.accessTime
                    )

                    TimelineInfoItem(
                        label = "Duration",
                        value = item.usageDuration
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(riskColor.copy(alpha = 0.10f))
                        .padding(12.dp)
                ) {

                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = Icons.Default.WarningAmber,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(18.dp)
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(
                            text =
                            "SentriX detected sensor activity " +
                                    "from this application.",
                            color = Color(0xFFECEFF1),
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TimelineInfoItem(
    label: String,
    value: String
) {

    Column {

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 11.sp
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = value,
            color = Color.White,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

val sensorTimeline = listOf(

    SensorUsageTimelineModel(
        appName = "Instagram",
        sensorType = "Camera Access",
        accessTime = "10:42 AM",
        usageDuration = "12 mins",
        riskLevel = "Medium",
        icon = Icons.Default.CameraAlt
    ),

    SensorUsageTimelineModel(
        appName = "Voice Assistant",
        sensorType = "Microphone Usage",
        accessTime = "11:10 AM",
        usageDuration = "7 mins",
        riskLevel = "High",
        icon = Icons.Default.GraphicEq
    ),

    SensorUsageTimelineModel(
        appName = "Maps",
        sensorType = "Location Tracking",
        accessTime = "11:36 AM",
        usageDuration = "48 mins",
        riskLevel = "Critical",
        icon = Icons.Default.LocationOn
    )
)

SensorUsageTimeline(
    timeline = sensorTimeline
)

*/
