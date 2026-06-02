package com.sentrix.ui.privacy

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GpsFixed
import androidx.compose.material.icons.filled.LocationSearching
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class TrackingDetectionModel(
    val appName: String,
    val trackerType: String,
    val trackerCount: Int,
    val lastDetection: String,
    val trackingStatus: String,
    val riskLevel: String,
    val detectionMessage: String
)

@Composable
fun TrackingDetectionCard(
    tracking: TrackingDetectionModel,
    modifier: Modifier = Modifier
) {

    val riskColor = when (tracking.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        else -> Color(0xFF00E676)
    }

    val statusColor =
        if (tracking.trackingStatus == "Tracking Active")
            Color(0xFFFF5252)
        else
            Color(0xFF00E676)

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 10.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF111827),
                            Color(0xFF0F172A)
                        )
                    )
                )
                .padding(22.dp)
        ) {

            Column(
                modifier = Modifier.fillMaxWidth()
            ) {

                // Header
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(60.dp)
                            .clip(CircleShape)
                            .background(riskColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.LocationSearching,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(32.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = tracking.appName,
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = tracking.trackerType,
                            color = Color(0xFF90A4AE),
                            fontSize = 13.sp
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(50),
                        color = statusColor.copy(alpha = 0.15f)
                    ) {

                        Text(
                            text = tracking.trackingStatus,
                            color = statusColor,
                            modifier = Modifier.padding(
                                horizontal = 12.dp,
                                vertical = 6.dp
                            ),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                TrackingInfoRow(
                    label = "Tracker Count",
                    value = "${tracking.trackerCount}",
                    valueColor = Color.White
                )

                TrackingInfoRow(
                    label = "Last Detection",
                    value = tracking.lastDetection,
                    valueColor = Color.White
                )

                TrackingInfoRow(
                    label = "Risk Level",
                    value = tracking.riskLevel,
                    valueColor = riskColor
                )

                Spacer(modifier = Modifier.height(22.dp))

                // Tracker Analysis Panel
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color(0xFF1E293B))
                        .padding(16.dp)
                ) {

                    Column {

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = null,
                                tint = Color.Cyan,
                                modifier = Modifier.size(20.dp)
                            )

                            Spacer(modifier = Modifier.width(8.dp))

                            Text(
                                text = "Tracker Analysis",
                                color = Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp
                            )
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {

                            TrackerMetricItem(
                                icon = Icons.Default.GpsFixed,
                                value = "${tracking.trackerCount}",
                                label = "Trackers"
                            )

                            TrackerMetricItem(
                                icon = Icons.Default.LocationSearching,
                                value = tracking.trackingStatus,
                                label = "Status"
                            )

                            TrackerMetricItem(
                                icon = Icons.Default.Shield,
                                value = tracking.riskLevel,
                                label = "Security"
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                // Detection Warning
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(riskColor.copy(alpha = 0.12f))
                        .padding(16.dp)
                ) {

                    Row(
                        verticalAlignment = Alignment.Top
                    ) {

                        Icon(
                            imageVector = Icons.Default.WarningAmber,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(22.dp)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Text(
                            text = tracking.detectionMessage,
                            color = Color(0xFFECEFF1),
                            fontSize = 13.sp,
                            lineHeight = 20.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Actions
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {

                    Button(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF00BCD4)
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Analyze")
                    }

                    OutlinedButton(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.Red
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Block")
                    }
                }
            }
        }
    }
}

@Composable
private fun TrackingInfoRow(
    label: String,
    value: String,
    valueColor: Color
) {

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 7.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 13.sp
        )

        Text(
            text = value,
            color = valueColor,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
private fun TrackerMetricItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    value: String,
    label: String
) {

    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = Color.Cyan,
            modifier = Modifier.size(22.dp)
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = value,
            color = Color.White,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 11.sp
        )
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

TrackingDetectionCard(
    tracking = TrackingDetectionModel(
        appName = "Social Media App",
        trackerType = "Location & Ad Tracking",
        trackerCount = 12,
        lastDetection = "3 mins ago",
        trackingStatus = "Tracking Active",
        riskLevel = "High",
        detectionMessage =
        "Multiple tracking modules detected running in the " +
        "background. This application may be collecting user " +
        "behavior, location, and advertising analytics data."
    )
)

*/
