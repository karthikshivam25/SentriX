package com.sentrix.ui.privacy

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryAlert
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PlayCircleFilled
import androidx.compose.material.icons.filled.Security
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

data class BackgroundActivityModel(
    val appName: String,
    val activityType: String,
    val runningDuration: String,
    val batteryUsage: String,
    val memoryConsumption: String,
    val backgroundStatus: String,
    val riskLevel: String,
    val warningMessage: String
)

@Composable
fun BackgroundActivityCard(
    activity: BackgroundActivityModel,
    modifier: Modifier = Modifier
) {

    val riskColor = when (activity.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        else -> Color(0xFF00E676)
    }

    val statusColor =
        if (activity.backgroundStatus == "Running")
            Color(0xFF00E676)
        else
            Color(0xFFFF5252)

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
                            imageVector = Icons.Default.PlayCircleFilled,
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
                            text = activity.appName,
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = activity.activityType,
                            color = Color(0xFF90A4AE),
                            fontSize = 13.sp
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(50),
                        color = statusColor.copy(alpha = 0.15f)
                    ) {

                        Text(
                            text = activity.backgroundStatus,
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

                BackgroundActivityInfoRow(
                    label = "Running Duration",
                    value = activity.runningDuration,
                    valueColor = Color.White
                )

                BackgroundActivityInfoRow(
                    label = "Battery Usage",
                    value = activity.batteryUsage,
                    valueColor = Color.White
                )

                BackgroundActivityInfoRow(
                    label = "Memory Usage",
                    value = activity.memoryConsumption,
                    valueColor = Color.White
                )

                BackgroundActivityInfoRow(
                    label = "Risk Level",
                    value = activity.riskLevel,
                    valueColor = riskColor
                )

                Spacer(modifier = Modifier.height(22.dp))

                // Resource Usage Panel
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
                                text = "Background Resource Analysis",
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

                            ResourceItem(
                                icon = Icons.Default.BatteryAlert,
                                value = activity.batteryUsage,
                                label = "Battery"
                            )

                            ResourceItem(
                                icon = Icons.Default.Memory,
                                value = activity.memoryConsumption,
                                label = "Memory"
                            )

                            ResourceItem(
                                icon = Icons.Default.LocationOn,
                                value = activity.runningDuration,
                                label = "Runtime"
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                // Warning Section
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
                            text = activity.warningMessage,
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

                        Text(text = "Inspect")
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
                            imageVector = Icons.Default.Block,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Stop App")
                    }
                }
            }
        }
    }
}

@Composable
private fun BackgroundActivityInfoRow(
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
private fun ResourceItem(
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

BackgroundActivityCard(
    activity = BackgroundActivityModel(
        appName = "Maps Tracker",
        activityType = "Background Location Tracking",
        runningDuration = "2h 14m",
        batteryUsage = "18%",
        memoryConsumption = "326 MB",
        backgroundStatus = "Running",
        riskLevel = "High",
        warningMessage =
        "This application has been continuously active in the " +
        "background and accessing sensitive resources. SentriX " +
        "recommends reviewing its permission behavior."
    )
)

*/
