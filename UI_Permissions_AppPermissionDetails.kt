package com.sentrix.ui.permissions

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class AppPermissionDetailsModel(
    val appName: String,
    val packageName: String,
    val permissionName: String,
    val permissionStatus: Boolean,
    val riskLevel: String,
    val lastAccessed: String,
    val totalAccessCount: Int,
    val description: String,
    val icon: ImageVector = Icons.Default.Security
)

@Composable
fun AppPermissionDetailsCard(
    details: AppPermissionDetailsModel,
    modifier: Modifier = Modifier
) {

    val statusColor =
        if (details.permissionStatus)
            Color(0xFF00E676)
        else
            Color(0xFFFF5252)

    val riskColor = when (details.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFEA00)
        else -> Color(0xFF00E676)
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111827)
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 8.dp
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
                        .background(Color(0xFF1E293B)),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = details.icon,
                        contentDescription = null,
                        tint = Color.Cyan,
                        modifier = Modifier.size(30.dp)
                    )
                }

                Spacer(modifier = Modifier.width(16.dp))

                Column(
                    modifier = Modifier.weight(1f)
                ) {

                    Text(
                        text = details.appName,
                        color = Color.White,
                        fontSize = 19.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = details.packageName,
                        color = Color(0xFF90A4AE),
                        fontSize = 12.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            PermissionInfoRow(
                label = "Permission",
                value = details.permissionName,
                valueColor = Color.White
            )

            PermissionInfoRow(
                label = "Status",
                value = if (details.permissionStatus) {
                    "Granted"
                } else {
                    "Denied"
                },
                valueColor = statusColor
            )

            PermissionInfoRow(
                label = "Risk Level",
                value = details.riskLevel,
                valueColor = riskColor
            )

            PermissionInfoRow(
                label = "Last Accessed",
                value = details.lastAccessed,
                valueColor = Color(0xFFCFD8DC)
            )

            PermissionInfoRow(
                label = "Access Count",
                value = "${details.totalAccessCount} times",
                valueColor = Color(0xFFCFD8DC)
            )

            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = "Security Analysis",
                color = Color.White,
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = details.description,
                color = Color(0xFFB0BEC5),
                fontSize = 13.sp,
                lineHeight = 20.sp
            )

            Spacer(modifier = Modifier.height(24.dp))

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
                        imageVector = Icons.Default.Visibility,
                        contentDescription = null
                    )

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(text = "Monitor")
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

                    Text(text = "Revoke")
                }
            }
        }
    }
}

@Composable
private fun PermissionInfoRow(
    label: String,
    value: String,
    valueColor: Color
) {

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
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
