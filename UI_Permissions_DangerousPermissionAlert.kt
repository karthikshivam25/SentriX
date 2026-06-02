package com.sentrix.ui.permissions

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class DangerousPermissionAlertModel(
    val permissionName: String,
    val appName: String,
    val riskLevel: String,
    val warningMessage: String,
    val detectedTime: String,
    val affectedData: String,
    val icon: ImageVector = Icons.Default.GppBad
)

@Composable
fun DangerousPermissionAlertCard(
    alert: DangerousPermissionAlertModel,
    modifier: Modifier = Modifier
) {

    val riskColor = when (alert.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF6D00)
        "Medium" -> Color(0xFFFFC400)
        else -> Color(0xFF00E676)
    }

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
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF1B1F2A),
                            Color(0xFF111827)
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
                            .size(58.dp)
                            .clip(CircleShape)
                            .background(riskColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = alert.icon,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(30.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = "Dangerous Permission Detected",
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = alert.detectedTime,
                            color = Color(0xFF90A4AE),
                            fontSize = 12.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(22.dp))

                AlertInfoRow(
                    label = "Application",
                    value = alert.appName,
                    valueColor = Color.White
                )

                AlertInfoRow(
                    label = "Permission",
                    value = alert.permissionName,
                    valueColor = riskColor
                )

                AlertInfoRow(
                    label = "Risk Level",
                    value = alert.riskLevel,
                    valueColor = riskColor
                )

                AlertInfoRow(
                    label = "Affected Data",
                    value = alert.affectedData,
                    valueColor = Color(0xFFCFD8DC)
                )

                Spacer(modifier = Modifier.height(18.dp))

                // Warning Box
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
                            text = alert.warningMessage,
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
                            containerColor = riskColor
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.Error,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Block")
                    }

                    OutlinedButton(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.White
                        )
                    ) {

                        Text(text = "Investigate")
                    }
                }
            }
        }
    }
}

@Composable
private fun AlertInfoRow(
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
