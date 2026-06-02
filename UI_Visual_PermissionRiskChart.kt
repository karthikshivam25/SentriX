package com.sentrix.ui.visual

import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PrivacyTip
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun PermissionRiskChartCard() {

    val permissionData = listOf(
        PermissionRiskData("Camera", 78f, Color(0xFF38BDF8)),
        PermissionRiskData("Location", 62f, Color(0xFFFACC15)),
        PermissionRiskData("Microphone", 45f, Color(0xFF22C55E)),
        PermissionRiskData("Storage", 85f, Color(0xFFEF4444))
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

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(
                            color = Color(0xFF1E293B),
                            shape = RoundedCornerShape(14.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.PrivacyTip,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8)
                    )
                }

                Column(
                    modifier = Modifier.padding(start = 14.dp)
                ) {

                    Text(
                        text = "Permission Risk",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Sensitive permission access overview",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(30.dp))

            PermissionBarChart(
                data = permissionData
            )

            Spacer(modifier = Modifier.height(24.dp))

            PermissionLegendSection(
                data = permissionData
            )
        }
    }
}

data class PermissionRiskData(
    val label: String,
    val percentage: Float,
    val color: Color
)

@Composable
fun PermissionBarChart(
    data: List<PermissionRiskData>
) {

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(240.dp)
    ) {

        val barWidth = size.width / (data.size * 2)

        data.forEachIndexed { index, item ->

            val left =
                (index * 2 + 0.5f) * barWidth

            val barHeight =
                size.height * (item.percentage / 100f)

            drawRoundRect(
                color = Color(0xFF1E293B),
                topLeft = Offset(
                    x = left,
                    y = size.height - size.height
                ),
                size = Size(
                    width = barWidth,
                    height = size.height
                ),
                cornerRadius = CornerRadius(
                    x = 24f,
                    y = 24f
                )
            )

            drawRoundRect(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        item.color,
                        item.color.copy(alpha = 0.45f)
                    )
                ),
                topLeft = Offset(
                    x = left,
                    y = size.height - barHeight
                ),
                size = Size(
                    width = barWidth,
                    height = barHeight
                ),
                cornerRadius = CornerRadius(
                    x = 24f,
                    y = 24f
                )
            )
        }
    }
}

@Composable
fun PermissionLegendSection(
    data: List<PermissionRiskData>
) {

    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        data.forEach { item ->

            PermissionLegendItem(
                label = item.label,
                percentage = "${item.percentage.toInt()}%",
                color = item.color
            )
        }
    }
}

@Composable
fun PermissionLegendItem(
    label: String,
    percentage: String,
    color: Color
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {

        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {

            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(
                        color = color,
                        shape = RoundedCornerShape(50)
                    )
            )

            Spacer(modifier = Modifier.size(10.dp))

            Text(
                text = label,
                color = Color.White,
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium
            )
        }

        Text(
            text = percentage,
            color = color,
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp
        )
    }
}
