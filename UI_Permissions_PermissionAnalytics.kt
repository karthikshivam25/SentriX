package com.sentrix.ui.permissions

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
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

data class PermissionAnalyticsModel(
    val title: String,
    val value: String,
    val percentage: Float,
    val analyticsType: String,
    val icon: ImageVector
)

@Composable
fun PermissionAnalyticsSection(
    analytics: List<PermissionAnalyticsModel>,
    modifier: Modifier = Modifier
) {

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 8.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF111827),
                            Color(0xFF0F172A)
                        )
                    )
                )
                .padding(vertical = 22.dp)
        ) {

            Column {

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Icon(
                        imageVector = Icons.Default.Analytics,
                        contentDescription = null,
                        tint = Color.Cyan,
                        modifier = Modifier.size(26.dp)
                    )

                    Spacer(modifier = Modifier.width(10.dp))

                    Text(
                        text = "Permission Analytics",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(16.dp),
                    contentPadding = PaddingValues(horizontal = 20.dp)
                ) {

                    items(analytics) { item ->
                        PermissionAnalyticsCard(item)
                    }
                }
            }
        }
    }
}

@Composable
private fun PermissionAnalyticsCard(
    analytics: PermissionAnalyticsModel
) {

    val analyticsColor = when (analytics.analyticsType) {
        "Critical" -> Color(0xFFFF1744)
        "Warning" -> Color(0xFFFFC400)
        "Secure" -> Color(0xFF00E676)
        else -> Color(0xFF00BCD4)
    }

    Card(
        modifier = Modifier
            .width(240.dp),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1E293B)
        )
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(analyticsColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = analytics.icon,
                        contentDescription = null,
                        tint = analyticsColor,
                        modifier = Modifier.size(24.dp)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column {

                    Text(
                        text = analytics.title,
                        color = Color.White,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = analytics.value,
                        color = analyticsColor,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(22.dp))

            LinearProgressIndicator(
                progress = { analytics.percentage },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp)
                    .clip(RoundedCornerShape(50)),
                color = analyticsColor,
                trackColor = Color(0xFF334155)
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "${(analytics.percentage * 100).toInt()}% Activity",
                color = Color(0xFFB0BEC5),
                fontSize = 12.sp
            )
        }
    }
}

/*
-----------------------------------
SAMPLE USAGE
-----------------------------------

val analyticsData = listOf(

    PermissionAnalyticsModel(
        title = "Secure Apps",
        value = "48",
        percentage = 0.82f,
        analyticsType = "Secure",
        icon = Icons.Default.Security
    ),

    PermissionAnalyticsModel(
        title = "Critical Risks",
        value = "6",
        percentage = 0.34f,
        analyticsType = "Critical",
        icon = Icons.Default.WarningAmber
    ),

    PermissionAnalyticsModel(
        title = "Permission Usage",
        value = "92%",
        percentage = 0.92f,
        analyticsType = "Analytics",
        icon = Icons.Default.Analytics
    )
)

PermissionAnalyticsSection(
    analytics = analyticsData
)
