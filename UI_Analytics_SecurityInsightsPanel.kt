package com.sentrix.ui.analytics

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
import androidx.compose.material.icons.rounded.AutoGraph
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SecurityInsightsPanel(
    modifier: Modifier = Modifier,
    insights: List<SecurityInsight> = defaultSecurityInsights()
) {

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF141C28)
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 10.dp
        )
    ) {

        Column(
            modifier = Modifier.padding(22.dp)
        ) {

            // Header
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .background(
                            brush = Brush.linearGradient(
                                colors = listOf(
                                    Color(0xFF00C6FF),
                                    Color(0xFF0072FF)
                                )
                            ),
                            shape = RoundedCornerShape(18.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Rounded.AutoGraph,
                        contentDescription = "Security Insights",
                        tint = Color.White,
                        modifier = Modifier.size(30.dp)
                    )
                }

                Spacer(modifier = Modifier.size(14.dp))

                Column {

                    Text(
                        text = "Security Insights",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "AI-generated protection recommendations",
                        color = Color(0xFF9CA3AF),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {

                items(insights.size) { index ->

                    SecurityInsightCard(
                        insight = insights[index]
                    )
                }
            }
        }
    }
}

@Composable
fun SecurityInsightCard(
    insight: SecurityInsight
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1B2432)
        )
    ) {

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalAlignment = Alignment.Top
        ) {

            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(
                        color = insight.accentColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(14.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = insight.icon,
                    contentDescription = insight.title,
                    tint = insight.accentColor,
                    modifier = Modifier.size(24.dp)
                )
            }

            Spacer(modifier = Modifier.size(14.dp))

            Column(
                modifier = Modifier.weight(1f)
            ) {

                Text(
                    text = insight.title,
                    color = Color.White,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = insight.description,
                    color = Color(0xFFD1D5DB),
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = insight.priority,
                    color = insight.accentColor,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

data class SecurityInsight(
    val title: String,
    val description: String,
    val priority: String,
    val accentColor: Color,
    val icon: androidx.compose.ui.graphics.vector.ImageVector
)

fun defaultSecurityInsights(): List<SecurityInsight> {

    return listOf(

        SecurityInsight(
            title = "Suspicious Network Activity",
            description = "Multiple unknown outbound connections were detected in the background during the last scan cycle.",
            priority = "HIGH PRIORITY",
            accentColor = Color(0xFFFF5252),
            icon = Icons.Rounded.WarningAmber
        ),

        SecurityInsight(
            title = "Privacy Optimization",
            description = "7 applications currently have unnecessary permission access enabled. Review recommended.",
            priority = "MEDIUM PRIORITY",
            accentColor = Color(0xFFFFC107),
            icon = Icons.Rounded.Info
        ),

        SecurityInsight(
            title = "Protection Status Stable",
            description = "Realtime malware protection and firewall modules are operating normally with no interruptions.",
            priority = "SYSTEM HEALTHY",
            accentColor = Color(0xFF00E676),
            icon = Icons.Rounded.Shield
        )
    )
}
