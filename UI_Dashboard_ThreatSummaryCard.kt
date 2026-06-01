package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun ThreatSummaryCard(
    modifier: Modifier = Modifier,
    activeThreats: Int = 2,
    blockedThreats: Int = 48,
    quarantinedFiles: Int = 6,
    securityStatus: String = "Protected"
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "threat_summary_glow"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.18f,
        targetValue = 0.45f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2300,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    val statusColor = when {
        activeThreats == 0 -> Color(0xFF00E676)
        activeThreats <= 3 -> Color(0xFFFFC107)
        else -> Color(0xFFFF5252)
    }

    Box(
        modifier = modifier
    ) {

        // ----------------------------------------
        // OUTER GLOW
        // ----------------------------------------

        Box(
            modifier = Modifier
                .matchParentSize()
                .blur(34.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            statusColor.copy(alpha = glowAlpha),
                            statusColor.copy(alpha = glowAlpha * 0.35f)
                        )
                    )
                )
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(30.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF111827)
            )
        ) {

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(22.dp)
            ) {

                // ----------------------------------------
                // HEADER
                // ----------------------------------------

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(56.dp)
                            .clip(CircleShape)
                            .background(
                                statusColor.copy(alpha = 0.14f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = if (activeThreats == 0) {
                                Icons.Default.Security
                            } else {
                                Icons.Default.WarningAmber
                            },
                            contentDescription = "Threat Summary",
                            tint = statusColor,
                            modifier = Modifier.size(30.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column {

                        Text(
                            text = "Threat Summary",
                            color = Color.White,
                            fontSize = 21.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = securityStatus,
                            color = statusColor,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(26.dp))

                // ----------------------------------------
                // MAIN THREAT STATUS
                // ----------------------------------------

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(26.dp))
                        .background(
                            Color.White.copy(alpha = 0.04f)
                        )
                        .padding(vertical = 26.dp),
                    contentAlignment = Alignment.Center
                ) {

                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {

                        Text(
                            text = activeThreats.toString(),
                            color = statusColor,
                            fontSize = 54.sp,
                            fontWeight = FontWeight.ExtraBold
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Text(
                            text = if (activeThreats == 1) {
                                "ACTIVE THREAT"
                            } else {
                                "ACTIVE THREATS"
                            },
                            color = Color(0xFF9CA3AF),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // STATS GRID
                // ----------------------------------------

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    ThreatStatItem(
                        modifier = Modifier.weight(1f),
                        title = "Blocked",
                        value = blockedThreats.toString(),
                        accentColor = Color(0xFF00E676),
                        icon = Icons.Default.Security
                    )

                    ThreatStatItem(
                        modifier = Modifier.weight(1f),
                        title = "Quarantined",
                        value = quarantinedFiles.toString(),
                        accentColor = Color(0xFFFF9100),
                        icon = Icons.Default.BugReport
                    )
                }
            }
        }
    }
}

@Composable
private fun ThreatStatItem(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    accentColor: Color,
    icon: androidx.compose.ui.graphics.vector.ImageVector
) {

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(22.dp))
            .background(
                Color.White.copy(alpha = 0.04f)
            )
            .padding(18.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Box(
            modifier = Modifier
                .size(46.dp)
                .clip(CircleShape)
                .background(
                    accentColor.copy(alpha = 0.14f)
                ),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = accentColor,
                modifier = Modifier.size(24.dp)
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        Text(
            text = value,
            color = accentColor,
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = title,
            color = Color(0xFF9CA3AF),
            fontSize = 13.sp
        )
    }
}
