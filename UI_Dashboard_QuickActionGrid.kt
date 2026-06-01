package com.sentrix.ui.screens.dashboard.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class QuickActionItem(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val accentColor: Color,
    val onClick: () -> Unit
)

@Composable
fun QuickActionGrid(
    modifier: Modifier = Modifier,
    actions: List<QuickActionItem> = defaultQuickActions()
) {

    Column(
        modifier = modifier.fillMaxWidth()
    ) {

        // ----------------------------------------
        // SECTION TITLE
        // ----------------------------------------

        Text(
            text = "Quick Actions",
            color = Color.White,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(18.dp))

        // ----------------------------------------
        // GRID
        // ----------------------------------------

        Column(
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {

            actions.chunked(2).forEach { rowItems ->

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    rowItems.forEach { item ->

                        QuickActionCard(
                            item = item,
                            modifier = Modifier.weight(1f)
                        )
                    }

                    // Fill remaining space if odd count
                    if (rowItems.size == 1) {
                        Spacer(modifier = Modifier.weight(1f))
                    }
                }
            }
        }
    }
}

@Composable
private fun QuickActionCard(
    item: QuickActionItem,
    modifier: Modifier = Modifier
) {

    Box(
        modifier = modifier
    ) {

        // GLOW EFFECT
        Box(
            modifier = Modifier
                .matchParentSize()
                .blur(28.dp)
                .clip(RoundedCornerShape(28.dp))
                .background(
                    item.accentColor.copy(alpha = 0.22f)
                )
        )

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(155.dp)
                .clickable {
                    item.onClick.invoke()
                },
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF111827)
            )
        ) {

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(
                            colors = listOf(
                                Color.White.copy(alpha = 0.03f),
                                Color.Transparent
                            )
                        )
                    )
                    .padding(20.dp)
            ) {

                Column(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.SpaceBetween
                ) {

                    // ICON CONTAINER
                    Box(
                        modifier = Modifier
                            .size(58.dp)
                            .clip(RoundedCornerShape(18.dp))
                            .background(
                                item.accentColor.copy(alpha = 0.14f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = item.icon,
                            contentDescription = item.title,
                            tint = item.accentColor,
                            modifier = Modifier.size(30.dp)
                        )
                    }

                    // TEXTS
                    Column {

                        Text(
                            text = item.title,
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Text(
                            text = item.subtitle,
                            color = Color(0xFF9CA3AF),
                            fontSize = 13.sp,
                            lineHeight = 18.sp
                        )
                    }
                }
            }
        }
    }
}

private fun defaultQuickActions(): List<QuickActionItem> {

    return listOf(

        QuickActionItem(
            title = "Secure VPN",
            subtitle = "Encrypted private connection",
            icon = Icons.Default.Security,
            accentColor = Color(0xFF00D9FF),
            onClick = {}
        ),

        QuickActionItem(
            title = "Threat Scan",
            subtitle = "Deep system malware analysis",
            icon = Icons.Default.Scanner,
            accentColor = Color(0xFF00E676),
            onClick = {}
        ),

        QuickActionItem(
            title = "Firewall",
            subtitle = "Advanced network protection",
            icon = Icons.Default.Shield,
            accentColor = Color(0xFFFFC107),
            onClick = {}
        ),

        QuickActionItem(
            title = "Live Monitor",
            subtitle = "Real-time activity tracking",
            icon = Icons.Default.Visibility,
            accentColor = Color(0xFFFF5252),
            onClick = {}
        )
    )
}
