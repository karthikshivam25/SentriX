package com.sentrix.ui.vpn

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class VPNServerItem(
    val id: Int,
    val country: String,
    val city: String,
    val latency: Int,
    val loadPercentage: Int,
    val isPremium: Boolean,
    val isRecommended: Boolean
)

@Composable
fun VPNServerList(

    servers: List<VPNServerItem>,
    selectedServerId: Int?,
    modifier: Modifier = Modifier,
    onServerSelected: (VPNServerItem) -> Unit = {}
) {

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {

        items(servers) { server ->

            VPNServerItemCard(
                server = server,
                isSelected = selectedServerId == server.id,
                onClick = {
                    onServerSelected(server)
                }
            )
        }
    }
}

@Composable
fun VPNServerItemCard(

    server: VPNServerItem,
    isSelected: Boolean,
    onClick: () -> Unit
) {

    val borderColor by animateColorAsState(
        targetValue = if (isSelected) {
            Color(0xFF00E5FF)
        } else {
            Color.Transparent
        },
        label = "server_border_color"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                onClick()
            },
        shape = RoundedCornerShape(24.dp),
        border = androidx.compose.foundation.BorderStroke(
            width = 1.5.dp,
            color = borderColor
        ),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 5.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF182235),
                            Color(0xFF101827)
                        )
                    )
                )
                .padding(18.dp)
        ) {

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .clip(CircleShape)
                        .background(
                            if (isSelected) {
                                Color(0x2200E5FF)
                            } else {
                                Color(0xFF1E293B)
                            }
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Language,
                        contentDescription = null,
                        tint = if (isSelected) {
                            Color(0xFF00E5FF)
                        } else {
                            Color.White
                        },
                        modifier = Modifier.size(28.dp)
                    )
                }

                Spacer(modifier = Modifier.width(16.dp))

                Column(
                    modifier = Modifier.weight(1f)
                ) {

                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Text(
                            text = server.country,
                            color = Color.White,
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold
                        )

                        if (server.isPremium) {

                            Spacer(modifier = Modifier.width(8.dp))

                            PremiumServerBadge()
                        }

                        if (server.isRecommended) {

                            Spacer(modifier = Modifier.width(8.dp))

                            RecommendedServerBadge()
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = server.city,
                        color = Color.Gray,
                        fontSize = 13.sp
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = Icons.Default.Speed,
                            contentDescription = null,
                            tint = Color(0xFF00E676),
                            modifier = Modifier.size(18.dp)
                        )

                        Spacer(modifier = Modifier.width(6.dp))

                        Text(
                            text = "${server.latency} ms",
                            color = Color.LightGray,
                            fontSize = 13.sp
                        )

                        Spacer(modifier = Modifier.width(18.dp))

                        Text(
                            text = "Load ${server.loadPercentage}%",
                            color = Color.Gray,
                            fontSize = 12.sp
                        )
                    }
                }

                if (isSelected) {

                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = Color(0xFF00E676),
                        modifier = Modifier.size(28.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun PremiumServerBadge() {

    Surface(
        shape = RoundedCornerShape(50),
        color = Color(0x22FFC107)
    ) {

        Row(
            modifier = Modifier.padding(
                horizontal = 10.dp,
                vertical = 5.dp
            ),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = Icons.Default.Star,
                contentDescription = null,
                tint = Color(0xFFFFC107),
                modifier = Modifier.size(12.dp)
            )

            Spacer(modifier = Modifier.width(4.dp))

            Text(
                text = "PREMIUM",
                color = Color(0xFFFFC107),
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun RecommendedServerBadge() {

    Surface(
        shape = RoundedCornerShape(50),
        color = Color(0x2200E676)
    ) {

        Text(
            text = "BEST",
            modifier = Modifier.padding(
                horizontal = 10.dp,
                vertical = 5.dp
            ),
            color = Color(0xFF00E676),
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun VPNServerPreviewData(): List<VPNServerItem> {

    return listOf(

        VPNServerItem(
            id = 1,
            country = "Singapore",
            city = "Singapore",
            latency = 42,
            loadPercentage = 28,
            isPremium = true,
            isRecommended = true
        ),

        VPNServerItem(
            id = 2,
            country = "Japan",
            city = "Tokyo",
            latency = 78,
            loadPercentage = 45,
            isPremium = true,
            isRecommended = false
        ),

        VPNServerItem(
            id = 3,
            country = "Germany",
            city = "Frankfurt",
            latency = 118,
            loadPercentage = 52,
            isPremium = false,
            isRecommended = false
        ),

        VPNServerItem(
            id = 4,
            country = "United States",
            city = "New York",
            latency = 204,
            loadPercentage = 66,
            isPremium = false,
            isRecommended = false
        )
    )
}
