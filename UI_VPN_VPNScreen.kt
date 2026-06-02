package com.sentrix.ui.vpn

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class VPNServer(
    val country: String,
    val city: String,
    val latency: Int,
    val isRecommended: Boolean
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VPNScreen() {

    var vpnEnabled by remember {
        mutableStateOf(false)
    }

    var selectedServer by remember {
        mutableStateOf(
            VPNServer(
                country = "Singapore",
                city = "Singapore",
                latency = 42,
                isRecommended = true
            )
        )
    }

    val servers = remember {
        listOf(
            VPNServer("Singapore", "Singapore", 42, true),
            VPNServer("Germany", "Frankfurt", 118, false),
            VPNServer("United States", "New York", 202, false),
            VPNServer("Japan", "Tokyo", 86, false),
            VPNServer("United Kingdom", "London", 174, false)
        )
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "vpn_animation"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1200
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Secure VPN",
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {

                    IconButton(onClick = { }) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = null
                        )
                    }
                }
            )
        },
        containerColor = Color(0xFF0B1020)
    ) { paddingValues ->

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {

            item {
                Spacer(modifier = Modifier.height(6.dp))
            }

            item {

                VPNStatusCard(
                    vpnEnabled = vpnEnabled,
                    pulseAlpha = pulseAlpha,
                    selectedServer = selectedServer,
                    onToggleVPN = {
                        vpnEnabled = !vpnEnabled
                    }
                )
            }

            item {

                VPNStatisticsSection(
                    vpnEnabled = vpnEnabled
                )
            }

            item {

                Text(
                    text = "Available Servers",
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            items(servers.size) { index ->

                VPNServerCard(
                    server = servers[index],
                    isSelected = selectedServer == servers[index],
                    onSelect = {
                        selectedServer = servers[index]
                    }
                )
            }

            item {
                Spacer(modifier = Modifier.height(30.dp))
            }
        }
    }
}

@Composable
fun VPNStatusCard(

    vpnEnabled: Boolean,
    pulseAlpha: Float,
    selectedServer: VPNServer,
    onToggleVPN: () -> Unit
) {

    val statusColor = if (vpnEnabled) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFF5252)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(30.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF1A1F35),
                            Color(0xFF101728)
                        )
                    )
                )
                .padding(24.dp)
        ) {

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {

                Box(
                    modifier = Modifier.size(160.dp),
                    contentAlignment = Alignment.Center
                ) {

                    Box(
                        modifier = Modifier
                            .size(150.dp)
                            .clip(CircleShape)
                            .background(
                                statusColor.copy(alpha = 0.12f)
                            )
                            .alpha(pulseAlpha)
                    )

                    FilledIconButton(
                        onClick = onToggleVPN,
                        modifier = Modifier.size(92.dp),
                        colors = IconButtonDefaults.filledIconButtonColors(
                            containerColor = statusColor
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.PowerSettingsNew,
                            contentDescription = null,
                            tint = Color.Black,
                            modifier = Modifier.size(38.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                Text(
                    text = if (vpnEnabled) {
                        "VPN Connected"
                    } else {
                        "VPN Disconnected"
                    },
                    color = Color.White,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(statusColor)
                    )

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(
                        text = "${selectedServer.country} • ${selectedServer.city}",
                        color = Color.LightGray,
                        fontSize = 14.sp
                    )
                }

                Spacer(modifier = Modifier.height(22.dp))

                AnimatedVisibility(
                    visible = vpnEnabled
                ) {

                    Surface(
                        shape = RoundedCornerShape(18.dp),
                        color = Color(0xFF111827)
                    ) {

                        Row(
                            modifier = Modifier.padding(
                                horizontal = 18.dp,
                                vertical = 12.dp
                            ),
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = null,
                                tint = Color(0xFF00E5FF)
                            )

                            Spacer(modifier = Modifier.width(10.dp))

                            Text(
                                text = "Your traffic is securely encrypted",
                                color = Color.LightGray,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun VPNStatisticsSection(

    vpnEnabled: Boolean
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(14.dp)
    ) {

        VPNStatCard(
            modifier = Modifier.weight(1f),
            title = "IP Status",
            value = if (vpnEnabled) "Protected" else "Exposed",
            icon = Icons.Default.Public,
            valueColor = if (vpnEnabled)
                Color(0xFF00E676)
            else
                Color(0xFFFF5252)
        )

        VPNStatCard(
            modifier = Modifier.weight(1f),
            title = "Encryption",
            value = if (vpnEnabled) "AES-256" else "--",
            icon = Icons.Default.Lock,
            valueColor = Color(0xFF00E5FF)
        )
    }
}

@Composable
fun VPNStatCard(

    modifier: Modifier = Modifier,
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    valueColor: Color
) {

    Card(
        modifier = modifier,
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF151C2E)
        )
    ) {

        Column(
            modifier = Modifier.padding(18.dp)
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color(0xFF00E5FF)
            )

            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = title,
                color = Color.Gray,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = value,
                color = valueColor,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun VPNServerCard(

    server: VPNServer,
    isSelected: Boolean,
    onSelect: () -> Unit
) {

    Card(
        onClick = onSelect,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected)
                Color(0xFF1C2942)
            else
                Color(0xFF151C2E)
        )
    ) {

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Box(
                modifier = Modifier
                    .size(52.dp)
                    .clip(CircleShape)
                    .background(
                        if (isSelected)
                            Color(0x2200E5FF)
                        else
                            Color(0xFF1E293B)
                    ),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = Icons.Default.Language,
                    contentDescription = null,
                    tint = if (isSelected)
                        Color(0xFF00E5FF)
                    else
                        Color.LightGray
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

                    if (server.isRecommended) {

                        Spacer(modifier = Modifier.width(8.dp))

                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(0x2200E676)
                        ) {

                            Text(
                                text = "BEST",
                                modifier = Modifier.padding(
                                    horizontal = 10.dp,
                                    vertical = 4.dp
                                ),
                                color = Color(0xFF00E676),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = "${server.city} • ${server.latency} ms",
                    color = Color.Gray,
                    fontSize = 13.sp
                )
            }

            if (isSelected) {

                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = Color(0xFF00E676)
                )
            }
        }
    }
}
