package com.sentrix.ui.screens.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentrix.ui.animations.ShieldProtectionAnimation
import com.sentrix.ui.animations.VPNConnectAnimation
import com.sentrix.ui.components.AppRiskCard
import com.sentrix.ui.components.DeviceInfoCard
import com.sentrix.ui.components.QuickActionButton
import com.sentrix.ui.components.VPNStatusCard

@Composable
fun DashboardScreen(
    onOpenVpn: () -> Unit = {},
    onOpenThreats: () -> Unit = {},
    onOpenSettings: () -> Unit = {}
) {

    var isVpnConnected by remember {
        mutableStateOf(true)
    }

    val backgroundGradient = Brush.verticalGradient(
        colors = listOf(
            Color(0xFF081120),
            Color(0xFF0D1B2A),
            Color(0xFF111827)
        )
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(backgroundGradient)
    ) {

        LazyColumn(
            modifier = Modifier
                .fillMaxSize(),
            contentPadding = PaddingValues(
                horizontal = 20.dp,
                vertical = 24.dp
            ),
            verticalArrangement = Arrangement.spacedBy(22.dp)
        ) {

            // --------------------------------------------------
            // HEADER
            // --------------------------------------------------

            item {

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Column {

                        Text(
                            text = "SentriX Security",
                            color = Color.White,
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "Your system is protected",
                            color = Color(0xFF9CA3AF),
                            fontSize = 14.sp
                        )
                    }

                    IconButton(
                        onClick = onOpenSettings
                    ) {

                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings",
                            tint = Color.White
                        )
                    }
                }
            }

            // --------------------------------------------------
            // MAIN SECURITY ANIMATION
            // --------------------------------------------------

            item {

                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {

                    ShieldProtectionAnimation(
                        modifier = Modifier.size(260.dp),
                        isProtected = true
                    )
                }
            }

            // --------------------------------------------------
            // VPN STATUS CARD
            // --------------------------------------------------

            item {

                VPNStatusCard(
                    isConnected = isVpnConnected,
                    vpnLocation = "Singapore",
                    ping = "18ms",
                    onToggleVpn = {
                        isVpnConnected = !isVpnConnected
                    }
                )
            }

            // --------------------------------------------------
            // VPN CONNECT ANIMATION
            // --------------------------------------------------

            item {

                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {

                    VPNConnectAnimation(
                        modifier = Modifier.size(220.dp),
                        isConnected = isVpnConnected
                    )
                }
            }

            // --------------------------------------------------
            // QUICK ACTIONS
            // --------------------------------------------------

            item {

                Text(
                    text = "Quick Actions",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.SemiBold
                )

                Spacer(modifier = Modifier.height(14.dp))

                Column(
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {

                    Row(
                        horizontalArrangement = Arrangement.spacedBy(14.dp)
                    ) {

                        QuickActionButton(
                            title = "VPN",
                            icon = Icons.Default.Security,
                            accentColor = Color(0xFF00D9FF),
                            onClick = onOpenVpn
                        )

                        QuickActionButton(
                            title = "Threats",
                            icon = Icons.Default.Warning,
                            accentColor = Color(0xFFFF5252),
                            onClick = onOpenThreats
                        )
                    }

                    Row(
                        horizontalArrangement = Arrangement.spacedBy(14.dp)
                    ) {

                        QuickActionButton(
                            title = "Scan",
                            icon = Icons.Default.Scanner,
                            accentColor = Color(0xFF00E676),
                            onClick = {}
                        )

                        QuickActionButton(
                            title = "Firewall",
                            icon = Icons.Default.Shield,
                            accentColor = Color(0xFFFFC107),
                            onClick = {}
                        )
                    }
                }
            }

            // --------------------------------------------------
            // DEVICE INFO
            // --------------------------------------------------

            item {

                DeviceInfoCard(
                    deviceName = "SentriX Device",
                    androidVersion = "Android 15",
                    securityPatch = "May 2026",
                    isSecure = true
                )
            }

            // --------------------------------------------------
            // APP RISK ANALYSIS
            // --------------------------------------------------

            item {

                AppRiskCard(
                    riskyApps = 2,
                    scannedApps = 148,
                    protectionLevel = "High"
                )
            }

            // --------------------------------------------------
            // SYSTEM STATUS
            // --------------------------------------------------

            item {

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF111827)
                    ),
                    shape = RoundedCornerShape(24.dp)
                ) {

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(18.dp)
                    ) {

                        Text(
                            text = "System Status",
                            color = Color.White,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold
                        )

                        StatusItem(
                            title = "Firewall",
                            status = "Active",
                            color = Color(0xFF00E676)
                        )

                        StatusItem(
                            title = "Real-time Monitoring",
                            status = "Running",
                            color = Color(0xFF00D9FF)
                        )

                        StatusItem(
                            title = "Threat Detection",
                            status = "Secured",
                            color = Color(0xFF00E676)
                        )

                        StatusItem(
                            title = "Network Encryption",
                            status = "Enabled",
                            color = Color(0xFFFFC107)
                        )
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(30.dp))
            }
        }
    }
}

@Composable
private fun StatusItem(
    title: String,
    status: String,
    color: Color
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {

        Text(
            text = title,
            color = Color(0xFFD1D5DB),
            fontSize = 15.sp
        )

        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {

            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(RoundedCornerShape(50))
                    .background(color)
            )

            Spacer(modifier = Modifier.width(8.dp))

            Text(
                text = status,
                color = color,
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}
