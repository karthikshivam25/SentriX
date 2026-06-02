package com.sentrix.ui.vpn

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class VPNProtocol(
    val id: Int,
    val name: String,
    val description: String,
    val securityLevel: String,
    val speedLevel: String,
    val recommended: Boolean
)

@Composable
fun VPNProtocolSelector(

    protocols: List<VPNProtocol>,
    selectedProtocolId: Int?,
    modifier: Modifier = Modifier,
    onProtocolSelected: (VPNProtocol) -> Unit = {}
) {

    Column(
        modifier = modifier.fillMaxWidth()
    ) {

        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = Icons.Default.Tune,
                contentDescription = null,
                tint = Color(0xFF00E5FF)
            )

            Spacer(modifier = Modifier.width(10.dp))

            Text(
                text = "VPN Protocols",
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {

            items(protocols) { protocol ->

                VPNProtocolCard(
                    protocol = protocol,
                    isSelected = selectedProtocolId == protocol.id,
                    onClick = {
                        onProtocolSelected(protocol)
                    }
                )
            }
        }
    }
}

@Composable
fun VPNProtocolCard(

    protocol: VPNProtocol,
    isSelected: Boolean,
    onClick: () -> Unit
) {

    val borderColor by animateColorAsState(
        targetValue = if (isSelected) {
            Color(0xFF00E5FF)
        } else {
            Color.Transparent
        },
        label = "protocol_border_color"
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

            Column {

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Text(
                                text = protocol.name,
                                color = Color.White,
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold
                            )

                            if (protocol.recommended) {

                                Spacer(modifier = Modifier.width(8.dp))

                                RecommendedProtocolBadge()
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = protocol.description,
                            color = Color.LightGray,
                            fontSize = 13.sp,
                            lineHeight = 20.sp,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis
                        )
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

                Spacer(modifier = Modifier.height(18.dp))

                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {

                    ProtocolInfoChip(
                        icon = Icons.Default.Security,
                        label = protocol.securityLevel,
                        color = Color(0xFF00E676)
                    )

                    ProtocolInfoChip(
                        icon = Icons.Default.Speed,
                        label = protocol.speedLevel,
                        color = Color(0xFF00E5FF)
                    )
                }
            }
        }
    }
}

@Composable
fun ProtocolInfoChip(

    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    color: Color
) {

    Surface(
        shape = RoundedCornerShape(50),
        color = color.copy(alpha = 0.12f)
    ) {

        Row(
            modifier = Modifier.padding(
                horizontal = 12.dp,
                vertical = 8.dp
            ),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(14.dp)
            )

            Spacer(modifier = Modifier.width(6.dp))

            Text(
                text = label,
                color = color,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun RecommendedProtocolBadge() {

    Surface(
        shape = RoundedCornerShape(50),
        color = Color(0x2200E676)
    ) {

        Text(
            text = "RECOMMENDED",
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
fun VPNProtocolPreviewData(): List<VPNProtocol> {

    return listOf(

        VPNProtocol(
            id = 1,
            name = "WireGuard",
            description = "Modern ultra-fast VPN protocol with advanced encryption and minimal latency.",
            securityLevel = "HIGH SECURITY",
            speedLevel = "ULTRA FAST",
            recommended = true
        ),

        VPNProtocol(
            id = 2,
            name = "OpenVPN",
            description = "Industry-standard secure VPN protocol widely trusted for privacy and reliability.",
            securityLevel = "MAX SECURITY",
            speedLevel = "FAST",
            recommended = false
        ),

        VPNProtocol(
            id = 3,
            name = "IKEv2/IPSec",
            description = "Stable protocol optimized for mobile devices and network switching.",
            securityLevel = "SECURE",
            speedLevel = "HIGH SPEED",
            recommended = false
        )
    )
}
