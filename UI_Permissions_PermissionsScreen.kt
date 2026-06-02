package com.sentrix.ui.permissions

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class PermissionItem(
    val title: String,
    val description: String,
    val icon: androidx.compose.ui.graphics.vector.ImageVector,
    val granted: Boolean,
    val riskLevel: String
)

@Composable
fun PermissionsScreen() {

    val permissions = listOf(
        PermissionItem(
            "Camera",
            "Used for QR scans and threat capture",
            Icons.Default.CameraAlt,
            true,
            "Low"
        ),
        PermissionItem(
            "Microphone",
            "Voice AI Assistant access",
            Icons.Default.Mic,
            false,
            "Medium"
        ),
        PermissionItem(
            "Location",
            "VPN region optimization",
            Icons.Default.LocationOn,
            true,
            "Medium"
        ),
        PermissionItem(
            "Notifications",
            "Threat alerts and warnings",
            Icons.Default.Notifications,
            true,
            "Low"
        ),
        PermissionItem(
            "Storage",
            "Scan downloaded files",
            Icons.Default.Storage,
            false,
            "High"
        )
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Permissions Center",
                        fontWeight = FontWeight.Bold
                    )
                }
            )
        }
    ) { padding ->

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(Color(0xFF0A0F1C)),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {

            item {
                SecurityOverviewCard()
            }

            item {
                Spacer(modifier = Modifier.height(8.dp))
            }

            items(permissions) { permission ->
                PermissionCard(permission)
            }
        }
    }
}

@Composable
private fun SecurityOverviewCard() {

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF121A2B)
        ),
        shape = RoundedCornerShape(20.dp)
    ) {

        Column(
            modifier = Modifier.padding(20.dp)
        ) {

            Text(
                text = "Permission Security Score",
                color = Color.White,
                fontSize = 16.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "84%",
                color = Color(0xFF00E676),
                fontSize = 34.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "3 permissions granted • 2 require attention",
                color = Color.LightGray
            )
        }
    }
}

@Composable
private fun PermissionCard(
    permission: PermissionItem
) {

    val statusColor =
        if (permission.granted)
            Color(0xFF00E676)
        else
            Color(0xFFFF5252)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF121A2B)
        ),
        shape = RoundedCornerShape(18.dp)
    ) {

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = permission.icon,
                contentDescription = null,
                tint = Color.Cyan,
                modifier = Modifier.size(30.dp)
            )

            Spacer(modifier = Modifier.width(14.dp))

            Column(
                modifier = Modifier.weight(1f)
            ) {

                Text(
                    text = permission.title,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold
                )

                Text(
                    text = permission.description,
                    color = Color.LightGray,
                    fontSize = 12.sp
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Risk Level: ${permission.riskLevel}",
                    color = when (permission.riskLevel) {
                        "High" -> Color.Red
                        "Medium" -> Color.Yellow
                        else -> Color.Green
                    },
                    fontSize = 11.sp
                )
            }

            Switch(
                checked = permission.granted,
                onCheckedChange = {}
            )
        }
    }
}
