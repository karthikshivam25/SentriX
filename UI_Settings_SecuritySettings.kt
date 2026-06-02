package com.sentrix.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SecuritySettingsScreen() {

    val biometricEnabled = remember { mutableStateOf(true) }
    val realtimeProtection = remember { mutableStateOf(true) }
    val autoLockEnabled = remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Security Settings",
                        fontWeight = FontWeight.Bold,
                        fontSize = 22.sp
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F172A),
                    titleContentColor = Color.White
                )
            )
        },
        containerColor = Color(0xFF020617)
    ) { paddingValues ->

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {

            item {

                Spacer(modifier = Modifier.height(8.dp))

                SecurityOverviewCard()
            }

            item {
                SecuritySectionTitle(title = "Protection")
            }

            item {
                SecuritySwitchCard(
                    icon = Icons.Default.Shield,
                    title = "Real-Time Protection",
                    subtitle = "Monitor threats continuously",
                    checked = realtimeProtection.value,
                    onCheckedChange = {
                        realtimeProtection.value = it
                    }
                )
            }

            item {
                SecuritySwitchCard(
                    icon = Icons.Default.Fingerprint,
                    title = "Biometric Authentication",
                    subtitle = "Fingerprint & face unlock security",
                    checked = biometricEnabled.value,
                    onCheckedChange = {
                        biometricEnabled.value = it
                    }
                )
            }

            item {
                SecuritySwitchCard(
                    icon = Icons.Default.Lock,
                    title = "Auto Lock",
                    subtitle = "Automatically lock sensitive areas",
                    checked = autoLockEnabled.value,
                    onCheckedChange = {
                        autoLockEnabled.value = it
                    }
                )
            }

            item {
                SecuritySectionTitle(title = "Advanced Security")
            }

            item {
                SecurityActionCard(
                    icon = Icons.Default.VerifiedUser,
                    title = "Permission Manager",
                    subtitle = "Manage application permissions"
                )
            }

            item {
                SecurityActionCard(
                    icon = Icons.Default.Key,
                    title = "Encryption Settings",
                    subtitle = "Secure local data encryption"
                )
            }

            item {
                SecurityActionCard(
                    icon = Icons.Default.Security,
                    title = "Threat Detection",
                    subtitle = "Advanced malware detection engine"
                )
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@Composable
fun SecurityOverviewCard() {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(Color(0xFF111827))
            .padding(20.dp)
    ) {

        Column {

            Text(
                text = "Device Security",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "SentriX protection systems are fully active.",
                color = Color(0xFF94A3B8),
                fontSize = 14.sp
            )

            Spacer(modifier = Modifier.height(18.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .clip(RoundedCornerShape(50))
                        .background(Color(0xFF22C55E))
                )

                Spacer(modifier = Modifier.size(8.dp))

                Text(
                    text = "Secure Environment",
                    color = Color(0xFF22C55E),
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
fun SecuritySectionTitle(
    title: String
) {

    Text(
        text = title,
        color = Color(0xFFCBD5E1),
        fontWeight = FontWeight.SemiBold,
        fontSize = 15.sp,
        modifier = Modifier.padding(top = 8.dp)
    )
}

@Composable
fun SecuritySwitchCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(Color(0xFF0F172A))
            .padding(18.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(Color(0xFF1E293B)),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color(0xFF38BDF8)
            )
        }

        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 14.dp)
        ) {

            Text(
                text = title,
                color = Color.White,
                fontWeight = FontWeight.Medium,
                fontSize = 16.sp
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = subtitle,
                color = Color(0xFF94A3B8),
                fontSize = 13.sp
            )
        }

        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = Color(0xFF2563EB),
                uncheckedThumbColor = Color.White,
                uncheckedTrackColor = Color(0xFF475569)
            )
        )
    }
}

@Composable
fun SecurityActionCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String
) {

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(Color(0xFF0F172A))
            .clickable { }
            .padding(18.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(Color(0xFF1E293B)),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color(0xFF38BDF8)
            )
        }

        Column(
            modifier = Modifier
                .padding(start = 14.dp)
        ) {

            Text(
                text = title,
                color = Color.White,
                fontWeight = FontWeight.Medium,
                fontSize = 16.sp
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = subtitle,
                color = Color(0xFF94A3B8),
                fontSize = 13.sp
            )
        }
    }
}
