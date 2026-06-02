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
import androidx.compose.material.icons.filled.ArrowForwardIos
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
fun SettingsScreen() {

    val darkModeEnabled = remember { mutableStateOf(true) }
    val notificationEnabled = remember { mutableStateOf(true) }
    val cloudSyncEnabled = remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Settings",
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
                Spacer(modifier = Modifier.height(10.dp))

                SecurityStatusCard()
            }

            item {
                SettingsSectionTitle(title = "Account")
            }

            item {
                SettingsNavigationItem(
                    icon = Icons.Default.Person,
                    title = "Profile",
                    subtitle = "Manage account information"
                )
            }

            item {
                SettingsNavigationItem(
                    icon = Icons.Default.VerifiedUser,
                    title = "Privacy & Permissions",
                    subtitle = "Control app permissions"
                )
            }

            item {
                SettingsSectionTitle(title = "Preferences")
            }

            item {
                SettingsSwitchItem(
                    icon = Icons.Default.DarkMode,
                    title = "Dark Mode",
                    subtitle = "Enable premium dark interface",
                    checked = darkModeEnabled.value,
                    onCheckedChange = {
                        darkModeEnabled.value = it
                    }
                )
            }

            item {
                SettingsSwitchItem(
                    icon = Icons.Default.Notifications,
                    title = "Push Notifications",
                    subtitle = "Receive security alerts instantly",
                    checked = notificationEnabled.value,
                    onCheckedChange = {
                        notificationEnabled.value = it
                    }
                )
            }

            item {
                SettingsSwitchItem(
                    icon = Icons.Default.Sync,
                    title = "Cloud Sync",
                    subtitle = "Sync data securely across devices",
                    checked = cloudSyncEnabled.value,
                    onCheckedChange = {
                        cloudSyncEnabled.value = it
                    }
                )
            }

            item {
                SettingsNavigationItem(
                    icon = Icons.Default.Language,
                    title = "Language",
                    subtitle = "English (India)"
                )
            }

            item {
                SettingsSectionTitle(title = "Security")
            }

            item {
                SettingsNavigationItem(
                    icon = Icons.Default.Security,
                    title = "Security Center",
                    subtitle = "Advanced protection settings"
                )
            }

            item {
                SettingsNavigationItem(
                    icon = Icons.Default.Lock,
                    title = "Biometric Authentication",
                    subtitle = "Fingerprint & face unlock"
                )
            }

            item {
                SettingsNavigationItem(
                    icon = Icons.Default.Storage,
                    title = "Storage & Cache",
                    subtitle = "Manage application storage"
                )
            }

            item {
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}

@Composable
fun SecurityStatusCard() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(Color(0xFF111827))
            .padding(20.dp)
    ) {

        Column {
            Text(
                text = "SentriX Security Status",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "Your device is fully protected.",
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
                    text = "Protection Active",
                    color = Color(0xFF22C55E),
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
fun SettingsSectionTitle(title: String) {

    Text(
        text = title,
        color = Color(0xFFCBD5E1),
        fontWeight = FontWeight.SemiBold,
        fontSize = 15.sp,
        modifier = Modifier.padding(top = 10.dp, bottom = 4.dp)
    )
}

@Composable
fun SettingsNavigationItem(
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
                .size(46.dp)
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

        Icon(
            imageVector = Icons.Default.ArrowForwardIos,
            contentDescription = null,
            tint = Color(0xFF64748B),
            modifier = Modifier.size(16.dp)
        )
    }
}

@Composable
fun SettingsSwitchItem(
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
                .size(46.dp)
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
