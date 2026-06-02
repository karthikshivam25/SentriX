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
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
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
fun AppearanceSettingsScreen() {

    val selectedTheme = remember {
        mutableStateOf("Dark")
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Appearance",
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

                AppearancePreviewCard(theme = selectedTheme.value)
            }

            item {
                SectionTitle(title = "Theme Mode")
            }

            item {
                ThemeOptionCard(
                    icon = Icons.Default.DarkMode,
                    title = "Dark",
                    subtitle = "Premium dark experience",
                    selected = selectedTheme.value == "Dark",
                    onClick = {
                        selectedTheme.value = "Dark"
                    }
                )
            }

            item {
                ThemeOptionCard(
                    icon = Icons.Default.LightMode,
                    title = "Light",
                    subtitle = "Clean and bright interface",
                    selected = selectedTheme.value == "Light",
                    onClick = {
                        selectedTheme.value = "Light"
                    }
                )
            }

            item {
                ThemeOptionCard(
                    icon = Icons.Default.PhoneAndroid,
                    title = "System Default",
                    subtitle = "Follow device appearance",
                    selected = selectedTheme.value == "System",
                    onClick = {
                        selectedTheme.value = "System"
                    }
                )
            }

            item {
                SectionTitle(title = "Customization")
            }

            item {
                SettingsActionCard(
                    icon = Icons.Default.Palette,
                    title = "Accent Color",
                    subtitle = "Customize SentriX highlight colors"
                )
            }

            item {
                SettingsActionCard(
                    icon = Icons.Default.Check,
                    title = "Animations",
                    subtitle = "Smooth premium transitions"
                )
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@Composable
fun AppearancePreviewCard(
    theme: String
) {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(Color(0xFF111827))
            .padding(20.dp)
    ) {

        Column {

            Text(
                text = "Preview",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "Current Theme",
                color = Color(0xFF94A3B8),
                fontSize = 14.sp
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = theme,
                color = Color(0xFF38BDF8),
                fontWeight = FontWeight.SemiBold,
                fontSize = 20.sp
            )

            Spacer(modifier = Modifier.height(18.dp))

            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {

                Box(
                    modifier = Modifier
                        .size(50.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(Color(0xFF2563EB))
                )

                Box(
                    modifier = Modifier
                        .size(50.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(Color(0xFF1E293B))
                )

                Box(
                    modifier = Modifier
                        .size(50.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(Color(0xFF0F172A))
                )
            }
        }
    }
}

@Composable
fun SectionTitle(
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
fun ThemeOptionCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String,
    selected: Boolean,
    onClick: () -> Unit
) {

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(
                if (selected) {
                    Color(0xFF172554)
                } else {
                    Color(0xFF0F172A)
                }
            )
            .clickable {
                onClick()
            }
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
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = subtitle,
                color = Color(0xFF94A3B8),
                fontSize = 13.sp
            )
        }

        RadioButton(
            selected = selected,
            onClick = onClick
        )
    }
}

@Composable
fun SettingsActionCard(
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
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium
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
