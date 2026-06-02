package com.sentrix.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WorkspacePremium
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SubscriptionScreen() {

    val selectedPlan = remember {
        mutableStateOf("Pro")
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Subscription",
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
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {

            item {

                Spacer(modifier = Modifier.height(8.dp))

                CurrentPlanCard()
            }

            item {
                PlanCard(
                    title = "Free",
                    price = "₹0 / month",
                    description = "Basic protection and scanning features",
                    features = listOf(
                        "Basic Threat Detection",
                        "Manual Device Scans",
                        "Standard Privacy Protection"
                    ),
                    isSelected = selectedPlan.value == "Free",
                    onClick = {
                        selectedPlan.value = "Free"
                    }
                )
            }

            item {
                PremiumPlanCard(
                    title = "Pro",
                    price = "₹299 / month",
                    description = "Advanced security & premium protection",
                    features = listOf(
                        "Real-Time Threat Detection",
                        "AI Malware Scanner",
                        "Privacy Shield",
                        "Cloud Sync Protection",
                        "Advanced Reports"
                    ),
                    isSelected = selectedPlan.value == "Pro",
                    onClick = {
                        selectedPlan.value = "Pro"
                    }
                )
            }

            item {
                PlanCard(
                    title = "Enterprise",
                    price = "₹999 / month",
                    description = "Professional-grade enterprise security",
                    features = listOf(
                        "Multi-Device Management",
                        "Enterprise Monitoring",
                        "Dedicated Security Dashboard"
                    ),
                    isSelected = selectedPlan.value == "Enterprise",
                    onClick = {
                        selectedPlan.value = "Enterprise"
                    }
                )
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@Composable
fun CurrentPlanCard() {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(26.dp))
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF1D4ED8),
                        Color(0xFF0F172A)
                    )
                )
            )
            .padding(24.dp)
    ) {

        Column {

            Text(
                text = "Current Subscription",
                color = Color(0xFFE2E8F0),
                fontSize = 14.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Icon(
                    imageVector = Icons.Default.WorkspacePremium,
                    contentDescription = null,
                    tint = Color(0xFFFACC15)
                )

                Spacer(modifier = Modifier.size(8.dp))

                Text(
                    text = "SentriX Pro",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 24.sp
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = "Your premium protection is active and fully secured.",
                color = Color(0xFFCBD5E1),
                fontSize = 14.sp
            )
        }
    }
}

@Composable
fun PlanCard(
    title: String,
    price: String,
    description: String,
    features: List<String>,
    isSelected: Boolean,
    onClick: () -> Unit
) {

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(22.dp))
            .background(Color(0xFF0F172A))
            .border(
                width = if (isSelected) 2.dp else 1.dp,
                color = if (isSelected) {
                    Color(0xFF2563EB)
                } else {
                    Color(0xFF1E293B)
                },
                shape = RoundedCornerShape(22.dp)
            )
            .clickable {
                onClick()
            }
            .padding(20.dp)
    ) {

        Text(
            text = title,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = price,
            color = Color(0xFF38BDF8),
            fontWeight = FontWeight.SemiBold,
            fontSize = 18.sp
        )

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = description,
            color = Color(0xFF94A3B8),
            fontSize = 14.sp
        )

        Spacer(modifier = Modifier.height(18.dp))

        features.forEach { feature ->

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(vertical = 5.dp)
            ) {

                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = Color(0xFF22C55E),
                    modifier = Modifier.size(18.dp)
                )

                Spacer(modifier = Modifier.size(10.dp))

                Text(
                    text = feature,
                    color = Color.White,
                    fontSize = 14.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        Button(
            onClick = { },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF1E293B)
            ),
            shape = RoundedCornerShape(14.dp)
        ) {

            Text(
                text = if (isSelected) {
                    "Selected Plan"
                } else {
                    "Choose Plan"
                }
            )
        }
    }
}

@Composable
fun PremiumPlanCard(
    title: String,
    price: String,
    description: String,
    features: List<String>,
    isSelected: Boolean,
    onClick: () -> Unit
) {

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF1E3A8A),
                        Color(0xFF0F172A)
                    )
                )
            )
            .border(
                width = 2.dp,
                color = Color(0xFF3B82F6),
                shape = RoundedCornerShape(24.dp)
            )
            .clickable {
                onClick()
            }
            .padding(22.dp)
    ) {

        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = null,
                tint = Color(0xFF60A5FA)
            )

            Spacer(modifier = Modifier.size(8.dp))

            Text(
                text = "Most Popular",
                color = Color(0xFF93C5FD),
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold
            )
        }

        Spacer(modifier = Modifier.height(18.dp))

        Text(
            text = title,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 24.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = price,
            color = Color(0xFF7DD3FC),
            fontWeight = FontWeight.SemiBold,
            fontSize = 19.sp
        )

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = description,
            color = Color(0xFFCBD5E1),
            fontSize = 14.sp
        )

        Spacer(modifier = Modifier.height(18.dp))

        features.forEach { feature ->

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(vertical = 5.dp)
            ) {

                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = Color(0xFF22C55E),
                    modifier = Modifier.size(18.dp)
                )

                Spacer(modifier = Modifier.size(10.dp))

                Text(
                    text = feature,
                    color = Color.White,
                    fontSize = 14.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Button(
            onClick = { },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF2563EB)
            ),
            shape = RoundedCornerShape(14.dp)
        ) {

            Text(
                text = if (isSelected) {
                    "Current Plan"
                } else {
                    "Upgrade to Pro"
                },
                color = Color.White
            )
        }
    }
}
