package com.sentrix.ui.onboarding

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Email
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Login
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

@Composable
fun LoginScreen(
    onLoginClick: () -> Unit = {},
    onSignupClick: () -> Unit = {},
    onForgotPasswordClick: () -> Unit = {}
) {

    var email by remember {
        mutableStateOf("")
    }

    var password by remember {
        mutableStateOf("")
    }

    var passwordVisible by remember {
        mutableStateOf(false)
    }

    var contentVisible by remember {
        mutableStateOf(false)
    }

    LaunchedEffect(Unit) {

        delay(250)

        contentVisible = true
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF07111F),
                        Color(0xFF0F172A),
                        Color(0xFF131C2B)
                    )
                )
            )
            .navigationBarsPadding()
    ) {

        // Background Glow
        Box(
            modifier = Modifier
                .size(320.dp)
                .align(Alignment.TopCenter)
                .alpha(0.16f)
                .background(
                    color = Color(0xFF00C6FF),
                    shape = CircleShape
                )
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 26.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Spacer(modifier = Modifier.height(70.dp))

            AnimatedVisibility(
                visible = contentVisible,
                enter = fadeIn() + slideInVertically()
            ) {

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {

                    // Logo
                    Box(
                        modifier = Modifier
                            .size(130.dp)
                            .background(
                                brush = Brush.linearGradient(
                                    colors = listOf(
                                        Color(0xFF00C6FF),
                                        Color(0xFF0072FF)
                                    )
                                ),
                                shape = RoundedCornerShape(36.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Rounded.Security,
                            contentDescription = "SentriX Logo",
                            tint = Color.White,
                            modifier = Modifier.size(66.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(34.dp))

                    Text(
                        text = "Welcome Back",
                        color = Color.White,
                        fontSize = 32.sp,
                        fontWeight = FontWeight.ExtraBold
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = "Login to continue protecting your device with SentriX.",
                        color = Color(0xFFB0BAC8),
                        fontSize = 15.sp,
                        textAlign = TextAlign.Center,
                        lineHeight = 24.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(40.dp))

            // Login Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(28.dp),
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF182231)
                ),
                elevation = CardDefaults.cardElevation(
                    defaultElevation = 8.dp
                )
            ) {

                Column(
                    modifier = Modifier.padding(22.dp)
                ) {

                    Text(
                        text = "Email Address",
                        color = Color.White,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = email,
                        onValueChange = {
                            email = it
                        },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = {
                            Text(
                                text = "Enter your email",
                                color = Color(0xFF7C8799)
                            )
                        },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Rounded.Email,
                                contentDescription = null,
                                tint = Color(0xFF00C6FF)
                            )
                        },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Email
                        ),
                        shape = RoundedCornerShape(18.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF00C6FF),
                            unfocusedBorderColor = Color(0xFF2C3A4D),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = Color(0xFF00C6FF)
                        )
                    )

                    Spacer(modifier = Modifier.height(22.dp))

                    Text(
                        text = "Password",
                        color = Color.White,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = password,
                        onValueChange = {
                            password = it
                        },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = {
                            Text(
                                text = "Enter your password",
                                color = Color(0xFF7C8799)
                            )
                        },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Rounded.Lock,
                                contentDescription = null,
                                tint = Color(0xFF00C6FF)
                            )
                        },
                        trailingIcon = {

                            IconButton(
                                onClick = {
                                    passwordVisible = !passwordVisible
                                }
                            ) {

                                Icon(
                                    imageVector =
                                    if (passwordVisible) {
                                        Icons.Rounded.VisibilityOff
                                    } else {
                                        Icons.Rounded.Visibility
                                    },
                                    contentDescription = null,
                                    tint = Color(0xFF9CA3AF)
                                )
                            }
                        },
                        singleLine = true,
                        visualTransformation =
                        if (passwordVisible) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password
                        ),
                        shape = RoundedCornerShape(18.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF00C6FF),
                            unfocusedBorderColor = Color(0xFF2C3A4D),
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White,
                            cursorColor = Color(0xFF00C6FF)
                        )
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    TextButton(
                        onClick = onForgotPasswordClick,
                        modifier = Modifier.align(Alignment.End)
                    ) {

                        Text(
                            text = "Forgot Password?",
                            color = Color(0xFF00C6FF),
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Button(
                        onClick = onLoginClick,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(58.dp),
                        shape = RoundedCornerShape(18.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF00C6FF),
                            contentColor = Color.White
                        )
                    ) {

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Icon(
                                imageVector = Icons.Rounded.Login,
                                contentDescription = null,
                                modifier = Modifier.size(22.dp)
                            )

                            Spacer(modifier = Modifier.size(10.dp))

                            Text(
                                text = "Login",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Text(
                    text = "Don't have an account?",
                    color = Color(0xFFB0BAC8),
                    fontSize = 14.sp
                )

                Spacer(modifier = Modifier.size(6.dp))

                Text(
                    text = "Sign Up",
                    color = Color(0xFF00C6FF),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.clickable {
                        onSignupClick()
                    }
                )
            }

            Spacer(modifier = Modifier.height(28.dp))
        }
    }
}
