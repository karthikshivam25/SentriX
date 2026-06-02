package com.sentrix.core.extensions

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.core.content.ContextCompat

/**
 * ------------------------------------------------------------
 * SentriX - ActivityExtensions
 * Package: com.sentrix.core.extensions
 * ------------------------------------------------------------
 */

fun Activity.showShortToast(message: String) {
    Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}

fun Activity.showLongToast(message: String) {
    Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}

fun Activity.makeStatusBarTransparent() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        window.setDecorFitsSystemWindows(false)

        window.insetsController?.apply {
            hide(WindowInsets.Type.statusBars())
            systemBarsBehavior =
                WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        }
    } else {
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                    View.SYSTEM_UI_FLAG_LAYOUT_STABLE
    }
}

fun Activity.setStatusBarColor(colorRes: Int) {
    window.statusBarColor = ContextCompat.getColor(this, colorRes)
}

fun Activity.setNavigationBarColor(colorRes: Int) {
    window.navigationBarColor = ContextCompat.getColor(this, colorRes)
}

fun Activity.enableFullScreenMode() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        window.insetsController?.hide(WindowInsets.Type.systemBars())
    } else {
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_FULLSCREEN or
                    View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
                    View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
    }
}

fun Activity.disableFullScreenMode() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        window.insetsController?.show(WindowInsets.Type.systemBars())
    } else {
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_VISIBLE
    }
}

fun Activity.restartActivity() {
    val intent = intent
    finish()
    startActivity(intent)
}

fun Activity.launchActivity(
    targetActivity: Class<*>,
    finishCurrent: Boolean = false
) {
    val intent = Intent(this, targetActivity)
    startActivity(intent)

    if (finishCurrent) {
        finish()
    }
}

fun Activity.handleBackPress(
    onBackPressedAction: () -> Unit
) {
    onBackPressedDispatcher.addCallback(
        this,
        object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                onBackPressedAction()
            }
        }
    )
}

fun Activity.hideSystemUI() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        window.insetsController?.hide(
            WindowInsets.Type.statusBars() or
                    WindowInsets.Type.navigationBars()
        )
    } else {
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or
                    View.SYSTEM_UI_FLAG_FULLSCREEN or
                    View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
    }
}

fun Activity.showSystemUI() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        window.insetsController?.show(
            WindowInsets.Type.statusBars() or
                    WindowInsets.Type.navigationBars()
        )
    } else {
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_VISIBLE
    }
}
