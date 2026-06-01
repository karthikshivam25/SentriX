package com.sentrix.ui.navigation

import androidx.compose.animation.*
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.navigation.NavBackStackEntry

private const val ANIMATION_DURATION = 450

@OptIn(ExperimentalAnimationApi::class)
object NavigationAnimations {

    // --------------------------------------------------
    // ENTER TRANSITIONS
    // --------------------------------------------------

    val slideInRight: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
        {
            slideIntoContainer(
                towards = AnimatedContentTransitionScope.SlideDirection.Left,
                animationSpec = tween(
                    durationMillis = ANIMATION_DURATION,
                    easing = FastOutSlowInEasing
                )
            ) + fadeIn(
                animationSpec = tween(300)
            )
        }

    val slideInLeft: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
        {
            slideIntoContainer(
                towards = AnimatedContentTransitionScope.SlideDirection.Right,
                animationSpec = tween(
                    durationMillis = ANIMATION_DURATION,
                    easing = FastOutSlowInEasing
                )
            ) + fadeIn(
                animationSpec = tween(300)
            )
        }

    val fadeInTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
        {
            fadeIn(
                animationSpec = tween(
                    durationMillis = 350
                )
            )
        }

    val scaleInTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
        {
            scaleIn(
                initialScale = 0.92f,
                animationSpec = tween(
                    durationMillis = ANIMATION_DURATION,
                    easing = FastOutSlowInEasing
                )
            ) + fadeIn(
                animationSpec = tween(300)
            )
        }

    // --------------------------------------------------
    // EXIT TRANSITIONS
    // --------------------------------------------------

    val slideOutLeft: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition =
        {
            slideOutOfContainer(
                towards = AnimatedContentTransitionScope.SlideDirection.Left,
                animationSpec = tween(
                    durationMillis = ANIMATION_DURATION,
                    easing = FastOutSlowInEasing
                )
            ) + fadeOut(
                animationSpec = tween(250)
            )
        }

    val slideOutRight: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition =
        {
            slideOutOfContainer(
                towards = AnimatedContentTransitionScope.SlideDirection.Right,
                animationSpec = tween(
                    durationMillis = ANIMATION_DURATION,
                    easing = FastOutSlowInEasing
                )
            ) + fadeOut(
                animationSpec = tween(250)
            )
        }

    val fadeOutTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition =
        {
            fadeOut(
                animationSpec = tween(
                    durationMillis = 250
                )
            )
        }

    val scaleOutTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition =
        {
            scaleOut(
                targetScale = 1.08f,
                animationSpec = tween(
                    durationMillis = ANIMATION_DURATION,
                    easing = FastOutSlowInEasing
                )
            ) + fadeOut(
                animationSpec = tween(250)
            )
        }

    // --------------------------------------------------
    // SPECIAL ANIMATIONS
    // --------------------------------------------------

    val splashTransition:
            AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
        {
            fadeIn(
                animationSpec = tween(1200)
            ) + scaleIn(
                initialScale = 0.8f,
                animationSpec = tween(
                    durationMillis = 1200,
                    easing = FastOutSlowInEasing
                )
            )
        }

    val modalTransition:
            AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition =
        {
            slideInVertically(
                initialOffsetY = { it },
                animationSpec = tween(
                    durationMillis = 400,
                    easing = FastOutSlowInEasing
                )
            ) + fadeIn()
        }

    val modalExitTransition:
            AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition =
        {
            slideOutVertically(
                targetOffsetY = { it },
                animationSpec = tween(
                    durationMillis = 350,
                    easing = FastOutSlowInEasing
                )
            ) + fadeOut()
        }
}
