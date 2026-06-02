package com.sentrix.core.extensions

import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController

/**
 * ------------------------------------------------------------
 * SentriX - FragmentExtensions
 * Package: com.sentrix.core.extensions
 * ------------------------------------------------------------
 */

fun Fragment.showShortToast(message: String) {
    context?.let {
        Toast.makeText(it, message, Toast.LENGTH_SHORT).show()
    }
}

fun Fragment.showLongToast(message: String) {
    context?.let {
        Toast.makeText(it, message, Toast.LENGTH_LONG).show()
    }
}

fun Fragment.navigateTo(destinationId: Int) {
    findNavController().navigate(destinationId)
}

fun Fragment.navigateBack() {
    findNavController().popBackStack()
}

fun Fragment.safeNavigate(
    destinationId: Int
) {
    val navController = findNavController()
    val currentDestination = navController.currentDestination

    currentDestination?.getAction(destinationId)?.let {
        navController.navigate(destinationId)
    }
}

fun Fragment.requireSafeContext() = requireContext()

fun Fragment.requireSafeActivity() = requireActivity()

fun Fragment.isFragmentAlive(): Boolean {
    return isAdded &&
            activity != null &&
            view != null
}

fun Fragment.runIfAlive(action: () -> Unit) {
    if (isFragmentAlive()) {
        action.invoke()
    }
}

fun Fragment.hideKeyboard() {
    view?.let { currentView ->
        val imm = requireContext().getSystemService(
            android.content.Context.INPUT_METHOD_SERVICE
        ) as android.view.inputmethod.InputMethodManager

        imm.hideSoftInputFromWindow(
            currentView.windowToken,
            0
        )
    }
}

fun Fragment.showKeyboard() {
    view?.requestFocus()

    val imm = requireContext().getSystemService(
        android.content.Context.INPUT_METHOD_SERVICE
    ) as android.view.inputmethod.InputMethodManager

    imm.toggleSoftInput(
        android.view.inputmethod.InputMethodManager.SHOW_FORCED,
        0
    )
}

fun Fragment.showErrorToast(
    message: String = "Something went wrong"
) {
    showShortToast(message)
}

fun Fragment.showSuccessToast(
    message: String = "Operation successful"
) {
    showShortToast(message)
}
