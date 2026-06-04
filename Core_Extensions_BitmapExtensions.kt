package com.sentrix.core.extensions

import android.graphics.*
import java.io.ByteArrayOutputStream
import kotlin.math.min

/**
 * Bitmap Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * Conversion Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.toByteArray(
    format: Bitmap.CompressFormat = Bitmap.CompressFormat.PNG,
    quality: Int = 100
): ByteArray {

    val outputStream = ByteArrayOutputStream()

    compress(
        format,
        quality.coerceIn(0, 100),
        outputStream
    )

    return outputStream.toByteArray()
}

fun ByteArray.toBitmap(): Bitmap? {
    return BitmapFactory.decodeByteArray(
        this,
        0,
        size
    )
}

/* -------------------------------------------------------------------------
 * Resize Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.resize(
    width: Int,
    height: Int
): Bitmap {
    return Bitmap.createScaledBitmap(
        this,
        width,
        height,
        true
    )
}

fun Bitmap.resizeByPercentage(
    percentage: Float
): Bitmap {

    val factor = percentage.coerceAtLeast(0.01f)

    return resize(
        (width * factor).toInt(),
        (height * factor).toInt()
    )
}

/* -------------------------------------------------------------------------
 * Crop Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.centerCrop(
    targetSize: Int
): Bitmap {

    val size = min(width, height)

    val x = (width - size) / 2
    val y = (height - size) / 2

    return Bitmap.createBitmap(
        this,
        x,
        y,
        size,
        size
    ).resize(targetSize, targetSize)
}

/* -------------------------------------------------------------------------
 * Rotation Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.rotate(
    degrees: Float
): Bitmap {

    val matrix = Matrix().apply {
        postRotate(degrees)
    }

    return Bitmap.createBitmap(
        this,
        0,
        0,
        width,
        height,
        matrix,
        true
    )
}

/* -------------------------------------------------------------------------
 * Flip Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.flipHorizontal(): Bitmap {

    val matrix = Matrix().apply {
        preScale(-1f, 1f)
    }

    return Bitmap.createBitmap(
        this,
        0,
        0,
        width,
        height,
        matrix,
        true
    )
}

fun Bitmap.flipVertical(): Bitmap {

    val matrix = Matrix().apply {
        preScale(1f, -1f)
    }

    return Bitmap.createBitmap(
        this,
        0,
        0,
        width,
        height,
        matrix,
        true
    )
}

/* -------------------------------------------------------------------------
 * Compression Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.compressBitmap(
    quality: Int = 80
): ByteArray {

    val outputStream = ByteArrayOutputStream()

    compress(
        Bitmap.CompressFormat.JPEG,
        quality.coerceIn(0, 100),
        outputStream
    )

    return outputStream.toByteArray()
}

/* -------------------------------------------------------------------------
 * Color Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.toGrayscale(): Bitmap {

    val bitmap = Bitmap.createBitmap(
        width,
        height,
        Bitmap.Config.ARGB_8888
    )

    val canvas = Canvas(bitmap)

    val paint = Paint()

    val matrix = ColorMatrix().apply {
        setSaturation(0f)
    }

    paint.colorFilter =
        ColorMatrixColorFilter(matrix)

    canvas.drawBitmap(
        this,
        0f,
        0f,
        paint
    )

    return bitmap
}

fun Bitmap.invertColors(): Bitmap {

    val bitmap = copy(
        Bitmap.Config.ARGB_8888,
        true
    )

    for (x in 0 until bitmap.width) {
        for (y in 0 until bitmap.height) {

            val pixel = bitmap.getPixel(x, y)

            val alpha = Color.alpha(pixel)
            val red = 255 - Color.red(pixel)
            val green = 255 - Color.green(pixel)
            val blue = 255 - Color.blue(pixel)

            bitmap.setPixel(
                x,
                y,
                Color.argb(
                    alpha,
                    red,
                    green,
                    blue
                )
            )
        }
    }

    return bitmap
}

/* -------------------------------------------------------------------------
 * Blur Helper (Simple)
 * ------------------------------------------------------------------------- */

fun Bitmap.blurSample(
    scaleFactor: Float = 0.25f
): Bitmap {

    val scaledBitmap = resize(
        (width * scaleFactor).toInt(),
        (height * scaleFactor).toInt()
    )

    return scaledBitmap.resize(
        width,
        height
    )
}

/* -------------------------------------------------------------------------
 * Bitmap Information
 * ------------------------------------------------------------------------- */

fun Bitmap.byteSize(): Int {
    return byteCount
}

fun Bitmap.sizeInKB(): Float {
    return byteCount / 1024f
}

fun Bitmap.sizeInMB(): Float {
    return byteCount / (1024f * 1024f)
}

fun Bitmap.aspectRatio(): Float {
    return width.toFloat() / height.toFloat()
}

/* -------------------------------------------------------------------------
 * Security / File Analysis Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.calculateSHA256(): String {

    val bytes = toByteArray()

    val digest = java.security.MessageDigest
        .getInstance("SHA-256")
        .digest(bytes)

    return digest.joinToString("") {
        "%02x".format(it)
    }
}

fun Bitmap.isLargeBitmap(
    maxWidth: Int = 4096,
    maxHeight: Int = 4096
): Boolean {

    return width > maxWidth ||
            height > maxHeight
}

fun Bitmap.estimatedMemoryUsageMB(): Float {

    return byteCount.toFloat() /
            (1024f * 1024f)
}

/* -------------------------------------------------------------------------
 * Watermark Helpers
 * ------------------------------------------------------------------------- */

fun Bitmap.addTextWatermark(
    text: String
): Bitmap {

    val mutableBitmap = copy(
        Bitmap.Config.ARGB_8888,
        true
    )

    val canvas = Canvas(mutableBitmap)

    val paint = Paint().apply {
        textSize = 40f
        isAntiAlias = true
        alpha = 150
    }

    canvas.drawText(
        text,
        20f,
        height - 40f,
        paint
    )

    return mutableBitmap
}

/* -------------------------------------------------------------------------
 * Circular Crop
 * ------------------------------------------------------------------------- */

fun Bitmap.toCircularBitmap(): Bitmap {

    val size = min(width, height)

    val output = Bitmap.createBitmap(
        size,
        size,
        Bitmap.Config.ARGB_8888
    )

    val canvas = Canvas(output)

    val paint = Paint().apply {
        isAntiAlias = true
    }

    val rect = Rect(0, 0, size, size)

    canvas.drawARGB(0, 0, 0, 0)

    canvas.drawCircle(
        size / 2f,
        size / 2f,
        size / 2f,
        paint
    )

    paint.xfermode =
        PorterDuffXfermode(PorterDuff.Mode.SRC_IN)

    canvas.drawBitmap(
        centerCrop(size),
        rect,
        rect,
        paint
    )

    return output
}
