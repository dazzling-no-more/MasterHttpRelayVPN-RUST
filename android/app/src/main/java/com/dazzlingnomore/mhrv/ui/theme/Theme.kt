package com.dazzlingnomore.mhrv.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/*
 * Android-specific dark theme.
 *
 * History: until v2.3 these constants were kept in lockstep with the
 * desktop egui binary's hand-rolled palette so a user moving between
 * Android + desktop saw the same brand. The desktop UI moved to Tauri
 * in v2.4 (see `desktop/src/app.css`), which uses a different palette
 * driven by Tailwind design tokens — there is no longer a desktop
 * source to mirror.
 *
 * Why not just adopt the Tauri palette: the legacy values below are
 * tested visually across the Android tablet + small-phone form
 * factors, and changing them risks contrast / readability regressions
 * on devices we can't easily re-test. We can revisit if the brand
 * drift between platforms becomes a real complaint.
 *
 * Deliberate choices:
 *   - ALWAYS dark. Neither light mode nor Android 12+ dynamic color
 *     is respected — consistent appearance across the user base
 *     trumps blending with the wallpaper here.
 *   - Card corners 6.dp, button corners 4.dp — kept for visual
 *     continuity with previous releases.
 */

// ACCENT / ACCENT_HOVER — clickable accents.
val AccentBlue = Color(0xFF4678B4)
val AccentHover = Color(0xFF5A91CD)

// Status indicators.
val OkGreen = Color(0xFF50B464)
val ErrRed = Color(0xFFDC6E6E)

// Card fill and stroke used by section containers.
val CardFill = Color(0xFF1C1E22)
val CardStroke = Color(0xFF32363C)

// Backdrop slightly darker than cards so containers pop off the page.
val BgDark = Color(0xFF111317)

// Text shades.
val TextPrimary = Color(0xFFC8C8C8)
val TextSecondary = Color(0xFF8C8C8C)
val TextLabel = Color(0xFFB4B4B4)

private val RahgozarDark =
    darkColorScheme(
        primary = AccentBlue,
        onPrimary = Color.White,
        primaryContainer = AccentHover,
        onPrimaryContainer = Color.White,
        secondary = OkGreen,
        onSecondary = Color.Black,
        tertiary = OkGreen,
        onTertiary = Color.Black,
        error = ErrRed,
        onError = Color.White,
        background = BgDark,
        onBackground = TextPrimary,
        surface = CardFill,
        onSurface = TextPrimary,
        surfaceVariant = CardFill,
        onSurfaceVariant = TextSecondary,
        outline = CardStroke,
        outlineVariant = CardStroke,
    )

/**
 * Material3 consumes Shapes through component defaults (Button uses
 * `shapes.full`, Card uses `shapes.medium`, etc.). Mapping every size to
 * tight rounded-rectangles keeps the whole app visually consistent with
 * the desktop's squared-off controls instead of Material's default pills.
 */
private val RahgozarShapes =
    Shapes(
        extraSmall = RoundedCornerShape(4.dp),
        small = RoundedCornerShape(4.dp),
        medium = RoundedCornerShape(6.dp),
        large = RoundedCornerShape(6.dp),
        extraLarge = RoundedCornerShape(8.dp),
    )

@Composable
fun RahgozarTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = RahgozarDark,
        shapes = RahgozarShapes,
        content = content,
    )
}
