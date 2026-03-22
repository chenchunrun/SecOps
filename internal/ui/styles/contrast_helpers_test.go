package styles

import (
	"image/color"
	"math"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/stretchr/testify/require"
)

const minReadableContrast = 4.5

func forEachTheme(t *testing.T, fn func(t *testing.T, theme Theme, s Styles, terminalBackground color.Color)) {
	t.Helper()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		name := "light"
		if theme == ThemeDark {
			name = "dark"
		}
		t.Run(name, func(t *testing.T) {
			s := DefaultStyles(theme)
			fn(t, theme, s, terminalBackgroundForTheme(theme))
		})
	}
}

func assertContrastAtLeast(t *testing.T, fg, bg color.Color, min float64) {
	t.Helper()
	require.GreaterOrEqual(t, contrastRatio(fg, bg), min)
}

func assertContrastAtLeastNamed(t *testing.T, name string, fg, bg color.Color, min float64) {
	t.Helper()
	ratio := contrastRatio(fg, bg)
	require.GreaterOrEqualf(t, ratio, min, "contrast check failed: %s (ratio=%.4f, min=%.2f)", name, ratio, min)
}

func terminalBackgroundForTheme(theme Theme) color.Color {
	if theme == ThemeLight {
		return lipgloss.Color("#FFFFFF")
	}
	return lipgloss.Color("#000000")
}

func contrastRatio(fg, bg color.Color) float64 {
	fgL := luminance(fg)
	bgL := luminance(bg)
	if fgL < bgL {
		fgL, bgL = bgL, fgL
	}
	return (fgL + 0.05) / (bgL + 0.05)
}

func luminance(c color.Color) float64 {
	r, g, b, _ := c.RGBA()
	return 0.2126*linearComponent(r) + 0.7152*linearComponent(g) + 0.0722*linearComponent(b)
}

func linearComponent(v uint32) float64 {
	f := float64(v) / 65535.0
	if f <= 0.03928 {
		return f / 12.92
	}
	return math.Pow((f+0.055)/1.055, 2.4)
}
