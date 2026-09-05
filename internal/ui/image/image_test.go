package image

import (
	"image"
	"image/color"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResizeToFit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		bounds        image.Rectangle
		width, height int
		want          image.Point
	}{
		{"landscape", image.Rect(0, 0, 100, 50), 20, 20, image.Pt(20, 10)},
		{"portrait", image.Rect(0, 0, 50, 100), 20, 20, image.Pt(10, 20)},
		{"no enlargement", image.Rect(0, 0, 2, 3), 20, 20, image.Pt(2, 3)},
		{"offset", image.Rect(10, 20, 110, 70), 20, 20, image.Pt(20, 10)},
		{"zero target", image.Rect(0, 0, 10, 10), 0, 20, image.Point{}},
		{"empty", image.Rectangle{}, 20, 20, image.Point{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resizeToFit(image.NewNRGBA(tc.bounds), tc.width, tc.height)
			require.Equal(t, tc.want, got.Bounds().Size())
		})
	}
}

func TestResizePalettedImage(t *testing.T) {
	t.Parallel()
	src := image.NewPaletted(image.Rect(0, 0, 20, 20), color.Palette{color.NRGBA{R: 255, A: 255}})
	var resized image.Image
	require.NotPanics(t, func() { resized = resizeToFit(src, 4, 4) })
	require.Equal(t, image.Pt(4, 4), resized.Bounds().Size())
	require.Equal(t, color.NRGBA{R: 255, A: 255}, color.NRGBAModel.Convert(resized.At(2, 2)))
}

func TestResetCache(t *testing.T) {
	t.Parallel()

	cachedMutex.Lock()
	cachedImages[imageKey{id: "a", cols: 10, rows: 10}] = cachedImage{
		img:  image.NewRGBA(image.Rect(0, 0, 1, 1)),
		cols: 10,
		rows: 10,
	}
	cachedImages[imageKey{id: "b", cols: 20, rows: 20}] = cachedImage{
		img:  image.NewRGBA(image.Rect(0, 0, 1, 1)),
		cols: 20,
		rows: 20,
	}
	cachedMutex.Unlock()

	ResetCache()

	cachedMutex.RLock()
	length := len(cachedImages)
	cachedMutex.RUnlock()

	require.Equal(t, 0, length)
}

func TestResetIdempotent(t *testing.T) {
	t.Parallel()

	// Calling Reset on an empty cache should not panic.
	ResetCache()

	cachedMutex.RLock()
	length := len(cachedImages)
	cachedMutex.RUnlock()

	require.Equal(t, 0, length)
}
