package model

import (
	"image"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitVertical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		height int
		top    image.Rectangle
		bottom image.Rectangle
	}{
		{name: "fixed height", height: 15, top: image.Rect(10, 20, 110, 35), bottom: image.Rect(10, 35, 110, 70)},
		{name: "negative height", height: -1, top: image.Rect(10, 20, 110, 20), bottom: image.Rect(10, 20, 110, 70)},
		{name: "oversized height", height: 80, top: image.Rect(10, 20, 110, 70), bottom: image.Rect(10, 70, 110, 70)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			top, bottom := splitVertical(image.Rect(10, 20, 110, 70), test.height)
			require.Equal(t, test.top, top)
			require.Equal(t, test.bottom, bottom)
		})
	}
}

func TestSplitHorizontal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		width int
		left  image.Rectangle
		right image.Rectangle
	}{
		{name: "fixed width", width: 30, left: image.Rect(10, 20, 40, 70), right: image.Rect(40, 20, 110, 70)},
		{name: "negative width", width: -1, left: image.Rect(10, 20, 10, 70), right: image.Rect(10, 20, 110, 70)},
		{name: "oversized width", width: 120, left: image.Rect(10, 20, 110, 70), right: image.Rect(110, 20, 110, 70)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			left, right := splitHorizontal(image.Rect(10, 20, 110, 70), test.width)
			require.Equal(t, test.left, left)
			require.Equal(t, test.right, right)
		})
	}
}
