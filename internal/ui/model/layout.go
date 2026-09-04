package model

import (
	"image"

	"github.com/charmbracelet/ultraviolet/layout"
)

func splitVertical(area image.Rectangle, height int) (top, bottom image.Rectangle) {
	layout.Vertical(layout.Len(height), layout.Fill(1)).Split(area).Assign(&top, &bottom)
	return top, bottom
}

func splitHorizontal(area image.Rectangle, width int) (left, right image.Rectangle) {
	layout.Horizontal(layout.Len(width), layout.Fill(1)).Split(area).Assign(&left, &right)
	return left, right
}
