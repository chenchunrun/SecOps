package styles

import (
	"image/color"
	"testing"

	"github.com/charmbracelet/x/exp/charmtone"
	"github.com/stretchr/testify/require"
)

func TestDefaultStylesButtons(t *testing.T) {
	t.Parallel()

	s := DefaultStyles()

	require.Equal(t, charmtone.Guac, s.ButtonFocus.GetBackground())
	require.Equal(t, charmtone.Pepper, s.ButtonFocus.GetForeground())
	require.Equal(t, s.White, s.ButtonBlur.GetForeground())
	require.Equal(t, s.BgSubtle, s.ButtonBlur.GetBackground())
	require.Equal(t, s.Border, s.ButtonBlur.GetBorderTopForeground())
	require.Equal(t, 1, s.ButtonBlur.GetBorderTopSize())
	require.Equal(t, 1, s.ButtonBlur.GetBorderRightSize())
	require.Equal(t, 1, s.ButtonBlur.GetBorderBottomSize())
	require.Equal(t, 1, s.ButtonBlur.GetBorderLeftSize())
}

func TestDefaultStylesDialogContentPanelThemeSelection(t *testing.T) {
	t.Parallel()

	defaultTheme := DefaultStyles()
	darkTheme := DefaultStyles(ThemeDark)
	lightTheme := DefaultStyles(ThemeLight)

	require.Equal(t, charmtone.BBQ, defaultTheme.Dialog.ContentPanel.GetBackground())
	require.Equal(t, defaultTheme.Dialog.ContentPanel.GetBackground(), darkTheme.Dialog.ContentPanel.GetBackground())
	require.Equal(t, charmtone.Salt, lightTheme.Dialog.ContentPanel.GetBackground())
}

func TestDefaultStylesDialogHelpContrast(t *testing.T) {
	t.Parallel()

	s := DefaultStyles()

	require.Equal(t, s.FgBase, s.Dialog.Help.ShortKey.GetForeground())
	require.Equal(t, s.FgMuted, s.Dialog.Help.ShortDesc.GetForeground())
	require.Equal(t, s.FgBase, s.Dialog.Help.FullKey.GetForeground())
	require.Equal(t, s.FgMuted, s.Dialog.Help.FullDesc.GetForeground())
}

func TestDefaultStylesHelpHierarchy(t *testing.T) {
	t.Parallel()

	s := DefaultStyles()

	require.Equal(t, s.FgBase, s.Help.ShortKey.GetForeground())
	require.Equal(t, s.FgMuted, s.Help.ShortDesc.GetForeground())
	require.Equal(t, s.FgBase, s.Help.FullKey.GetForeground())
	require.Equal(t, s.FgMuted, s.Help.FullDesc.GetForeground())
	require.Equal(t, s.Help.ShortKey.GetForeground(), s.Dialog.Help.ShortKey.GetForeground())
	require.Equal(t, s.Help.ShortDesc.GetForeground(), s.Dialog.Help.ShortDesc.GetForeground())
}

func TestDefaultStylesInteractiveContrast(t *testing.T) {
	t.Parallel()

	forEachTheme(t, func(t *testing.T, _ Theme, s Styles, _ color.Color) {
		assertContrastAtLeast(t, s.ButtonFocus.GetForeground(), s.ButtonFocus.GetBackground(), minReadableContrast)
		assertContrastAtLeast(t, s.FilePicker.Selected.GetForeground(), s.FilePicker.Selected.GetBackground(), minReadableContrast)
		assertContrastAtLeast(t, s.Dialog.SelectedItem.GetForeground(), s.Dialog.SelectedItem.GetBackground(), minReadableContrast)
		assertContrastAtLeast(t, s.Attachments.Deleting.GetForeground(), s.Attachments.Deleting.GetBackground(), minReadableContrast)
	})
}

func TestDefaultStylesStatusAndTagsContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		s := DefaultStyles(theme)

		require.GreaterOrEqual(t,
			contrastRatio(s.Status.SuccessIndicator.GetForeground(), s.Status.SuccessIndicator.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Status.WarnIndicator.GetForeground(), s.Status.WarnIndicator.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Status.ErrorIndicator.GetForeground(), s.Status.ErrorIndicator.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Status.SuccessMessage.GetForeground(), s.Status.SuccessMessage.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Status.WarnMessage.GetForeground(), s.Status.WarnMessage.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Status.ErrorMessage.GetForeground(), s.Status.ErrorMessage.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Tool.ErrorTag.GetForeground(), s.Tool.ErrorTag.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Tool.AgentTaskTag.GetForeground(), s.Tool.AgentTaskTag.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Tool.AgenticFetchPromptTag.GetForeground(), s.Tool.AgenticFetchPromptTag.GetBackground()),
			4.5,
		)
	}
}

func TestDefaultStylesBadgeContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		s := DefaultStyles(theme)

		require.GreaterOrEqual(t,
			contrastRatio(s.TagError.GetForeground(), s.TagError.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.TagInfo.GetForeground(), s.TagInfo.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Tool.NoteTag.GetForeground(), s.Tool.NoteTag.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Tool.AgenticFetchPromptTag.GetForeground(), s.Tool.AgenticFetchPromptTag.GetBackground()),
			4.5,
		)
		require.GreaterOrEqual(t,
			contrastRatio(s.Attachments.Image.GetForeground(), s.Attachments.Image.GetBackground()),
			4.5,
		)
	}
}

func TestDefaultStylesSecondaryTextContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		s := DefaultStyles(theme)
		bg := terminalBackgroundForTheme(theme)

		require.GreaterOrEqual(t, contrastRatio(s.Tool.StateWaiting.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Tool.StateCancelled.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Tool.ErrorMessage.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Tool.JobDescription.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Header.KeystrokeTip.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Pills.HelpText.GetForeground(), bg), 4.5)
	}
}

func TestDefaultStylesChatContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		s := DefaultStyles(theme)
		bg := terminalBackgroundForTheme(theme)

		require.GreaterOrEqual(t, contrastRatio(s.Chat.Message.ErrorTag.GetForeground(), s.Chat.Message.ErrorTag.GetBackground()), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Chat.Message.ThinkingBox.GetForeground(), s.Chat.Message.ThinkingBox.GetBackground()), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Chat.Message.ErrorDetails.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Chat.Message.AssistantInfoProvider.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Chat.Message.AssistantInfoDuration.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Chat.Message.ThinkingFooterDuration.GetForeground(), bg), 4.5)
	}
}

func TestDefaultStylesChatFocusHierarchy(t *testing.T) {
	t.Parallel()

	s := DefaultStyles()

	require.Equal(t, 1, s.Chat.Message.UserFocused.GetBorderLeftSize())
	require.Equal(t, 1, s.Chat.Message.UserBlurred.GetBorderLeftSize())
	require.Equal(t, "▌", s.Chat.Message.UserFocused.GetBorderStyle().Left)
	require.Equal(t, "│", s.Chat.Message.UserBlurred.GetBorderStyle().Left)

	require.Equal(t, 1, s.Chat.Message.AssistantFocused.GetBorderLeftSize())
	require.Equal(t, 0, s.Chat.Message.AssistantBlurred.GetBorderLeftSize())
	require.Greater(t, s.Chat.Message.AssistantBlurred.GetPaddingLeft(), s.Chat.Message.AssistantFocused.GetPaddingLeft())

	require.Equal(t, 1, s.Chat.Message.ToolCallFocused.GetBorderLeftSize())
	require.Equal(t, 0, s.Chat.Message.ToolCallBlurred.GetBorderLeftSize())
	require.Greater(t, s.Chat.Message.ToolCallBlurred.GetPaddingLeft(), s.Chat.Message.ToolCallFocused.GetPaddingLeft())
}

func TestDefaultStylesDiffThemeSelection(t *testing.T) {
	t.Parallel()

	dark := DefaultStyles(ThemeDark)
	light := DefaultStyles(ThemeLight)

	require.NotEqual(
		t,
		dark.Diff.InsertLine.Code.GetBackground(),
		light.Diff.InsertLine.Code.GetBackground(),
	)
	require.NotEqual(
		t,
		dark.Diff.DeleteLine.Code.GetBackground(),
		light.Diff.DeleteLine.Code.GetBackground(),
	)
	require.NotEqual(
		t,
		dark.Diff.InsertLine.Code.GetForeground(),
		light.Diff.InsertLine.Code.GetForeground(),
	)
	require.NotEqual(
		t,
		dark.Diff.DeleteLine.Code.GetForeground(),
		light.Diff.DeleteLine.Code.GetForeground(),
	)
}

func TestDefaultStylesFilePickerAndDialogContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		name := "light"
		if theme == ThemeDark {
			name = "dark"
		}
		t.Run(name, func(t *testing.T) {
			s := DefaultStyles(theme)

			require.GreaterOrEqual(t,
				contrastRatio(s.FilePicker.DisabledSelected.GetForeground(), s.FilePicker.DisabledSelected.GetBackground()),
				4.5,
			)
			require.GreaterOrEqual(t,
				contrastRatio(s.Dialog.SecondaryText.GetForeground(), s.Dialog.View.GetBackground()),
				4.5,
			)
			require.GreaterOrEqual(t,
				contrastRatio(s.Dialog.ContentPanel.GetForeground(), s.Dialog.ContentPanel.GetBackground()),
				4.5,
			)
		})
	}
}

func TestDefaultStylesHelpContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		s := DefaultStyles(theme)
		bg := terminalBackgroundForTheme(theme)

		shortKey := contrastRatio(s.Help.ShortKey.GetForeground(), bg)
		shortDesc := contrastRatio(s.Help.ShortDesc.GetForeground(), bg)
		fullKey := contrastRatio(s.Help.FullKey.GetForeground(), bg)
		fullDesc := contrastRatio(s.Help.FullDesc.GetForeground(), bg)

		require.GreaterOrEqual(t, shortKey, 4.5)
		require.GreaterOrEqual(t, shortDesc, 4.5)
		require.GreaterOrEqual(t, fullKey, 4.5)
		require.GreaterOrEqual(t, fullDesc, 4.5)
		require.Greater(t, shortKey, shortDesc)
		require.Greater(t, fullKey, fullDesc)
	}
}

func TestDefaultStylesResourceStatusContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		s := DefaultStyles(theme)
		bg := terminalBackgroundForTheme(theme)

		groupRatio := contrastRatio(s.ResourceGroupTitle.GetForeground(), bg)
		nameRatio := contrastRatio(s.ResourceName.GetForeground(), bg)
		statusRatio := contrastRatio(s.ResourceStatus.GetForeground(), bg)
		additionalRatio := contrastRatio(s.ResourceAdditionalText.GetForeground(), bg)

		require.GreaterOrEqual(t, groupRatio, 4.5)
		require.GreaterOrEqual(t, nameRatio, 4.5)
		require.GreaterOrEqual(t, statusRatio, 4.5)
		require.GreaterOrEqual(t, additionalRatio, 4.5)
		require.GreaterOrEqual(t, groupRatio, statusRatio)
		require.GreaterOrEqual(t, nameRatio, statusRatio)
		require.Equal(t, s.ResourceStatus.GetForeground(), s.ResourceAdditionalText.GetForeground())
	}
}

func TestDefaultStylesHeaderPillsHierarchy(t *testing.T) {
	t.Parallel()

	s := DefaultStyles()

	require.Equal(t, s.FgMuted, s.Header.Keystroke.GetForeground())
	require.Equal(t, s.FgMuted, s.Header.KeystrokeTip.GetForeground())
	require.Equal(t, s.FgMuted, s.Header.WorkingDir.GetForeground())
	require.Equal(t, s.FgMuted, s.Header.Separator.GetForeground())
	require.Equal(t, s.FgBase, s.Pills.HelpKey.GetForeground())
	require.Equal(t, s.FgMuted, s.Pills.HelpText.GetForeground())
}

func TestDefaultStylesHeaderAndEditorPromptContrast(t *testing.T) {
	t.Parallel()

	themes := []Theme{ThemeDark, ThemeLight}
	for _, theme := range themes {
		s := DefaultStyles(theme)
		bg := terminalBackgroundForTheme(theme)

		require.GreaterOrEqual(t, contrastRatio(s.Header.Keystroke.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Header.KeystrokeTip.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Header.WorkingDir.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.Header.Separator.GetForeground(), bg), 4.5)

		require.GreaterOrEqual(t, contrastRatio(s.EditorPromptNormalFocused.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(t, contrastRatio(s.EditorPromptNormalBlurred.GetForeground(), bg), 4.5)
		require.GreaterOrEqual(
			t,
			contrastRatio(
				s.EditorPromptYoloIconFocused.GetForeground(),
				s.EditorPromptYoloIconFocused.GetBackground(),
			),
			4.5,
		)
		require.GreaterOrEqual(t, contrastRatio(s.EditorPromptYoloDotsBlurred.GetForeground(), bg), 4.5)
	}
}

func TestDefaultStylesLSPDiagnosticsContrast(t *testing.T) {
	t.Parallel()

	forEachTheme(t, func(t *testing.T, _ Theme, s Styles, bg color.Color) {
		assertContrastAtLeastNamed(t, "lsp_error", s.LSP.ErrorDiagnostic.GetForeground(), bg, minReadableContrast)
		assertContrastAtLeastNamed(t, "lsp_warning", s.LSP.WarningDiagnostic.GetForeground(), bg, minReadableContrast)
		assertContrastAtLeastNamed(t, "lsp_hint", s.LSP.HintDiagnostic.GetForeground(), bg, minReadableContrast)
		assertContrastAtLeastNamed(t, "lsp_info", s.LSP.InfoDiagnostic.GetForeground(), bg, minReadableContrast)
	})
}
