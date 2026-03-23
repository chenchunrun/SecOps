package styles

import (
	"fmt"
	"image/color"
	"strings"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/glamour/v2/ansi"
	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"
	"github.com/charmbracelet/x/exp/charmtone"
	"github.com/chenchunrun/SecOps/internal/ui/diffview"
)

const (
	CheckIcon   string = "✓"
	SpinnerIcon string = "⋯"
	LoadingIcon string = "⟳"
	ModelIcon   string = "◇"

	ArrowRightIcon string = "→"

	ToolPending string = "●"
	ToolSuccess string = "✓"
	ToolError   string = "×"

	RadioOn  string = "◉"
	RadioOff string = "○"

	BorderThin  string = "│"
	BorderThick string = "▌"

	SectionSeparator string = "─"

	TodoCompletedIcon  string = "✓"
	TodoPendingIcon    string = "•"
	TodoInProgressIcon string = "→"

	ImageIcon string = "■"
	TextIcon  string = "≡"

	ScrollbarThumb string = "┃"
	ScrollbarTrack string = "│"

	LSPErrorIcon   string = "E"
	LSPWarningIcon string = "W"
	LSPInfoIcon    string = "I"
	LSPHintIcon    string = "H"
)

const (
	defaultMargin     = 2
	defaultListIndent = 2
)

// newStrPtr returns a *string pointer to the given string.
// Used for ansi/chroma StyleConfig fields which expect *string.
func newStrPtr(s string) *string { return &s }

// Helper functions to return *string pointers for ansi/chroma StyleConfig fields
// which expect *string (not color.Color). Uses the new(X).Hex() idiom:
// new(charmtone.X) creates *charmtone.Key, then .Hex() returns the hex string.
func newFgBaseHex() *string      { return newStrPtr(new(charmtone.Ash).Hex()) }
func newFgMutedHex() *string     { return newStrPtr(new(charmtone.Squid).Hex()) }
func newFgHalfMutedHex() *string { return newStrPtr(new(charmtone.Smoke).Hex()) }
func newFgSubtleHex() *string    { return newStrPtr(new(charmtone.Oyster).Hex()) }

func colorHex(c color.Color) string {
	r, g, b, _ := c.RGBA()
	return fmt.Sprintf("#%02X%02X%02X", uint8(r>>8), uint8(g>>8), uint8(b>>8))
}


type Styles struct {
	WindowTooSmall lipgloss.Style

	// Reusable text styles
	Base      lipgloss.Style
	Muted     lipgloss.Style
	HalfMuted lipgloss.Style
	Subtle    lipgloss.Style

	// Tags
	TagBase  lipgloss.Style
	TagError lipgloss.Style
	TagInfo  lipgloss.Style

	// Header
	Header struct {
		Charm        lipgloss.Style // Style for "Charm™" label
		Diagonals    lipgloss.Style // Style for diagonal separators (╱)
		Percentage   lipgloss.Style // Style for context percentage
		Keystroke    lipgloss.Style // Style for keystroke hints (e.g., "ctrl+d")
		KeystrokeTip lipgloss.Style // Style for keystroke action text (e.g., "open", "close")
		WorkingDir   lipgloss.Style // Style for current working directory
		Separator    lipgloss.Style // Style for separator dots (•)
	}

	CompactDetails struct {
		View    lipgloss.Style
		Version lipgloss.Style
		Title   lipgloss.Style
	}

	// Panels
	PanelMuted lipgloss.Style
	PanelBase  lipgloss.Style

	// Line numbers for code blocks
	LineNumber lipgloss.Style

	// Message borders
	FocusedMessageBorder lipgloss.Border

	// Tool calls
	ToolCallPending   lipgloss.Style
	ToolCallError     lipgloss.Style
	ToolCallSuccess   lipgloss.Style
	ToolCallCancelled lipgloss.Style
	EarlyStateMessage lipgloss.Style

	// Text selection
	TextSelection lipgloss.Style

	// LSP and MCP status indicators
	ResourceGroupTitle     lipgloss.Style
	ResourceOfflineIcon    lipgloss.Style
	ResourceBusyIcon       lipgloss.Style
	ResourceErrorIcon      lipgloss.Style
	ResourceOnlineIcon     lipgloss.Style
	ResourceName           lipgloss.Style
	ResourceStatus         lipgloss.Style
	ResourceAdditionalText lipgloss.Style

	// Markdown & Chroma
	Markdown      ansi.StyleConfig
	PlainMarkdown ansi.StyleConfig

	// Inputs
	TextInput textinput.Styles
	TextArea  textarea.Styles

	// Help
	Help help.Styles

	// Diff
	Diff diffview.Style

	// FilePicker
	FilePicker filepicker.Styles

	// Buttons
	ButtonFocus lipgloss.Style
	ButtonBlur  lipgloss.Style

	// Borders
	BorderFocus lipgloss.Style
	BorderBlur  lipgloss.Style

	// Editor
	EditorPromptNormalFocused   lipgloss.Style
	EditorPromptNormalBlurred   lipgloss.Style
	EditorPromptYoloIconFocused lipgloss.Style
	EditorPromptYoloIconBlurred lipgloss.Style
	EditorPromptYoloDotsFocused lipgloss.Style
	EditorPromptYoloDotsBlurred lipgloss.Style

	// Radio
	RadioOn  lipgloss.Style
	RadioOff lipgloss.Style

	// Background
	Background color.Color

	// Logo
	LogoFieldColor   color.Color
	LogoTitleColorA  color.Color
	LogoTitleColorB  color.Color
	LogoCharmColor   color.Color
	LogoVersionColor color.Color

	// Colors - semantic colors for tool rendering.
	Primary       color.Color
	Secondary     color.Color
	Tertiary      color.Color
	BgBase        color.Color
	BgBaseLighter color.Color
	BgSubtle      color.Color
	BgOverlay     color.Color
	FgBase        color.Color
	FgMuted       color.Color
	FgHalfMuted   color.Color
	FgSubtle      color.Color
	Border        color.Color
	BorderColor   color.Color // Border focus color
	Error         color.Color
	Warning       color.Color
	Info          color.Color
	White         color.Color
	BlueLight     color.Color
	Blue          color.Color
	BlueDark      color.Color
	GreenLight    color.Color
	Green         color.Color
	GreenDark     color.Color
	Red           color.Color
	RedDark       color.Color
	Yellow        color.Color

	// Section Title
	Section struct {
		Title lipgloss.Style
		Line  lipgloss.Style
	}

	// Initialize
	Initialize struct {
		Header  lipgloss.Style
		Content lipgloss.Style
		Accent  lipgloss.Style
	}

	// LSP
	LSP struct {
		ErrorDiagnostic   lipgloss.Style
		WarningDiagnostic lipgloss.Style
		HintDiagnostic    lipgloss.Style
		InfoDiagnostic    lipgloss.Style
	}

	// Files
	Files struct {
		Path      lipgloss.Style
		Additions lipgloss.Style
		Deletions lipgloss.Style
	}

	// Chat
	Chat struct {
		// Message item styles
		Message struct {
			UserBlurred      lipgloss.Style
			UserFocused      lipgloss.Style
			AssistantBlurred lipgloss.Style
			AssistantFocused lipgloss.Style
			NoContent        lipgloss.Style
			Thinking         lipgloss.Style
			ErrorTag         lipgloss.Style
			ErrorTitle       lipgloss.Style
			ErrorDetails     lipgloss.Style
			ToolCallFocused  lipgloss.Style
			ToolCallCompact  lipgloss.Style
			ToolCallBlurred  lipgloss.Style
			SectionHeader    lipgloss.Style

			// Thinking section styles
			ThinkingBox            lipgloss.Style // Background for thinking content
			ThinkingTruncationHint lipgloss.Style // "… (N lines hidden)" hint
			ThinkingFooterTitle    lipgloss.Style // "Thought for" text
			ThinkingFooterDuration lipgloss.Style // Duration value
			AssistantInfoIcon      lipgloss.Style
			AssistantInfoModel     lipgloss.Style
			AssistantInfoProvider  lipgloss.Style
			AssistantInfoDuration  lipgloss.Style
		}
	}

	// Tool - styles for tool call rendering
	Tool struct {
		// Icon styles with tool status
		IconPending   lipgloss.Style
		IconSuccess   lipgloss.Style
		IconError     lipgloss.Style
		IconCancelled lipgloss.Style

		// Tool name styles
		NameNormal lipgloss.Style // Top-level tool name
		NameNested lipgloss.Style // Nested child tool name (inside Agent/Agentic Fetch)

		// Parameter list styles
		ParamMain lipgloss.Style
		ParamKey  lipgloss.Style

		// Content rendering styles
		ContentLine           lipgloss.Style // Individual content line with background and width
		ContentTruncation     lipgloss.Style // Truncation message "… (N lines)"
		ContentCodeLine       lipgloss.Style // Code line with background and width
		ContentCodeTruncation lipgloss.Style // Code truncation message with bgBase
		ContentCodeBg         color.Color    // Background color for syntax highlighting
		Body                  lipgloss.Style // Body content padding (PaddingLeft(2))

		// Deprecated - kept for backward compatibility
		ContentBg         lipgloss.Style // Content background
		ContentText       lipgloss.Style // Content text
		ContentLineNumber lipgloss.Style // Line numbers in code

		// State message styles
		StateWaiting   lipgloss.Style // "Waiting for tool response..."
		StateCancelled lipgloss.Style // "Canceled."

		// Error styles
		ErrorTag     lipgloss.Style // ERROR tag
		ErrorMessage lipgloss.Style // Error message text

		// Diff styles
		DiffTruncation lipgloss.Style // Diff truncation message with padding

		// Multi-edit note styles
		NoteTag     lipgloss.Style // NOTE tag (yellow background)
		NoteMessage lipgloss.Style // Note message text

		// Job header styles (for bash jobs)
		JobIconPending lipgloss.Style // Pending job icon (green dark)
		JobIconError   lipgloss.Style // Error job icon (red dark)
		JobIconSuccess lipgloss.Style // Success job icon (green)
		JobToolName    lipgloss.Style // Job tool name "Bash" (blue)
		JobAction      lipgloss.Style // Action text (Start, Output, Kill)
		JobPID         lipgloss.Style // PID text
		JobDescription lipgloss.Style // Description text

		// Agent task styles
		AgentTaskTag lipgloss.Style // Agent task tag (blue background, bold)
		AgentPrompt  lipgloss.Style // Agent prompt text

		// Agentic fetch styles
		AgenticFetchPromptTag lipgloss.Style // Agentic fetch prompt tag (green background, bold)

		// Todo styles
		TodoRatio          lipgloss.Style // Todo ratio (e.g., "2/5")
		TodoCompletedIcon  lipgloss.Style // Completed todo icon
		TodoInProgressIcon lipgloss.Style // In-progress todo icon
		TodoPendingIcon    lipgloss.Style // Pending todo icon

		// MCP tools
		MCPName     lipgloss.Style // The mcp name
		MCPToolName lipgloss.Style // The mcp tool name
		MCPArrow    lipgloss.Style // The mcp arrow icon

		// Images and external resources
		ResourceLoadedText      lipgloss.Style
		ResourceLoadedIndicator lipgloss.Style
		ResourceName            lipgloss.Style
		ResourceSize            lipgloss.Style
		MediaType               lipgloss.Style

		// Docker MCP tools
		DockerMCPActionAdd lipgloss.Style // Docker MCP add action (green)
		DockerMCPActionDel lipgloss.Style // Docker MCP remove action (red)
	}

	// Dialog styles
	Dialog struct {
		Title       lipgloss.Style
		TitleText   lipgloss.Style
		TitleError  lipgloss.Style
		TitleAccent lipgloss.Style
		// View is the main content area style.
		View          lipgloss.Style
		PrimaryText   lipgloss.Style
		SecondaryText lipgloss.Style
		// HelpView is the line that contains the help.
		HelpView lipgloss.Style
		Help     struct {
			Ellipsis       lipgloss.Style
			ShortKey       lipgloss.Style
			ShortDesc      lipgloss.Style
			ShortSeparator lipgloss.Style
			FullKey        lipgloss.Style
			FullDesc       lipgloss.Style
			FullSeparator  lipgloss.Style
		}

		NormalItem   lipgloss.Style
		SelectedItem lipgloss.Style
		InputPrompt  lipgloss.Style

		List lipgloss.Style

		Spinner lipgloss.Style

		// ContentPanel is used for content blocks with subtle background.
		ContentPanel lipgloss.Style

		// Scrollbar styles for scrollable content.
		ScrollbarThumb lipgloss.Style
		ScrollbarTrack lipgloss.Style

		// Arguments
		Arguments struct {
			Content                  lipgloss.Style
			Description              lipgloss.Style
			InputLabelBlurred        lipgloss.Style
			InputLabelFocused        lipgloss.Style
			InputRequiredMarkBlurred lipgloss.Style
			InputRequiredMarkFocused lipgloss.Style
		}

		Commands struct{}

		ImagePreview lipgloss.Style

		Sessions struct {
			// styles for when we are in delete mode
			DeletingView                   lipgloss.Style
			DeletingItemFocused            lipgloss.Style
			DeletingItemBlurred            lipgloss.Style
			DeletingTitle                  lipgloss.Style
			DeletingMessage                lipgloss.Style
			DeletingTitleGradientFromColor color.Color
			DeletingTitleGradientToColor   color.Color

			// styles for when we are in update mode
			RenamingView                   lipgloss.Style
			RenamingingItemFocused         lipgloss.Style
			RenamingItemBlurred            lipgloss.Style
			RenamingingTitle               lipgloss.Style
			RenamingingMessage             lipgloss.Style
			RenamingTitleGradientFromColor color.Color
			RenamingTitleGradientToColor   color.Color
			RenamingPlaceholder            lipgloss.Style
		}
	}

	// Status bar and help
	Status struct {
		Help lipgloss.Style

		ErrorIndicator   lipgloss.Style
		WarnIndicator    lipgloss.Style
		InfoIndicator    lipgloss.Style
		UpdateIndicator  lipgloss.Style
		SuccessIndicator lipgloss.Style

		ErrorMessage   lipgloss.Style
		WarnMessage    lipgloss.Style
		InfoMessage    lipgloss.Style
		UpdateMessage  lipgloss.Style
		SuccessMessage lipgloss.Style
	}

	// Completions popup styles
	Completions struct {
		Normal  lipgloss.Style
		Focused lipgloss.Style
		Match   lipgloss.Style
	}

	// Attachments styles
	Attachments struct {
		Normal   lipgloss.Style
		Image    lipgloss.Style
		Text     lipgloss.Style
		Deleting lipgloss.Style
	}

	// Pills styles for todo/queue pills
	Pills struct {
		Base            lipgloss.Style // Base pill style with padding
		Focused         lipgloss.Style // Focused pill with visible border
		Blurred         lipgloss.Style // Blurred pill with hidden border
		QueueItemPrefix lipgloss.Style // Prefix for queue list items
		HelpKey         lipgloss.Style // Keystroke hint style
		HelpText        lipgloss.Style // Help action text style
		Area            lipgloss.Style // Pills area container
		TodoSpinner     lipgloss.Style // Todo spinner style
	}
}

// ChromaTheme converts the current markdown chroma styles to a chroma
// StyleEntries map.
func (s *Styles) ChromaTheme() chroma.StyleEntries {
	rules := s.Markdown.CodeBlock

	return chroma.StyleEntries{
		chroma.Text:                chromaStyle(rules.Chroma.Text),
		chroma.Error:               chromaStyle(rules.Chroma.Error),
		chroma.Comment:             chromaStyle(rules.Chroma.Comment),
		chroma.CommentPreproc:      chromaStyle(rules.Chroma.CommentPreproc),
		chroma.Keyword:             chromaStyle(rules.Chroma.Keyword),
		chroma.KeywordReserved:     chromaStyle(rules.Chroma.KeywordReserved),
		chroma.KeywordNamespace:    chromaStyle(rules.Chroma.KeywordNamespace),
		chroma.KeywordType:         chromaStyle(rules.Chroma.KeywordType),
		chroma.Operator:            chromaStyle(rules.Chroma.Operator),
		chroma.Punctuation:         chromaStyle(rules.Chroma.Punctuation),
		chroma.Name:                chromaStyle(rules.Chroma.Name),
		chroma.NameBuiltin:         chromaStyle(rules.Chroma.NameBuiltin),
		chroma.NameTag:             chromaStyle(rules.Chroma.NameTag),
		chroma.NameAttribute:       chromaStyle(rules.Chroma.NameAttribute),
		chroma.NameClass:           chromaStyle(rules.Chroma.NameClass),
		chroma.NameConstant:        chromaStyle(rules.Chroma.NameConstant),
		chroma.NameDecorator:       chromaStyle(rules.Chroma.NameDecorator),
		chroma.NameException:       chromaStyle(rules.Chroma.NameException),
		chroma.NameFunction:        chromaStyle(rules.Chroma.NameFunction),
		chroma.NameOther:           chromaStyle(rules.Chroma.NameOther),
		chroma.Literal:             chromaStyle(rules.Chroma.Literal),
		chroma.LiteralNumber:       chromaStyle(rules.Chroma.LiteralNumber),
		chroma.LiteralDate:         chromaStyle(rules.Chroma.LiteralDate),
		chroma.LiteralString:       chromaStyle(rules.Chroma.LiteralString),
		chroma.LiteralStringEscape: chromaStyle(rules.Chroma.LiteralStringEscape),
		chroma.GenericDeleted:      chromaStyle(rules.Chroma.GenericDeleted),
		chroma.GenericEmph:         chromaStyle(rules.Chroma.GenericEmph),
		chroma.GenericInserted:     chromaStyle(rules.Chroma.GenericInserted),
		chroma.GenericStrong:       chromaStyle(rules.Chroma.GenericStrong),
		chroma.GenericSubheading:   chromaStyle(rules.Chroma.GenericSubheading),
		chroma.Background:          chromaStyle(rules.Chroma.Background),
	}
}

// DialogHelpStyles returns the styles for dialog help.
func (s *Styles) DialogHelpStyles() help.Styles {
	return help.Styles(s.Dialog.Help)
}

// DefaultStyles returns the default styles for the UI.
// It accepts an optional Theme parameter to select between dark (default) and
// light color schemes. When no theme is provided, ThemeDark is used.
func DefaultStyles(theme ...Theme) Styles {
	isDarkTheme := len(theme) == 0 || theme[0] == ThemeDark

	var (
		primary   color.Color = charmtone.Charple
		secondary color.Color = charmtone.Dolly
		tertiary  color.Color = charmtone.Bok

		// Backgrounds
		bgBase        color.Color = charmtone.Pepper
		bgBaseLighter color.Color = charmtone.BBQ
		bgSubtle      color.Color = charmtone.Charcoal
		bgOverlay     color.Color = charmtone.Iron

		// Foregrounds — adapt to terminal background via foregroundColorsForTheme.
		fgBase, fgMuted, fgHalfMuted, fgSubtle = foregroundColorsForTheme(theme...)

		// Borders
		border      color.Color = charmtone.Charcoal
		borderFocus color.Color = charmtone.Charple

		// Status
		error   color.Color = charmtone.Sriracha
		warning color.Color = charmtone.Zest
		info    color.Color = charmtone.Malibu

		// Colors
		white color.Color = charmtone.Butter

		blueLight color.Color = charmtone.Sardine
		blue      color.Color = charmtone.Malibu
		blueDark  color.Color = charmtone.Damson

		yellow color.Color = charmtone.Mustard

		greenLight color.Color = charmtone.Bok
		green      color.Color = charmtone.Julep
		greenDark  color.Color = charmtone.Guac

		red     color.Color = charmtone.Coral
		redDark color.Color = charmtone.Sriracha
	)

	if !isDarkTheme {
		// Codex-like light palette: soft gray canvas, dark text, cyan accents.
		bgBase = lipgloss.Color("#FFFFFF")
		bgBaseLighter = lipgloss.Color("#F4F4F4")
		bgSubtle = lipgloss.Color("#ECECEC")
		bgOverlay = lipgloss.Color("#F7F7F7")
		border = lipgloss.Color("#CFCFCF")
		borderFocus = lipgloss.Color("#00A8B5")

		primary = lipgloss.Color("#0E7490")
		secondary = lipgloss.Color("#0E7490")
		tertiary = lipgloss.Color("#3B82F6")

		blueLight = lipgloss.Color("#0F766E")
		blue = lipgloss.Color("#0C4A6E")
		blueDark = lipgloss.Color("#0E7490")

		greenLight = lipgloss.Color("#15803D")
		green = lipgloss.Color("#166534")
		greenDark = lipgloss.Color("#14532D")

		yellow = lipgloss.Color("#92400E")
		warning = lipgloss.Color("#78350F")
		red = lipgloss.Color("#DC2626")
		redDark = lipgloss.Color("#B91C1C")
		error = red
		info = blue
	}

	normalBorder := lipgloss.NormalBorder()

	base := lipgloss.NewStyle().Foreground(fgBase)
	fgBaseHex := newStrPtr(colorHex(fgBase))

	s := Styles{}

	s.Background = bgBase

	// Populate color fields
	s.Primary = primary
	s.Secondary = secondary
	s.Tertiary = tertiary
	s.BgBase = bgBase
	s.BgBaseLighter = bgBaseLighter
	s.BgSubtle = bgSubtle
	s.BgOverlay = bgOverlay
	s.FgBase = fgBase
	s.FgMuted = fgMuted
	s.FgHalfMuted = fgHalfMuted
	s.FgSubtle = fgSubtle
	s.Border = border
	s.BorderColor = borderFocus
	s.Error = error
	s.Warning = warning
	s.Info = info
	s.White = white
	s.BlueLight = blueLight
	s.Blue = blue
	s.BlueDark = blueDark
	s.GreenLight = greenLight
	s.Green = green
	s.GreenDark = greenDark
	s.Red = red
	s.RedDark = redDark
	s.Yellow = yellow

	s.TextInput = textinput.Styles{
		Focused: textinput.StyleState{
			Text:        base,
			Placeholder: base.Foreground(fgSubtle),
			Prompt:      base.Foreground(tertiary),
			Suggestion:  base.Foreground(fgSubtle),
		},
		Blurred: textinput.StyleState{
			Text:        base.Foreground(fgMuted),
			Placeholder: base.Foreground(fgSubtle),
			Prompt:      base.Foreground(fgMuted),
			Suggestion:  base.Foreground(fgSubtle),
		},
		Cursor: textinput.CursorStyle{
			Color: secondary,
			Shape: tea.CursorBlock,
			Blink: true,
		},
	}

	s.TextArea = textarea.Styles{
		Focused: textarea.StyleState{
			Base:             base,
			Text:             base,
			LineNumber:       base.Foreground(fgSubtle),
			CursorLine:       base,
			CursorLineNumber: base.Foreground(fgSubtle),
			Placeholder:      base.Foreground(fgSubtle),
			Prompt:           base.Foreground(tertiary),
		},
		Blurred: textarea.StyleState{
			Base:             base,
			Text:             base.Foreground(fgMuted),
			LineNumber:       base.Foreground(fgMuted),
			CursorLine:       base,
			CursorLineNumber: base.Foreground(fgMuted),
			Placeholder:      base.Foreground(fgSubtle),
			Prompt:           base.Foreground(fgMuted),
		},
		Cursor: textarea.CursorStyle{
			Color: secondary,
			Shape: tea.CursorBlock,
			Blink: true,
		},
	}

	s.Markdown = ansi.StyleConfig{
		Document: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				// BlockPrefix: "\n",
				// BlockSuffix: "\n",
				Color: fgBaseHex,
			},
			// Margin: new(uint(defaultMargin)),
		},
		BlockQuote: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{},
			Indent:         new(uint(1)),
			IndentToken:    new("│ "),
		},
		List: ansi.StyleList{
			LevelIndent: defaultListIndent,
		},
		Heading: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				BlockSuffix: "\n",
				Color:       newStrPtr(new(charmtone.Malibu).Hex()),
				Bold:        new(true),
			},
		},
		H1: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          " ",
				Suffix:          " ",
				Color:           new(charmtone.Zest.Hex()),
				BackgroundColor: new(charmtone.Charple.Hex()),
				Bold:            new(true),
			},
		},
		H2: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "## ",
			},
		},
		H3: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "### ",
			},
		},
		H4: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "#### ",
			},
		},
		H5: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "##### ",
			},
		},
		H6: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "###### ",
				Color:  new(charmtone.Guac.Hex()),
				Bold:   new(false),
			},
		},
		Strikethrough: ansi.StylePrimitive{
			CrossedOut: new(true),
		},
		Emph: ansi.StylePrimitive{
			Italic: new(true),
		},
		Strong: ansi.StylePrimitive{
			Bold: new(true),
		},
		HorizontalRule: ansi.StylePrimitive{
			Color:  new(charmtone.Charcoal.Hex()),
			Format: "\n--------\n",
		},
		Item: ansi.StylePrimitive{
			BlockPrefix: "• ",
		},
		Enumeration: ansi.StylePrimitive{
			BlockPrefix: ". ",
		},
		Task: ansi.StyleTask{
			StylePrimitive: ansi.StylePrimitive{},
			Ticked:         "[✓] ",
			Unticked:       "[ ] ",
		},
		Link: ansi.StylePrimitive{
			Color:     new(charmtone.Zinc.Hex()),
			Underline: new(true),
		},
		LinkText: ansi.StylePrimitive{
			Color: new(charmtone.Guac.Hex()),
			Bold:  new(true),
		},
		Image: ansi.StylePrimitive{
			Color:     new(charmtone.Cheeky.Hex()),
			Underline: new(true),
		},
		ImageText: ansi.StylePrimitive{
			Color:  new(charmtone.Squid.Hex()),
			Format: "Image: {{.text}} →",
		},
		Code: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          " ",
				Suffix:          " ",
				Color:           new(charmtone.Coral.Hex()),
				BackgroundColor: new(charmtone.Charcoal.Hex()),
			},
		},
		CodeBlock: ansi.StyleCodeBlock{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color: new(charmtone.Charcoal.Hex()),
				},
				Margin: new(uint(defaultMargin)),
			},
			Chroma: &ansi.Chroma{
				Text: ansi.StylePrimitive{
					Color: fgBaseHex,
				},
				Error: ansi.StylePrimitive{
					Color:           new(charmtone.Butter.Hex()),
					BackgroundColor: new(charmtone.Sriracha.Hex()),
				},
				Comment: ansi.StylePrimitive{
					Color: new(charmtone.Oyster.Hex()),
				},
				CommentPreproc: ansi.StylePrimitive{
					Color: new(charmtone.Bengal.Hex()),
				},
				Keyword: ansi.StylePrimitive{
					Color: new(charmtone.Malibu.Hex()),
				},
				KeywordReserved: ansi.StylePrimitive{
					Color: new(charmtone.Pony.Hex()),
				},
				KeywordNamespace: ansi.StylePrimitive{
					Color: new(charmtone.Pony.Hex()),
				},
				KeywordType: ansi.StylePrimitive{
					Color: new(charmtone.Guppy.Hex()),
				},
				Operator: ansi.StylePrimitive{
					Color: new(charmtone.Salmon.Hex()),
				},
				Punctuation: ansi.StylePrimitive{
					Color: new(charmtone.Zest.Hex()),
				},
				Name: ansi.StylePrimitive{
					Color: fgBaseHex,
				},
				NameBuiltin: ansi.StylePrimitive{
					Color: new(charmtone.Cheeky.Hex()),
				},
				NameTag: ansi.StylePrimitive{
					Color: new(charmtone.Mauve.Hex()),
				},
				NameAttribute: ansi.StylePrimitive{
					Color: new(charmtone.Hazy.Hex()),
				},
				NameClass: ansi.StylePrimitive{
					Color:     new(charmtone.Salt.Hex()),
					Underline: new(true),
					Bold:      new(true),
				},
				NameDecorator: ansi.StylePrimitive{
					Color: new(charmtone.Citron.Hex()),
				},
				NameFunction: ansi.StylePrimitive{
					Color: new(charmtone.Guac.Hex()),
				},
				LiteralNumber: ansi.StylePrimitive{
					Color: new(charmtone.Julep.Hex()),
				},
				LiteralString: ansi.StylePrimitive{
					Color: new(charmtone.Cumin.Hex()),
				},
				LiteralStringEscape: ansi.StylePrimitive{
					Color: new(charmtone.Bok.Hex()),
				},
				GenericDeleted: ansi.StylePrimitive{
					Color: new(charmtone.Coral.Hex()),
				},
				GenericEmph: ansi.StylePrimitive{
					Italic: new(true),
				},
				GenericInserted: ansi.StylePrimitive{
					Color: new(charmtone.Guac.Hex()),
				},
				GenericStrong: ansi.StylePrimitive{
					Bold: new(true),
				},
				GenericSubheading: ansi.StylePrimitive{
					Color: new(charmtone.Squid.Hex()),
				},
				Background: ansi.StylePrimitive{
					BackgroundColor: new(charmtone.Charcoal.Hex()),
				},
			},
		},
		Table: ansi.StyleTable{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{},
			},
		},
		DefinitionDescription: ansi.StylePrimitive{
			BlockPrefix: "\n ",
		},
	}

	// PlainMarkdown style - muted colors on subtle background for thinking content.
	plainBg := newStrPtr(colorHex(bgBaseLighter))
	plainFg := fgBaseHex
	s.PlainMarkdown = ansi.StyleConfig{
		Document: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		BlockQuote: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
			Indent:      new(uint(1)),
			IndentToken: new("│ "),
		},
		List: ansi.StyleList{
			LevelIndent: defaultListIndent,
		},
		Heading: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				BlockSuffix:     "\n",
				Bold:            new(true),
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		H1: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          " ",
				Suffix:          " ",
				Bold:            new(true),
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		H2: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          "## ",
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		H3: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          "### ",
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		H4: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          "#### ",
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		H5: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          "##### ",
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		H6: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          "###### ",
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		Strikethrough: ansi.StylePrimitive{
			CrossedOut:      new(true),
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		Emph: ansi.StylePrimitive{
			Italic:          new(true),
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		Strong: ansi.StylePrimitive{
			Bold:            new(true),
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		HorizontalRule: ansi.StylePrimitive{
			Format:          "\n--------\n",
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		Item: ansi.StylePrimitive{
			BlockPrefix:     "• ",
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		Enumeration: ansi.StylePrimitive{
			BlockPrefix:     ". ",
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		Task: ansi.StyleTask{
			StylePrimitive: ansi.StylePrimitive{
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
			Ticked:   "[✓] ",
			Unticked: "[ ] ",
		},
		Link: ansi.StylePrimitive{
			Underline:       new(true),
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		LinkText: ansi.StylePrimitive{
			Bold:            new(true),
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		Image: ansi.StylePrimitive{
			Underline:       new(true),
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		ImageText: ansi.StylePrimitive{
			Format:          "Image: {{.text}} →",
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
		Code: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix:          " ",
				Suffix:          " ",
				Color:           plainFg,
				BackgroundColor: plainBg,
			},
		},
		CodeBlock: ansi.StyleCodeBlock{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color:           plainFg,
					BackgroundColor: plainBg,
				},
				Margin: new(uint(defaultMargin)),
			},
		},
		Table: ansi.StyleTable{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color:           plainFg,
					BackgroundColor: plainBg,
				},
			},
		},
		DefinitionDescription: ansi.StylePrimitive{
			BlockPrefix:     "\n ",
			Color:           plainFg,
			BackgroundColor: plainBg,
		},
	}

	s.Help = help.Styles{
		ShortKey:       base.Foreground(fgBase),
		ShortDesc:      base.Foreground(fgMuted),
		ShortSeparator: base.Foreground(border),
		Ellipsis:       base.Foreground(border),
		FullKey:        base.Foreground(fgBase),
		FullDesc:       base.Foreground(fgMuted),
		FullSeparator:  base.Foreground(border),
	}

	s.Diff = diffview.DefaultDarkStyle()
	if len(theme) > 0 && theme[0] == ThemeLight {
		s.Diff = diffview.DefaultLightStyle()
	}

	s.FilePicker = filepicker.Styles{
		DisabledCursor:   base.Foreground(fgMuted),
		Cursor:           base.Foreground(fgBase),
		Symlink:          base.Foreground(fgSubtle),
		Directory:        base.Foreground(primary),
		File:             base.Foreground(fgBase),
		DisabledFile:     base.Foreground(fgMuted),
		DisabledSelected: base.Background(bgSubtle).Foreground(lipgloss.LightDark(isDarkTheme)(charmtone.Pepper, white)),
		Permission:       base.Foreground(fgMuted),
		Selected:         base.Background(primary).Foreground(white),
		FileSize:         base.Foreground(fgMuted),
		EmptyDirectory:   base.Foreground(fgMuted).PaddingLeft(2).SetString("Empty directory"),
	}

	// borders
	s.FocusedMessageBorder = lipgloss.Border{Left: BorderThick}

	// text presets
	s.Base = lipgloss.NewStyle().Foreground(fgBase)
	s.Muted = lipgloss.NewStyle().Foreground(fgMuted)
	s.HalfMuted = lipgloss.NewStyle().Foreground(fgHalfMuted)
	s.Subtle = lipgloss.NewStyle().Foreground(fgSubtle)

	s.WindowTooSmall = s.Muted

	// tag presets
	s.TagBase = lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase))
	s.TagError = s.TagBase.Background(red)
	s.TagInfo = s.TagBase.Background(blueLight)

	// Compact header styles
	s.Header.Charm = base.Foreground(secondary)
	s.Header.Diagonals = base.Foreground(primary)
	s.Header.Percentage = s.Muted
	s.Header.Keystroke = s.Muted
	s.Header.KeystrokeTip = s.Muted
	s.Header.WorkingDir = s.Muted
	s.Header.Separator = s.Muted

	s.CompactDetails.Title = s.Base
	s.CompactDetails.View = s.Base.Padding(0, 1, 1, 1).Border(lipgloss.RoundedBorder()).BorderForeground(borderFocus)
	s.CompactDetails.Version = s.Muted

	// panels
	s.PanelMuted = s.Muted.Background(bgBaseLighter)
	s.PanelBase = lipgloss.NewStyle().Background(bgBase)

	// code line number
	s.LineNumber = lipgloss.NewStyle().Foreground(fgMuted).Background(bgBase).PaddingRight(1).PaddingLeft(1)

	// Tool calls
	s.ToolCallPending = lipgloss.NewStyle().Foreground(greenDark).SetString(ToolPending)
	s.ToolCallError = lipgloss.NewStyle().Foreground(redDark).SetString(ToolError)
	s.ToolCallSuccess = lipgloss.NewStyle().Foreground(green).SetString(ToolSuccess)
	// Cancelled uses muted tone but same glyph as pending
	s.ToolCallCancelled = s.Muted.SetString(ToolPending)
	s.EarlyStateMessage = s.Subtle.PaddingLeft(2)

	// Tool rendering styles
	s.Tool.IconPending = base.Foreground(greenDark).SetString(ToolPending)
	s.Tool.IconSuccess = base.Foreground(green).SetString(ToolSuccess)
	s.Tool.IconError = base.Foreground(redDark).SetString(ToolError)
	s.Tool.IconCancelled = s.Muted.SetString(ToolPending)

	s.Tool.NameNormal = base.Foreground(blue)
	s.Tool.NameNested = base.Foreground(blue)

	s.Tool.ParamMain = s.Subtle
	s.Tool.ParamKey = s.Subtle

	// Content rendering - prepared styles that accept width parameter
	s.Tool.ContentLine = s.Muted.Background(bgBaseLighter)
	s.Tool.ContentTruncation = s.Muted.Background(bgBaseLighter)
	s.Tool.ContentCodeLine = s.Base.Background(bgBase).PaddingLeft(2)
	s.Tool.ContentCodeTruncation = s.Muted.Background(bgBase).PaddingLeft(2)
	s.Tool.ContentCodeBg = bgBase
	s.Tool.Body = base.PaddingLeft(2)

	// Deprecated - kept for backward compatibility
	s.Tool.ContentBg = s.Muted.Background(bgBaseLighter)
	s.Tool.ContentText = s.Muted
	s.Tool.ContentLineNumber = base.Foreground(fgMuted).Background(bgBase).PaddingRight(1).PaddingLeft(1)

	s.Tool.StateWaiting = base.Foreground(fgMuted)
	s.Tool.StateCancelled = base.Foreground(fgMuted)

	s.Tool.ErrorTag = base.Padding(0, 1).Background(red).Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase))
	s.Tool.ErrorMessage = base.Foreground(fgMuted)

	// Diff and multi-edit styles
	s.Tool.DiffTruncation = s.Muted.Background(bgBaseLighter).PaddingLeft(2)
	s.Tool.NoteTag = base.Padding(0, 1).Background(info).Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase))
	s.Tool.NoteMessage = base.Foreground(fgMuted)

	// Job header styles
	s.Tool.JobIconPending = base.Foreground(greenDark)
	s.Tool.JobIconError = base.Foreground(redDark)
	s.Tool.JobIconSuccess = base.Foreground(green)
	s.Tool.JobToolName = base.Foreground(blue)
	s.Tool.JobAction = base.Foreground(blueDark)
	s.Tool.JobPID = s.Muted
	s.Tool.JobDescription = s.Muted

	// Agent task styles
	s.Tool.AgentTaskTag = base.Padding(0, 1).MarginLeft(2).Background(blueLight).Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase))
	s.Tool.AgentPrompt = s.Muted

	// Agentic fetch styles
	s.Tool.AgenticFetchPromptTag = base.Padding(0, 1).MarginLeft(2).Background(green).Foreground(lipgloss.LightDark(isDarkTheme)(white, border))

	// Todo styles
	s.Tool.TodoRatio = base.Foreground(blueDark)
	s.Tool.TodoCompletedIcon = base.Foreground(green)
	s.Tool.TodoInProgressIcon = base.Foreground(greenDark)
	s.Tool.TodoPendingIcon = base.Foreground(fgMuted)

	// MCP styles
	s.Tool.MCPName = base.Foreground(blue)
	s.Tool.MCPToolName = base.Foreground(blueDark)
	s.Tool.MCPArrow = base.Foreground(blue).SetString(ArrowRightIcon)

	// Loading indicators for images, skills
	s.Tool.ResourceLoadedText = base.Foreground(green)
	s.Tool.ResourceLoadedIndicator = base.Foreground(greenDark)
	s.Tool.ResourceName = base
	s.Tool.MediaType = base
	s.Tool.ResourceSize = base.Foreground(fgMuted)

	// Docker MCP styles
	s.Tool.DockerMCPActionAdd = base.Foreground(greenLight)
	s.Tool.DockerMCPActionDel = base.Foreground(red)

	// Buttons: focused uses strong contrast on positive background.
	s.ButtonFocus = lipgloss.NewStyle().
		Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase)).
		Background(greenDark).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(greenDark)
	s.ButtonBlur = lipgloss.NewStyle().
		Foreground(lipgloss.LightDark(isDarkTheme)(fgBase, white)).
		Background(lipgloss.LightDark(isDarkTheme)(charmtone.Salt, bgSubtle)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border)

	// Borders
	s.BorderFocus = lipgloss.NewStyle().BorderForeground(borderFocus).Border(lipgloss.RoundedBorder()).Padding(1, 2)

	// Editor
	s.EditorPromptNormalFocused = lipgloss.NewStyle().
		Foreground(lipgloss.LightDark(isDarkTheme)(blueDark, greenDark)).
		SetString("::: ")
	s.EditorPromptNormalBlurred = s.EditorPromptNormalFocused.Foreground(fgMuted)
	s.EditorPromptYoloIconFocused = lipgloss.NewStyle().MarginRight(1).Foreground(lipgloss.LightDark(isDarkTheme)(charmtone.Pepper, bgBase)).Background(charmtone.Citron).SetString(" ! ")
	s.EditorPromptYoloIconBlurred = s.EditorPromptYoloIconFocused.Foreground(charmtone.Pepper).Background(charmtone.Squid)
	s.EditorPromptYoloDotsFocused = lipgloss.NewStyle().MarginRight(1).Foreground(charmtone.Zest).SetString(":::")
	s.EditorPromptYoloDotsBlurred = s.EditorPromptYoloDotsFocused.Foreground(fgMuted)

	s.RadioOn = s.HalfMuted.SetString(RadioOn)
	s.RadioOff = s.HalfMuted.SetString(RadioOff)

	// Logo colors
	s.LogoFieldColor = primary
	s.LogoTitleColorA = secondary
	s.LogoTitleColorB = primary
	s.LogoCharmColor = secondary
	s.LogoVersionColor = primary

	// Section
	s.Section.Title = s.Subtle
	s.Section.Line = s.Base.Foreground(charmtone.Charcoal)

	// Initialize
	s.Initialize.Header = s.Base
	s.Initialize.Content = s.Muted
	s.Initialize.Accent = s.Base.Foreground(greenDark)

	// LSP and MCP status.
	s.ResourceGroupTitle = lipgloss.NewStyle().Foreground(fgBase).Bold(true)
	s.ResourceOfflineIcon = lipgloss.NewStyle().Foreground(fgMuted).SetString("●")
	s.ResourceBusyIcon = s.ResourceOfflineIcon.Foreground(lipgloss.LightDark(isDarkTheme)(blueDark, blue))
	s.ResourceErrorIcon = s.ResourceOfflineIcon.Foreground(lipgloss.LightDark(isDarkTheme)(redDark, red))
	s.ResourceOnlineIcon = s.ResourceOfflineIcon.Foreground(lipgloss.LightDark(isDarkTheme)(charmtone.Turtle, green))
	s.ResourceName = lipgloss.NewStyle().Foreground(fgBase)
	s.ResourceStatus = lipgloss.NewStyle().Foreground(fgMuted)
	s.ResourceAdditionalText = lipgloss.NewStyle().Foreground(fgMuted)

	// LSP
	s.LSP.ErrorDiagnostic = s.Base.Foreground(lipgloss.LightDark(isDarkTheme)(lipgloss.Color("#7A1E1E"), redDark))
	s.LSP.WarningDiagnostic = s.Base.Foreground(lipgloss.LightDark(isDarkTheme)(charmtone.Pepper, warning))
	s.LSP.HintDiagnostic = s.Base.Foreground(lipgloss.LightDark(isDarkTheme)(fgMuted, fgHalfMuted))
	s.LSP.InfoDiagnostic = s.Base.Foreground(lipgloss.LightDark(isDarkTheme)(blueDark, info))

	// Files
	s.Files.Path = s.Muted
	s.Files.Additions = s.Base.Foreground(greenDark)
	s.Files.Deletions = s.Base.Foreground(redDark)

	// Chat
	messageFocussedBorder := lipgloss.Border{
		Left: "▌",
	}

	s.Chat.Message.NoContent = lipgloss.NewStyle().Foreground(fgBase)
	s.Chat.Message.UserBlurred = s.Chat.Message.NoContent.PaddingLeft(1).BorderLeft(true).
		BorderForeground(primary).BorderStyle(normalBorder)
	s.Chat.Message.UserFocused = s.Chat.Message.NoContent.PaddingLeft(1).BorderLeft(true).
		BorderForeground(primary).BorderStyle(messageFocussedBorder)
	s.Chat.Message.AssistantBlurred = s.Chat.Message.NoContent.PaddingLeft(2)
	s.Chat.Message.AssistantFocused = s.Chat.Message.NoContent.PaddingLeft(1).BorderLeft(true).
		BorderForeground(greenDark).BorderStyle(messageFocussedBorder)
	s.Chat.Message.Thinking = lipgloss.NewStyle().MaxHeight(10)
	s.Chat.Message.ErrorTag = lipgloss.NewStyle().Padding(0, 1).
		Background(red).Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase))
	s.Chat.Message.ErrorTitle = lipgloss.NewStyle().Foreground(fgHalfMuted)
	s.Chat.Message.ErrorDetails = lipgloss.NewStyle().Foreground(fgMuted)

	// Message item styles
	s.Chat.Message.ToolCallFocused = s.Muted.PaddingLeft(1).
		BorderStyle(messageFocussedBorder).
		BorderLeft(true).
		BorderForeground(greenDark)
	s.Chat.Message.ToolCallBlurred = s.Muted.PaddingLeft(2)
	// No padding or border for compact tool calls within messages
	s.Chat.Message.ToolCallCompact = s.Muted
	s.Chat.Message.SectionHeader = s.Base.PaddingLeft(2)
	s.Chat.Message.AssistantInfoIcon = s.Subtle
	s.Chat.Message.AssistantInfoModel = s.Muted
	s.Chat.Message.AssistantInfoProvider = s.Muted
	s.Chat.Message.AssistantInfoDuration = s.Muted

	// Thinking section styles
	s.Chat.Message.ThinkingBox = s.Base.Background(lipgloss.LightDark(isDarkTheme)(white, bgBaseLighter))
	s.Chat.Message.ThinkingTruncationHint = s.Muted
	s.Chat.Message.ThinkingFooterTitle = s.Muted
	s.Chat.Message.ThinkingFooterDuration = s.Muted

	// Text selection.
	s.TextSelection = lipgloss.NewStyle().Foreground(charmtone.Salt).Background(charmtone.Charple)

	// Dialog styles
	s.Dialog.Title = base.Padding(0, 1).Foreground(primary)
	s.Dialog.TitleText = base.Foreground(primary)
	s.Dialog.TitleError = base.Foreground(red)
	s.Dialog.TitleAccent = base.Foreground(green).Bold(true)
	s.Dialog.View = lipgloss.NewStyle().
		Background(lipgloss.LightDark(isDarkTheme)(charmtone.Salt, bgOverlay)).
		Foreground(fgBase).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderFocus)
	s.Dialog.PrimaryText = base.Padding(0, 1).Foreground(primary)
	s.Dialog.SecondaryText = base.Padding(0, 1).Foreground(lipgloss.LightDark(isDarkTheme)(fgMuted, white))
	s.Dialog.HelpView = base.Padding(0, 1).AlignHorizontal(lipgloss.Left)
	s.Dialog.Help.ShortKey = base.Foreground(fgBase)
	s.Dialog.Help.ShortDesc = base.Foreground(fgMuted)
	s.Dialog.Help.ShortSeparator = base.Foreground(border)
	s.Dialog.Help.Ellipsis = base.Foreground(border)
	s.Dialog.Help.FullKey = base.Foreground(fgBase)
	s.Dialog.Help.FullDesc = base.Foreground(fgMuted)
	s.Dialog.Help.FullSeparator = base.Foreground(border)
	s.Dialog.NormalItem = base.Padding(0, 1).Foreground(fgBase)
	s.Dialog.SelectedItem = base.Padding(0, 1).Background(primary).Foreground(white)
	s.Dialog.InputPrompt = base.Margin(1, 1)

	s.Dialog.List = base.Margin(0, 0, 1, 0)
	s.Dialog.ContentPanel = base.Background(lipgloss.LightDark(isDarkTheme)(charmtone.Salt, bgBaseLighter)).Foreground(fgBase).Padding(1, 2)
	s.Dialog.Spinner = base.Foreground(secondary)
	s.Dialog.ScrollbarThumb = base.Foreground(secondary)
	s.Dialog.ScrollbarTrack = base.Foreground(border)

	s.Dialog.ImagePreview = lipgloss.NewStyle().Padding(0, 1).Foreground(fgSubtle)

	s.Dialog.Arguments.Content = base.Padding(1)
	s.Dialog.Arguments.Description = base.MarginBottom(1).MaxHeight(3)
	s.Dialog.Arguments.InputLabelBlurred = base.Foreground(fgMuted)
	s.Dialog.Arguments.InputLabelFocused = base.Bold(true)
	s.Dialog.Arguments.InputRequiredMarkBlurred = base.Foreground(fgMuted).SetString("*")
	s.Dialog.Arguments.InputRequiredMarkFocused = base.Foreground(primary).Bold(true).SetString("*")

	s.Dialog.Sessions.DeletingTitle = s.Dialog.Title.Foreground(red)
	s.Dialog.Sessions.DeletingView = s.Dialog.View.BorderForeground(red)
	s.Dialog.Sessions.DeletingMessage = s.Base.Padding(1)
	s.Dialog.Sessions.DeletingTitleGradientFromColor = red
	s.Dialog.Sessions.DeletingTitleGradientToColor = s.Primary
	s.Dialog.Sessions.DeletingItemBlurred = s.Dialog.NormalItem.Foreground(fgSubtle)
	s.Dialog.Sessions.DeletingItemFocused = s.Dialog.SelectedItem.Background(red).Foreground(charmtone.Butter)

	s.Dialog.Sessions.RenamingingTitle = s.Dialog.Title.Foreground(charmtone.Zest)
	s.Dialog.Sessions.RenamingView = s.Dialog.View.BorderForeground(charmtone.Zest)
	s.Dialog.Sessions.RenamingingMessage = s.Base.Padding(1)
	s.Dialog.Sessions.RenamingTitleGradientFromColor = charmtone.Zest
	s.Dialog.Sessions.RenamingTitleGradientToColor = charmtone.Bok
	s.Dialog.Sessions.RenamingItemBlurred = s.Dialog.NormalItem.Foreground(fgSubtle)
	s.Dialog.Sessions.RenamingingItemFocused = s.Dialog.SelectedItem.UnsetBackground().UnsetForeground()
	s.Dialog.Sessions.RenamingPlaceholder = base.Foreground(charmtone.Squid)

	s.Status.Help = lipgloss.NewStyle().Padding(0, 1)
	s.Status.SuccessIndicator = base.Foreground(lipgloss.LightDark(isDarkTheme)(white, bgSubtle)).Background(green).Padding(0, 1).SetString("OKAY!")
	s.Status.InfoIndicator = s.Status.SuccessIndicator
	s.Status.UpdateIndicator = s.Status.SuccessIndicator.SetString("HEY!")
	s.Status.WarnIndicator = s.Status.SuccessIndicator.Foreground(lipgloss.LightDark(isDarkTheme)(white, bgOverlay)).Background(yellow).SetString("WARNING")
	s.Status.ErrorIndicator = s.Status.SuccessIndicator.Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase)).Background(red).SetString("ERROR")
	s.Status.SuccessMessage = base.Foreground(lipgloss.LightDark(isDarkTheme)(white, bgSubtle)).Background(greenDark).Padding(0, 1)
	s.Status.InfoMessage = s.Status.SuccessMessage
	s.Status.UpdateMessage = s.Status.SuccessMessage
	s.Status.WarnMessage = s.Status.SuccessMessage.Foreground(lipgloss.LightDark(isDarkTheme)(white, bgOverlay)).Background(warning)
	s.Status.ErrorMessage = s.Status.SuccessMessage.Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase)).Background(red)

	// Completions styles
	s.Completions.Normal = base.Background(bgSubtle).Foreground(fgBase)
	s.Completions.Focused = base.Background(primary).Foreground(white)
	s.Completions.Match = base.Underline(true)

	// Attachments styles
	attachmentIconStyle := base.Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase)).Background(green).Padding(0, 1)
	s.Attachments.Image = attachmentIconStyle.SetString(ImageIcon)
	s.Attachments.Text = attachmentIconStyle.SetString(TextIcon)
	s.Attachments.Normal = base.Padding(0, 1).MarginRight(1).Background(fgMuted).Foreground(fgBase)
	s.Attachments.Deleting = base.Padding(0, 1).Background(red).Foreground(lipgloss.LightDark(isDarkTheme)(white, bgBase))

	// Pills styles
	s.Pills.Base = base.Padding(0, 1)
	s.Pills.Focused = base.Padding(0, 1).BorderStyle(lipgloss.RoundedBorder()).BorderForeground(bgOverlay)
	s.Pills.Blurred = base.Padding(0, 1).BorderStyle(lipgloss.HiddenBorder())
	s.Pills.QueueItemPrefix = s.Muted.SetString("  •")
	s.Pills.HelpKey = s.Base
	s.Pills.HelpText = s.Muted
	s.Pills.Area = base
	s.Pills.TodoSpinner = base.Foreground(greenDark)

	return s
}

func chromaStyle(style ansi.StylePrimitive) string {
	var s strings.Builder

	if style.Color != nil {
		s.WriteString(*style.Color)
	}
	if style.BackgroundColor != nil {
		if s.Len() > 0 {
			s.WriteString(" ")
		}
		s.WriteString("bg:")
		s.WriteString(*style.BackgroundColor)
	}
	if style.Italic != nil && *style.Italic {
		if s.Len() > 0 {
			s.WriteString(" ")
		}
		s.WriteString("italic")
	}
	if style.Bold != nil && *style.Bold {
		if s.Len() > 0 {
			s.WriteString(" ")
		}
		s.WriteString("bold")
	}
	if style.Underline != nil && *style.Underline {
		if s.Len() > 0 {
			s.WriteString(" ")
		}
		s.WriteString("underline")
	}

	return s.String()
}

// Theme represents the color theme of the terminal.
type Theme int

const (
	// ThemeDark uses colors optimized for dark terminal backgrounds.
	ThemeDark Theme = iota
	// ThemeLight uses colors optimized for light terminal backgrounds.
	ThemeLight
)

// foregroundColorsForTheme returns the foreground color palette for the given theme.
func foregroundColorsForTheme(theme ...Theme) (fgBase, fgMuted, fgHalfMuted, fgSubtle color.Color) {
	t := ThemeDark
	if len(theme) > 0 {
		t = theme[0]
	}
	switch t {
	case ThemeLight:
		// Foregrounds for light terminal backgrounds.
		fgBase = lipgloss.Color("#1A1A1A")
		fgMuted = lipgloss.Color("#5A5A5A")
		fgHalfMuted = lipgloss.Color("#8A8A8A")
		fgSubtle = lipgloss.Color("#AAAAAA")
	default:
		// Foregrounds for dark terminal backgrounds.
		fgBase = lipgloss.Color("#F5F5F5")
		fgMuted = lipgloss.Color("#BBBBBB")
		fgHalfMuted = lipgloss.Color("#999999")
		fgSubtle = lipgloss.Color("#777777")
	}
	return fgBase, fgMuted, fgHalfMuted, fgSubtle
}
