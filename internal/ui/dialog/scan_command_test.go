package dialog

import (
	"testing"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"
)

func TestTypedScanCommandBypassesFuzzySelection(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"scan new", "scan authorize /tmp/project with spaces", "scan review task passed Checked packages"} {
		c := &Commands{selected: SystemCommands, input: textinput.New()}
		c.keyMap.Select = key.NewBinding(key.WithKeys("enter"))
		c.input.SetValue(input)
		action := c.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnter})
		require.Equal(t, ActionRunScanCommand{Input: input[len("scan "):]}, action)
	}
}
