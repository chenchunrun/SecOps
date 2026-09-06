package dialog

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"
)

func TestPermissionsApprovalGuard(t *testing.T) {
	t.Parallel()
	for _, code := range []rune{'a', 's', tea.KeyEnter, tea.KeyTab, tea.KeyRight} {
		p := &Permissions{keyMap: defaultPermissionsKeyMap(), acceptAfter: time.Now().Add(time.Hour)}
		require.Nil(t, p.HandleMsg(tea.KeyPressMsg{Code: code}))
		require.Zero(t, p.selectedOption)
	}
	for _, code := range []rune{'d', tea.KeyEscape} {
		p := &Permissions{keyMap: defaultPermissionsKeyMap(), acceptAfter: time.Now().Add(time.Hour)}
		action := p.HandleMsg(tea.KeyPressMsg{Code: code})
		require.Equal(t, PermissionDeny, action.(ActionPermissionResponse).Action)
	}
	for _, tc := range []struct {
		code rune
		want PermissionAction
	}{
		{'a', PermissionAllow}, {'s', PermissionAllowForSession}, {tea.KeyEnter, PermissionAllow},
	} {
		p := &Permissions{keyMap: defaultPermissionsKeyMap(), acceptAfter: time.Now().Add(-time.Second)}
		action := p.HandleMsg(tea.KeyPressMsg{Code: tc.code})
		require.Equal(t, tc.want, action.(ActionPermissionResponse).Action)
	}
}
