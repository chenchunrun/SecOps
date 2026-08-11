package admission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/stretchr/testify/require"
)

func TestManagersInSeparateProcessesDoNotOversubscribe(t *testing.T) {
	const contenders = 24

	root := t.TempDir()
	barrier := filepath.Join(root, "start")
	commands := make([]*exec.Cmd, 0, contenders)
	outputs := make([]bytes.Buffer, contenders)
	for index := range contenders {
		command := exec.Command(os.Args[0], "-test.run=^TestAdmissionProcessHelper$")
		command.Env = append(os.Environ(),
			"SECOPS_ADMISSION_HELPER=1",
			"SECOPS_ADMISSION_ROOT="+root,
			"SECOPS_ADMISSION_BARRIER="+barrier,
			fmt.Sprintf("SECOPS_ADMISSION_INDEX=%d", index),
		)
		command.Stdout = &outputs[index]
		command.Stderr = &outputs[index]
		require.NoError(t, command.Start())
		commands = append(commands, command)
	}
	require.NoError(t, os.WriteFile(barrier, []byte("start"), 0o600))

	admitted := 0
	for index, command := range commands {
		require.NoErrorf(t, command.Wait(), "helper %d output: %s", index, outputs[index].String())
		if strings.Contains(outputs[index].String(), "ADMISSION_RESULT=admitted") {
			admitted++
		}
	}
	require.Equal(t, 1, admitted)

	store, err := NewFileStore(root)
	require.NoError(t, err)
	active, err := store.List(context.Background(), StateActive)
	require.NoError(t, err)
	require.Len(t, active, 1)
}

func TestAdmissionProcessHelper(t *testing.T) {
	if os.Getenv("SECOPS_ADMISSION_HELPER") != "1" {
		t.Skip("subprocess helper")
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("SECOPS_ADMISSION_BARRIER")); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect start barrier: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for start barrier")
		}
		time.Sleep(time.Millisecond)
	}

	store, err := NewFileStore(os.Getenv("SECOPS_ADMISSION_ROOT"))
	require.NoError(t, err)
	manager, err := NewManager(store, []Profile{{
		ComputerID: computer.ID("local"),
		Capacity:   Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	}})
	require.NoError(t, err)
	index := os.Getenv("SECOPS_ADMISSION_INDEX")
	_, err = manager.Acquire(context.Background(), Request{
		LeaseID:    ID("lease-" + index),
		TaskID:     ID("task-" + index),
		ComputerID: computer.ID("local"),
		Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256},
	})
	if err == nil {
		fmt.Println("ADMISSION_RESULT=admitted")
		return
	}
	if errors.Is(err, ErrCapacityExceeded) {
		fmt.Println("ADMISSION_RESULT=capacity")
		return
	}
	t.Fatalf("acquire admission lease: %v", err)
}
