package workbench

import (
	"context"
	"errors"

	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

type DurableTaskController struct {
	runtime *taskruntime.Runtime
}

func NewDurableTaskController(runtime *taskruntime.Runtime) (*DurableTaskController, error) {
	if runtime == nil {
		return nil, errors.New("initialize durable task controller: runtime is nil")
	}
	return &DurableTaskController{runtime: runtime}, nil
}

func (c *DurableTaskController) Pause(ctx context.Context, id string) error {
	_, err := c.runtime.Pause(ctx, taskruntime.ID(id))
	return err
}

func (c *DurableTaskController) Resume(ctx context.Context, id string) error {
	_, err := c.runtime.Resume(ctx, taskruntime.ID(id))
	return err
}

func (c *DurableTaskController) Cancel(ctx context.Context, id string) error {
	_, err := c.runtime.Cancel(ctx, taskruntime.ID(id))
	return err
}
