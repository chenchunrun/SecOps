package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/chenchunrun/SecOps/internal/admission"
	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

func defaultAdmissionCapacity() admission.Resources {
	return admission.Resources{Slots: 2, CPUUnits: 2, MemoryMB: 2048}
}

func admissionCapacityFor(cfg *config.Config, backend computer.Backend) admission.Resources {
	capacity := defaultAdmissionCapacity()
	if cfg == nil || cfg.Sandbox == nil || !strings.EqualFold(strings.TrimSpace(cfg.Sandbox.Mode), string(backend)) {
		return capacity
	}
	configured := admission.Resources{
		Slots:    cfg.Sandbox.CapacitySlots,
		CPUUnits: cfg.Sandbox.CapacityCPUUnits,
		MemoryMB: cfg.Sandbox.CapacityMemoryMB,
	}
	if configured == (admission.Resources{}) {
		return capacity
	}
	return configured
}

func normalizeAdmissionDemand(demand admission.Resources) admission.Resources {
	if demand == (admission.Resources{}) {
		return admission.Resources{Slots: 1, CPUUnits: 1, MemoryMB: 256}
	}
	return demand
}

func (r *ComputerRuntime) RunTaskAdmitted(
	ctx context.Context,
	id taskruntime.ID,
	resolver taskruntime.ComputerResolver,
) (taskruntime.Task, error) {
	if r == nil || r.Tasks == nil || r.Admission == nil {
		return taskruntime.Task{}, fmt.Errorf("%w: admission runtime is unavailable", taskruntime.ErrInvalidTask)
	}
	task, err := r.Tasks.Get(ctx, id)
	if err != nil {
		return taskruntime.Task{}, err
	}
	demand := normalizeAdmissionDemand(task.ResourceDemand)
	lease, err := r.Admission.Acquire(ctx, admission.Request{
		LeaseID:    taskAdmissionLeaseID(task),
		TaskID:     admission.ID(task.ID),
		ComputerID: task.ComputerID,
		Demand:     demand,
	})
	if errors.Is(err, admission.ErrUnknownComputer) && r.Computers != nil {
		if _, computerErr := r.Computers.Get(task.ComputerID); computerErr == nil {
			profileErr := r.Admission.RegisterProfile(admission.Profile{
				ComputerID: task.ComputerID,
				Capacity:   defaultAdmissionCapacity(),
			})
			if profileErr != nil {
				return task, fmt.Errorf("register durable task admission profile: %w", profileErr)
			}
			lease, err = r.Admission.Acquire(ctx, admission.Request{
				LeaseID:    taskAdmissionLeaseID(task),
				TaskID:     admission.ID(task.ID),
				ComputerID: task.ComputerID,
				Demand:     demand,
			})
		}
	}
	if err != nil {
		return task, fmt.Errorf("admit durable task: %w", err)
	}

	executed, runErr := r.Tasks.RunAssigned(ctx, id, resolver)
	_, releaseErr := r.Admission.Release(context.WithoutCancel(ctx), lease.ID)
	if runErr != nil || releaseErr != nil {
		return executed, errors.Join(runErr, releaseErr)
	}
	return executed, nil
}

func taskAdmissionLeaseID(task taskruntime.Task) admission.ID {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", task.ID, task.Attempt+1)))
	return admission.ID(fmt.Sprintf("task-%x", digest[:12]))
}
