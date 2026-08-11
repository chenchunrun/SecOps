package admission

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/chenchunrun/SecOps/internal/computer"
)

func BenchmarkSharedAdmissionStore(b *testing.B) {
	for _, workers := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("managers-%d", workers), func(b *testing.B) {
			b.ReportAllocs()
			for iteration := range b.N {
				b.StopTimer()
				root, err := os.MkdirTemp("", "secops-admission-benchmark-")
				if err != nil {
					b.Fatal(err)
				}
				managers := benchmarkManagers(b, root, workers)
				start := make(chan struct{})
				errors := make(chan error, workers)
				var wait sync.WaitGroup
				wait.Add(workers)

				b.StartTimer()
				for worker, manager := range managers {
					go func() {
						defer wait.Done()
						<-start
						leaseID := ID(fmt.Sprintf("lease-%d-%d", iteration, worker))
						lease, err := manager.Acquire(context.Background(), Request{
							LeaseID:    leaseID,
							TaskID:     ID(fmt.Sprintf("task-%d-%d", iteration, worker)),
							ComputerID: computer.ID("benchmark"),
							Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 1},
						})
						if err == nil {
							_, err = manager.Release(context.Background(), lease.ID)
						}
						errors <- err
					}()
				}
				close(start)
				wait.Wait()
				b.StopTimer()

				close(errors)
				for err := range errors {
					if err != nil {
						b.Fatal(err)
					}
				}
				if err := os.RemoveAll(root); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.N*workers*2)/b.Elapsed().Seconds(), "store_ops/s")
		})
	}
}

func BenchmarkAdmissionStoreHistoryDepth(b *testing.B) {
	for _, history := range []int{0, 100, 1000} {
		b.Run(fmt.Sprintf("released-leases-%d", history), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(history), "history_leases")
			for range b.N {
				b.StopTimer()
				root, err := os.MkdirTemp("", "secops-admission-history-benchmark-")
				if err != nil {
					b.Fatal(err)
				}
				store, err := NewFileStore(root)
				if err != nil {
					b.Fatal(err)
				}
				seedReleasedLeases(b, store, history)
				manager, err := NewManager(store, []Profile{{
					ComputerID: computer.ID("benchmark"),
					Capacity:   Resources{Slots: 1, CPUUnits: 1, MemoryMB: 1},
				}})
				if err != nil {
					b.Fatal(err)
				}

				b.StartTimer()
				lease, err := manager.Acquire(context.Background(), Request{
					LeaseID:    ID("measured-lease"),
					TaskID:     ID("measured-task"),
					ComputerID: computer.ID("benchmark"),
					Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 1},
				})
				if err == nil {
					_, err = manager.Release(context.Background(), lease.ID)
				}
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				if err := os.RemoveAll(root); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func seedReleasedLeases(b *testing.B, store Store, count int) {
	b.Helper()
	ctx := context.Background()
	for index := range count {
		now := time.Now().UTC()
		lease, err := store.Create(ctx, Lease{
			ID:         ID(fmt.Sprintf("history-lease-%d", index)),
			TaskID:     ID(fmt.Sprintf("history-task-%d", index)),
			ComputerID: computer.ID("benchmark"),
			Demand:     Resources{Slots: 1, CPUUnits: 1, MemoryMB: 1},
			State:      StateActive,
			CreatedAt:  now,
			UpdatedAt:  now,
		})
		if err != nil {
			b.Fatal(err)
		}
		lease.State = StateReleased
		lease.UpdatedAt = now
		lease.ReleasedAt = now
		if _, err := store.Update(ctx, lease); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkManagers(b *testing.B, root string, workers int) []*Manager {
	b.Helper()
	managers := make([]*Manager, workers)
	for worker := range workers {
		store, err := NewFileStore(filepath.Clean(root))
		if err != nil {
			b.Fatal(err)
		}
		manager, err := NewManager(store, []Profile{{
			ComputerID: computer.ID("benchmark"),
			Capacity: Resources{
				Slots:    workers,
				CPUUnits: workers,
				MemoryMB: int64(workers),
			},
		}})
		if err != nil {
			b.Fatal(err)
		}
		managers[worker] = manager
	}
	return managers
}
