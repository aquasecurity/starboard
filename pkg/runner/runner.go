package runner

import (
	"errors"
	"time"

	"k8s.io/klog"
)

// ErrTimeout is returned when Runner's Run method fails due to a timeout event.
var ErrTimeout = errors.New("runner received timeout")

// Runnable is the interface that wraps the basic Run method.
//
// Run should be implemented by any task intended to be executed by the Runner.
type Runnable interface {
	Run() error
}

// The RunnableFunc type is an adapter to allow the use of ordinary functions as Runnable tasks.
// If f is a function with the appropriate signature, RunnableFunc(f) is a Runnable that calls f.
type RunnableFunc func() error

// Run calls f()
func (f RunnableFunc) Run() error {
	return f()
}

// Runner is the interface that wraps the basic Run method.
//
// Run executes submitted Runnable tasks.
type Runner interface {
	Run(task Runnable) error
}

type runner struct {
	// complete channel reports that processing is done
	complete chan error
	// timeout channel reports that time has run out
	timeout <-chan time.Time
}

// New constructs a new ready-to-use Runner with the specified timeout for running a Task.
func New(d time.Duration) Runner {
	return &runner{
		complete: make(chan error),
		timeout:  time.After(d),
	}
}

// Run runs the specified task and monitors channel events.
func (r *runner) Run(task Runnable) error {
	go func() {
		r.complete <- task.Run()
	}()

	select {
	// Signaled when processing is done.
	case err := <-r.complete:
		klog.V(3).Infof("Stopping runner on task completion with error: %v", err)
		return err
	// Signaled when we run out of time.
	case <-r.timeout:
		klog.V(3).Info("Stopping runner on timeout")
		return ErrTimeout
	}
}
