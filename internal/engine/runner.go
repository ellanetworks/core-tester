package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

const (
	DefaultTestTimeout = 1 * time.Second
)

type Meta struct {
	ID      string
	Summary string
	Tags    []string
	Timeout time.Duration
}

type CoreConfig struct {
	N2Address string
	MCC       string
	MNC       string
	SST       int32
	SD        string
	DNN       string
	TAC       string
}

type Env struct {
	CoreConfig   CoreConfig
	GnbN2Address string
}

type Test interface {
	Run(ctx context.Context, env Env) error
	Meta() Meta
}

type TestResult struct {
	Meta     Meta
	Success  bool
	Details  string
	Duration time.Duration
}

var tests map[string]Test

func init() {
	tests = make(map[string]Test)
}

func Register(t Test) error {
	testID := t.Meta().ID

	_, ok := tests[testID]
	if ok {
		return fmt.Errorf("test with id is already registered (%s)", testID)
	}

	tests[testID] = t

	return nil
}

func List() map[string]Test {
	return tests
}

func getSuccessString(success bool) string {
	if success {
		return "PASSED"
	}

	return "FAILED"
}

// Run all registered tests and print the results to stdout.
// Returns true if all tests passed, false otherwise.
func Run(ctx context.Context, env Env) (bool, []TestResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	aTestFailed := false

	var testResults []TestResult

	for _, v := range List() {
		meta := v.Meta()

		timeout := meta.Timeout
		if timeout <= 0 {
			timeout = DefaultTestTimeout
		}

		tctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		err := v.Run(tctx, env)
		dur := time.Since(start)

		// Determine success
		success := (err == nil)

		// If the context timed out, override
		if errors.Is(tctx.Err(), context.DeadlineExceeded) {
			success = false

			if err == nil {
				err = fmt.Errorf("timeout after %s", timeout)
			}
		}

		cancel()

		details := ""
		if err != nil {
			details = err.Error()
			aTestFailed = true
		}

		testResults = append(testResults, TestResult{
			Meta:     meta,
			Success:  success,
			Details:  details,
			Duration: dur,
		})

		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t(%s)\n",
			meta.ID,
			getSuccessString(success),
			details,
			dur.Round(time.Millisecond),
		)
	}

	w.Flush()

	return !aTestFailed, testResults
}
