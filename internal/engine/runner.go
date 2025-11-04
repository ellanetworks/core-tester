package engine

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

type Meta struct {
	ID      string
	Summary string
	Tags    []string
	Timeout time.Duration
}

type Env struct {
	CoreN2Address string
	GnbN2Address  string
}

type Test interface {
	Run(env Env) error
	Meta() Meta
}

type TestResult struct {
	Meta    Meta
	Success bool
	Details string
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
func Run(env Env) (bool, []TestResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	aTestFailed := false

	t := List()

	var testResults []TestResult

	for _, v := range t {
		success := true
		details := ""

		err := v.Run(env)
		if err != nil {
			success = false
			details = err.Error()
			aTestFailed = true
		}
		// time.Sleep(1 * time.Second) // Small delay between tests

		testResults = append(testResults, TestResult{
			Meta:    v.Meta(),
			Success: success,
			Details: details,
		})

		fmt.Fprintf(w, "%s\t%s\t%s\n", v.Meta().ID, getSuccessString(success), details)
	}

	w.Flush()

	return !aTestFailed, testResults
}
