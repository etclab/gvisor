// execbench: how long a fork+execve+wait takes inside the sandbox.
//
// Spike E2 needs the same number with and without the exec sink installed, so
// this measures the whole of what a workload pays to start a process — the
// fork, the execve, and the wait for a program that does nothing — rather than
// the execve syscall alone. The sink runs inside the execve, before the new
// image is installed, so whatever it costs is inside this interval; nothing
// else about the interval changes between the two runs.
//
//	execbench <n> <path> [argv...]
//
// It prints one line: n, and the min, median, p95 and max of the interval.
// A run that is refused prints the error and the count at which it happened,
// which is how the same program shows an exec outside x failing EACCES.
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <n> <path> [argv...]\n", os.Args[0])
		os.Exit(2)
	}
	n, err := strconv.Atoi(os.Args[1])
	if err != nil || n < 1 {
		fmt.Fprintf(os.Stderr, "execbench: %q is not a count\n", os.Args[1])
		os.Exit(2)
	}
	path := os.Args[2]
	argv := os.Args[2:]
	attr := &syscall.ProcAttr{
		Dir:   "/",
		Env:   []string{"PATH=/bin"},
		Files: []uintptr{0, 1, 2},
	}
	d := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		pid, err := syscall.ForkExec(path, argv, attr)
		if err != nil {
			fmt.Printf("execbench: REFUSED path=%s at attempt %d after %d successes: %v\n", path, i+1, i, err)
			os.Exit(1)
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
			fmt.Printf("execbench: wait failed at attempt %d: %v\n", i+1, err)
			os.Exit(1)
		}
		d = append(d, time.Since(start))
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	fmt.Printf("execbench: path=%s n=%d min=%v median=%v p95=%v max=%v\n",
		path, n, d[0], d[n/2], d[pct(n, 95)], d[n-1])
}

// pct is the index of the p'th percentile of a sorted slice of length n.
func pct(n, p int) int {
	i := (p*(n-1) + 50) / 100
	if i >= n {
		i = n - 1
	}
	return i
}
