package setup

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// RenderTerminal writes a human-readable setup report.
func RenderTerminal(w io.Writer, report *Report) {
	fmt.Fprintln(w, "Universal Auth Setup")
	fmt.Fprintln(w, strings.Repeat("-", len("Universal Auth Setup")))
	fmt.Fprintln(w)

	for _, s := range report.Steps {
		fmt.Fprintf(w, "  %-6s %s\n", s.Status, s.Name)
		if s.Message != "" {
			fmt.Fprintf(w, "         %s\n", s.Message)
		}
		if s.Status == Fail && s.Code != "" {
			fmt.Fprintf(w, "         %s\n", s.Code)
		}
		if s.Detail != "" && (s.Status == Fail || s.Status == Action) {
			for _, line := range strings.Split(s.Detail, "\n") {
				fmt.Fprintf(w, "         %s\n", line)
			}
		}
	}

	fmt.Fprintln(w)
	switch {
	case report.HasFails:
		fmt.Fprintln(w, "Universal Auth setup failed.")
	case report.HasActions:
		fmt.Fprintln(w, "Universal Auth setup incomplete:")
		for _, s := range report.Steps {
			if s.Status == Action {
				fmt.Fprintf(w, "  %s\n", s.Message)
			}
		}
	default:
		fmt.Fprintln(w, "Universal Auth is ready.")
	}
}

// RenderJSON writes the setup report as JSON.
func RenderJSON(w io.Writer, report *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
