package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func RenderTerminal(w io.Writer, report *Report) {
	fmt.Fprintln(w, "Universal Auth Doctor")
	fmt.Fprintln(w, strings.Repeat("-", len("Universal Auth Doctor")))

	currentSection := ""
	for _, r := range report.Results {
		if r.Section != currentSection {
			currentSection = r.Section
			fmt.Fprintf(w, "\n%s\n", currentSection)
		}
		fmt.Fprintf(w, "  %-4s %s\n", r.Status, r.Check)
		if r.Status == Fail {
			if r.Code != "" {
				fmt.Fprintf(w, "       %s\n", r.Code)
			}
			if r.Message != "" {
				fmt.Fprintf(w, "       %s\n", r.Message)
			}
			if r.Action != "" {
				fmt.Fprintf(w, "       Fix: %s\n", r.Action)
			}
		}
		if r.Status == Pass && r.Message != "" {
			fmt.Fprintf(w, "       %s\n", r.Message)
		}
		if r.Status == Warn && r.Message != "" {
			fmt.Fprintf(w, "       %s\n", r.Message)
		}
	}

	fmt.Fprintln(w)
	if report.HasFails {
		fmt.Fprintln(w, "FAIL")
	} else {
		fmt.Fprintln(w, "READY")
	}
}

func RenderJSON(w io.Writer, report *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
