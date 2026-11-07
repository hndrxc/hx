package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// ErrNotImplemented is returned when a requested command runtime is not implemented.
var ErrNotImplemented = errors.New("not implemented")

// NewTUICommand returns the tui subcommand for the hx CLI.
// It has no server or hub imports.
func NewTUICommand(out, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Start the terminal user interface",
		Long:  "Start the hx terminal user interface (TUI).",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("tui: %w", ErrNotImplemented)
		},
	}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd
}
