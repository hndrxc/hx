package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/hndrxc/hx/internal/buildinfo"
)

var errNotImplemented = errors.New("not implemented")

// newVersionCommand constructs the version subcommand.
func newVersionCommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the hx-desktop version",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(out, "hx-desktop version %s\n", buildinfo.Version)
		},
	}
	return cmd
}

// newRootCommand constructs the top-level hx-desktop command.
func newRootCommand(out, errOut io.Writer) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "hx-desktop",
		Short:         "hx graphical desktop client",
		Long:          "hx graphical desktop client application.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("desktop: %w", errNotImplemented)
		},
	}

	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)

	// Disable auto-generated completion command.
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add version flag and version subcommand.
	rootCmd.Version = buildinfo.Version
	rootCmd.SetVersionTemplate("hx-desktop version {{.Version}}\n")
	rootCmd.AddCommand(newVersionCommand(out))

	return rootCmd
}

func execute(args []string, out, errOut io.Writer) int {
	rootCmd := newRootCommand(out, errOut)
	rootCmd.SetArgs(args)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(errOut, "Error: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	code := execute(os.Args[1:], os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}
