package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/hndrxc/hx/internal/buildinfo"
	"github.com/hndrxc/hx/internal/cli"
)

var errNotImplemented = errors.New("not implemented")

// newHubCommand constructs the hub server subcommand.
func newHubCommand(out, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Run the hx hub daemon",
		Long:  "Run the hx hub daemon service.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("hub: %w", errNotImplemented)
		},
	}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd
}

// newVersionCommand constructs the version subcommand.
func newVersionCommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the hx version",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(out, "hx version %s\n", buildinfo.Version)
		},
	}
	return cmd
}

// newRootCommand constructs the top-level hx CLI command.
func newRootCommand(out, errOut io.Writer) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "hx",
		Short:         "hx observability and telemetry platform",
		Long:          "hx unified executable for hub services, device telemetry, and client tooling.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)

	// Disable auto-generated completion command.
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add version flag and version subcommand.
	rootCmd.Version = buildinfo.Version
	rootCmd.SetVersionTemplate("hx version {{.Version}}\n")
	rootCmd.AddCommand(newVersionCommand(out))

	// Register subcommands.
	rootCmd.AddCommand(newHubCommand(out, errOut))
	rootCmd.AddCommand(cli.NewTUICommand(out, errOut))

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
