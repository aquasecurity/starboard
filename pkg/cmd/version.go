package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

func NewVersionCmd(version VersionInfo, outWriter io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			_, _ = fmt.Fprintf(outWriter, "Starboard Version: %+v\n", version)
			return
		},
	}
	return cmd
}
