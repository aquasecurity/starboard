package cmd

import (
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/spf13/cobra"
)

func NewVersionCmd(version starboard.BuildInfo, outWriter io.Writer) *cobra.Command {
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
