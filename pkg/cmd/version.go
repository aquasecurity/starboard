package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

func NewVersionCmd(version VersionInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			fmt.Printf("Starboard Version: %+v\n", version)
			return
		},
	}
	return cmd
}
