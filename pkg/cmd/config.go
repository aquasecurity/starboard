package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

type LocalFlags struct {
	get string
	nameOnly bool
}

var localFlags LocalFlags

func NewConfigCmd(cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "View the configuration parameters used by starboard scanners",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := context.Background()
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
			starboard := "starboard"	// the configmap name and namespace are both currently "starboard"
			configMap, err := clientset.CoreV1().ConfigMaps(starboard).Get(ctx, starboard, metav1.GetOptions{})
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(outWriter, "%s\n", getFilteredValues(configMap))
			return
		},
	}
	setLocalFlags(cmd)
	return cmd
}

func getFilteredValues(configMap *v1.ConfigMap) string {
	data := configMap.Data
	if localFlags.get != "" {
		return data[localFlags.get]
	}
	if localFlags.nameOnly {
		return convertMapToString(data, true)
	}
	return convertMapToString(data, false)
}

func convertMapToString(mapToConvert map[string]string, nameOnly bool) string {
	asString := make([]string, 0, len(mapToConvert))
	for key, val := range mapToConvert {
		asString = append(asString, key)
		if !nameOnly {
			asString = append(asString, val)
		}
	}
	return strings.Join(asString, "\n")
}

func setLocalFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&localFlags.nameOnly, "name-only", false, "List parameters by name only")
	cmd.Flags().StringVar(&localFlags.get, "get", "", "Get configuration parameters for a specified key")
}

