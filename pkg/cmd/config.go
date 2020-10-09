package cmd

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/kube"
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

func NewConfigCmd(cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
	var localFlags LocalFlags
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
			configMap, err := clientset.CoreV1().ConfigMaps(kube.NamespaceStarboard).Get(ctx, kube.NamespaceStarboard, metav1.GetOptions{})
			if err != nil {
				return
			}
			filteredValues, err := getFilteredValues(configMap, &localFlags)
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(outWriter, "%s\n", filteredValues)
			return
		},
	}
	setLocalFlags(cmd, &localFlags)
	return cmd
}

func getFilteredValues(configMap *v1.ConfigMap, localFlags *LocalFlags) (string, error) {
	data := configMap.Data
	if localFlags.get != "" {
		value := data[localFlags.get]
		if value != "" {
			return data[localFlags.get], nil
		} else {
			return "", fmt.Errorf("no such key exists: %s", localFlags.get)
		}
	}
	if localFlags.nameOnly {
		return convertMapToString(data, true), nil
	}
	return convertMapToString(data, false), nil
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

func setLocalFlags(cmd *cobra.Command, localFlags *LocalFlags) {
	cmd.Flags().BoolVar(&localFlags.nameOnly, "name-only", false, "List parameters by name only")
	cmd.Flags().StringVar(&localFlags.get, "get", "", "Get configuration parameters for a specified key")
}

