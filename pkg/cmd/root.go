package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io"
	"io/ioutil"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"os"
	"os/user"
	"path"
	"path/filepath"
)

const (
	shortMessage = "Kubernetes-native security toolkit"
	longMessage  = `Kubernetes-native security toolkit

Starboard CLI can be used to find risks, such as vulnerabilities or insecure
pod descriptors, in Kubernetes workloads. By default, the risk assessment
reports are stored as custom resources.

To get started execute the following one-time init command:

$ %[1]s init

As an example let's run in the current namespace an old version of nginx that
we know has vulnerabilities:

$ kubectl create deployment nginx --image nginx:1.16

Run the vulnerability scanner to generate vulnerability reports:

$ %[1]s scan vulnerabilityreports deployment/nginx

Once this has been done, you can retrieve the vulnerability report:

$ %[1]s get vulnerabilityreports deployment/nginx -o yaml
`
)

func NewRootCmd(buildInfo starboard.BuildInfo, args []string, outWriter io.Writer, errWriter io.Writer) *cobra.Command {
	var cf *genericclioptions.ConfigFlags

	rootCmd := &cobra.Command{
		Use:           "starboard",
		Short:         shortMessage,
		Long:          fmt.Sprintf(longMessage, buildInfo.Executable),
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cf = genericclioptions.NewConfigFlags(true)

	rootCmd.AddCommand(NewVersionCmd(buildInfo, outWriter))
	rootCmd.AddCommand(NewInitCmd(buildInfo, cf))
	rootCmd.AddCommand(NewScanCmd(buildInfo, cf))
	rootCmd.AddCommand(NewGetCmd(buildInfo, cf, outWriter))
	rootCmd.AddCommand(NewReportCmd(buildInfo, cf, outWriter))
	rootCmd.AddCommand(NewCleanupCmd(buildInfo, cf))
	rootCmd.AddCommand(NewConfigCmd(cf, outWriter))

	SetGlobalFlags(cf, rootCmd)

	rootCmd.SetArgs(args[1:])
	rootCmd.SetOut(outWriter)
	rootCmd.SetErr(errWriter)

	return rootCmd
}

func GetStarboardHomeFolder() (string, error) {
	usrFolder, err := user.Current()
	if err != nil {
		return "", err
	}
	// User can set a custom KUBE_KNARK_HOME from environment variable
	return path.Join(usrFolder.HomeDir, ".starboard"), nil
}

// Run is the entry point of the Starboard CLI. It runs the specified
// command based on the specified args.
func Run(version starboard.BuildInfo, args []string, outWriter io.Writer, errWriter io.Writer) error {

	initFlags()
	folderPath, err := GetStarboardHomeFolder()
	if err != nil {
		return err
	}
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		err = CreateStarboardHomeFolderIfNotExist(folderPath)
		if err != nil {
			return err
		}
	}
	filePath := filepath.Join(folderPath, "metadata.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		err := initMetadata(version, err, filePath)
		if err != nil {
			return err
		}
	} else {
		metadataByte, err := ioutil.ReadFile(filePath)
		if err != nil {
			return err
		}
		var metadata Metadata
		err = json.Unmarshal(metadataByte, &metadata)
		if err != nil {
			return err
		}
	}
	fmt.Println(folderPath)

	return NewRootCmd(version, args, outWriter, errWriter).Execute()
}

func initMetadata(version starboard.BuildInfo, err error, filePath string) error {
	cf := genericclioptions.NewConfigFlags(true)
	err = installData(cf, version)
	if err != nil {
		return err
	}
	matadata := Metadata{Version: version.Version, Initialized: true}
	metadataByte, err := json.Marshal(matadata)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, metadataByte, 0644)
	if err != nil {
		return err
	}
	return nil
}

//CreateStarboardHomeFolderIfNotExist create starboard home folder if not exist
func CreateStarboardHomeFolderIfNotExist(folderName string) error {
	_, err := os.Stat(folderName)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(folderName, 0750)
		if errDir != nil {
			return err
		}
	}
	return nil
}

func initFlags() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	// Hide all klog flags except for -v
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name != "v" {
			pflag.Lookup(f.Name).Hidden = true
		}
	})
}

type Metadata struct {
	Version     string `json:"version"`
	Initialized bool   `json:"initialized"`
}
