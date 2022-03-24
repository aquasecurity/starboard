package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"time"

	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	starboardHomeFolder = ".starboard"
	MetadataFileName    = "metadata.json"
)

func createOrUpdateResourcesAndMetadata(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		filePath, err := getMetadataFilePath()
		if err != nil {
			return err
		}
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			err := createResourcesAndMetadata(buildInfo, cf, filePath)
			if err != nil {
				return err
			}
		} else {
			err := updateResourcesAndMetadata(filePath, buildInfo, cf)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func updateResourcesAndMetadata(filePath string, buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) error {
	if needUpdate, err := needUpdate(filePath, buildInfo); err == nil && needUpdate {
		err := deleteStarboardMetadataFile(filePath)
		if err != nil {
			return err
		}
		err = createResourcesAndMetadata(buildInfo, cf, filePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func createResourcesAndMetadata(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags, filePath string) error {
	fmt.Fprintf(os.Stdout, "updating starboard resources...\n")
	kubeConfig, err := cf.ToRESTConfig()
	if err != nil {
		return err
	}
	scheme := starboard.NewScheme()
	kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	err = installResources(kubeClient, kubeConfig, buildInfo)
	if err != nil {
		return err
	}
	err = createMetadataFile(buildInfo, err, filePath)
	if err != nil {
		return err
	}
	return nil
}

func createMetadataFile(buildInfo starboard.BuildInfo, err error, filePath string) error {
	metadata := Metadata{Version: buildInfo.Version, Initialized: true, CreatedAt: time.Now().Format("2006-01-02 15:04:05")}
	metadataByte, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filePath, metadataByte, 0644)
	if err != nil {
		return err
	}
	return nil
}

func needUpdate(filePath string, buildInfo starboard.BuildInfo) (bool, error) {
	metadataByte, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false, err
	}
	var metadata Metadata
	err = json.Unmarshal(metadataByte, &metadata)
	if err != nil {
		return false, err
	}
	if metadata.Version != buildInfo.Version || !metadata.Initialized {
		return true, nil
	}
	return false, nil
}

func getMetadataFilePath() (string, error) {
	folderPath, err := getStarboardHomeFolder()
	if err != nil {
		return "", err
	}
	err = createStarboardHomeFolderIfNotExist(folderPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(folderPath, MetadataFileName), nil
}

func deleteStarboardMetadataFolder() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		starboardHomeFolder, err := getStarboardHomeFolder()
		if err != nil {
			return err
		}
		err = os.RemoveAll(starboardHomeFolder)
		if err != nil {
			return err
		}
		return nil
	}
}

func deleteStarboardMetadataFile(starboardMetadataFile string) error {
	err := os.Remove(starboardMetadataFile)
	if err != nil {
		return err
	}
	return nil
}

type Metadata struct {
	Version     string `json:"version"`
	Initialized bool   `json:"initialized"`
	CreatedAt   string `json:"createdAt"`
}

//createStarboardHomeFolderIfNotExist create starboard home folder if not exist
func createStarboardHomeFolderIfNotExist(folderName string) error {
	if _, err := os.Stat(folderName); os.IsNotExist(err) {
		errDir := os.MkdirAll(folderName, 0700)
		if errDir != nil {
			return err
		}
	}
	return nil
}

func getStarboardHomeFolder() (string, error) {
	usrFolder, err := user.Current()
	if err != nil {
		return "", err
	}
	return path.Join(usrFolder.HomeDir, starboardHomeFolder), nil
}
