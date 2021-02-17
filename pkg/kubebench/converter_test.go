package kubebench_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestConverter_Convert(t *testing.T) {
	config := starboard.ConfigData{
		"kube-bench.imageRef": "aquasec/kube-bench:0.3.1",
	}
	var testCases = []struct {
		name string
		in   string // input File
		op   string // golden file
		err  error  // expected error
	}{
		{
			name: "Valid single json object in array",
			in:   "testdata/valid.json",
			op:   "testdata/goldenSingle.json",
			err:  nil,
		},
		{
			name: "invalid json object",
			in:   "testdata/invalid.json",
			err:  errors.New("invalid character 'I' looking for beginning of value"),
		},
		{
			name: "Valid multiple json object in array",
			in:   "testdata/multiObjects.json",
			op:   "testdata/goldenMultiple.json",
			err:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inFile, err := os.Open(tc.in)
			require.NoError(t, err)
			defer func() {
				_ = inFile.Close()
			}()

			converter := &kubebench.Converter{Clock: fixedClock, Config: config}
			output, err := converter.Convert(inFile)

			switch {
			case tc.err == nil:
				require.NoError(t, err)
				expectedOutput := expectedOutputFrom(t, tc.op)
				assert.Equal(t, expectedOutput, output, "Converted report does not match expected report")
			default:
				assert.EqualError(t, err, tc.err.Error())
			}
		})
	}
}

func expectedOutputFrom(t *testing.T, fileName string) v1alpha1.CISKubeBenchOutput {
	t.Helper()

	file, err := os.Open(fileName)
	require.NoError(t, err)
	defer file.Close()

	var expectedOutput v1alpha1.CISKubeBenchOutput
	err = json.NewDecoder(file).Decode(&expectedOutput)
	require.NoError(t, err)

	// Override time read from file
	expectedOutput.UpdateTimestamp = metav1.NewTime(fixedTime)

	return expectedOutput
}
