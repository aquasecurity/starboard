package kubebench

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"testing"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_Convert(t *testing.T) {
	var testcases = []struct {
		name string
		in   string // input File
		op   string // golden file
		err  error  // expected error
	}{
		{"Valid single json object in array", "testdata/valid.json", "testdata/goldenSingle.json", nil},
		{"invalid json object", "testdata/invalid.json", "testdata/goldenSingle.json", errors.New("json: cannot unmarshal object into Go value of type []v1alpha1.CISKubeBenchSection")},
		{"Valid multiple json object in array", "testdata/multiobjects.json", "testdata/goldenMultiple.json", nil},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			gFile, err := os.Open(tc.op)
			require.NoError(t, err)
			dec := json.NewDecoder(gFile)
			var kbop starboard.CISKubeBenchOutput
			for {
				if err = dec.Decode(&kbop); err == io.EOF {
					break
				} else if err != nil {
					log.Fatalln("Error while decoding golden file", err)
				}
			}

			inFile, err := os.Open(tc.in)
			require.NoError(t, err)
			defer func() {
				_ = inFile.Close()
				_ = gFile.Close()
			}()

			var r starboard.CISKubeBenchOutput
			r, err = DefaultConverter.Convert(inFile)
			switch {
			case tc.err == nil:
				require.NoError(t, err)
				assert.Equal(t, kbop, r, "Converted report does not match expected report")
			default:
				assert.EqualError(t, err, tc.err.Error())
			}
		})
	}
}
