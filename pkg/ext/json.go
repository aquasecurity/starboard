package ext

import "io"

type JsonReader struct {
	reader  io.ReadCloser
	started bool
}

// NewJsonReader constructs a new instant of JsonReader, which will try to match a start characator of
// "{" or "[" as beginning of the json stream.
func NewJsonReader(reader io.ReadCloser) io.ReadCloser {
	return &JsonReader{reader: reader}
}

func (j *JsonReader) Read(p []byte) (n int, err error) {
	if j.started {
		return j.reader.Read(p)
	}
	var c = make([]byte, len(p))
	for ; err == nil; n, err = j.reader.Read(c) {
		i := 0
		for ; i < n; i++ {
			if c[i] == '{' || c[i] == '[' {
				j.started = true
				copy(p, c[i:])
				return n - i, err
			}
		}
	}

	return n, err
}

func (j *JsonReader) Close() error {
	return j.reader.Close()
}
