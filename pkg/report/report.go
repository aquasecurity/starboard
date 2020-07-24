package report

import "io"

type Reporter interface {
	Generate(writer io.Writer) error
}