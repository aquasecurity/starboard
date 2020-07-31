package report

import "io"

type Reporter interface {
	GenerateReport(writer io.Writer) error
}