package report

type Reporter interface {
	GenerateReport() (report []byte, err error)
	PublishReport(report []byte) error
}
