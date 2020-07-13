package report

type Reporter interface {
	GenerateReport() (report interface{}, err error)
	PublishReport(report interface{}) error
}
