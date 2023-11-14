package exporters

// generic exporter interface
type Exporter interface {
	// SendAlert sends an alert to the exporter
	SendAlert()
}
