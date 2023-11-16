# KubeCope exporters package
This package contains the exporters for the KubeCope project.

## Exporters
The following exporters are available:
- [Alertmanager](https://github.com/prometheus/alertmanager)
- STD OUT

### Alertmanager
The Alertmanager exporter is used to send alerts to the Alertmanager. The Alertmanager will then send the alerts to the configured receivers.
To enable the Alertmanager exporter, set the following environment variables:
- `ALERTMANAGER_URL`: The URL of the Alertmanager. Example: `localhost:9093`

### STD OUT
The STD OUT exporter is used to print the alerts to the standard output. This exporter is enabled by default.
To disable the STD OUT exporter, set the following environment variable:
- `STDOUT_ENABLED`: Set to `false` to disable the STD OUT exporter.