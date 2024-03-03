# KubeCop exporters package
This package contains the exporters for the KubeCop project.

## Exporters
The following exporters are available:
- [Alertmanager](https://github.com/prometheus/alertmanager)
- STD OUT
- SYSLOG
- CSV
- HTTP endpoint

### Alertmanager
The Alertmanager exporter is used to send alerts to the Alertmanager. The Alertmanager will then send the alerts to the configured receivers.
This exporter supports multiple Alertmanagers. The alerts will be sent to all configured Alertmanagers.
To enable the Alertmanager exporter, set the following environment variables:
- `ALERTMANAGER_URLS`: The URLs of the Alertmanagers. Example: `localhost:9093` or `localhost:9093,localhost:9094`

### STD OUT
The STD OUT exporter is used to print the alerts to the standard output. This exporter is enabled by default.
To disable the STD OUT exporter, set the following environment variable:
- `STDOUT_ENABLED`: Set to `false` to disable the STD OUT exporter.

### SYSLOG
The SYSLOG exporter is used to send the alerts to a syslog server. This exporter is disabled by default.
NOTE: The SYSLOG messages format is RFC 5424.
To enable the SYSLOG exporter, set the following environment variables:
- `SYSLOG_HOST`: The host of the syslog server. Example: `localhost:514`
- `SYSLOG_PROTOCOL`: The protocol of the syslog server. Example: `tcp` or `udp`

### CSV
The CSV exporter is used to write the alerts to a CSV file. This exporter is disabled by default.
To enable the CSV exporter, set the following environment variables:
- `EXPORTER_CSV_RULE_PATH`: The path to the CSV file of the failed rules. Example: `/tmp/alerts.csv`
- `EXPORTER_CSV_MALWARE_PATH`: The path to the CSV file of the malwares found. Example: `/tmp/malware.csv`

### HTTP endpoint
The HTTP endpoint exporter is used to send the alerts to an HTTP endpoint. This exporter is disabled by default.
To enable the HTTP endpoint exporter, set the following environment variables:
- `HTTP_ENDPOINT_URL`: The URL of the HTTP endpoint. Example: `http://localhost:8080/alerts`
This will send a POST request to the specified URL with the alerts as the body.
The alerts are limited to 10000 per minute. If the limit is reached, the exporter will stop sending alerts for the rest of the minute and will send a system alert to the configured HTTP endpoint.
