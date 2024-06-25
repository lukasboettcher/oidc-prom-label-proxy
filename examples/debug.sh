go run . -label job -upstream http://demo.do.prometheus.io:9090 \
    -insecure-listen-address 127.0.0.1:8080 \
    -oidc-client-id XXX \
    -oidc-issuer https://login.microsoftonline.com/XXX/v2.0 \
    -oidc-config examples/tenant-config.yaml