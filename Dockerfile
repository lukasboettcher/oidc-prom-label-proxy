FROM golang:latest as builder

WORKDIR /app

COPY . .

RUN go build .

FROM quay.io/prometheus/busybox-linux-amd64:glibc

COPY --from=builder  /app/oidc-prom-label-proxy /bin/oidc-prom-label-proxy

USER        nobody

ENTRYPOINT  [ "/bin/oidc-prom-label-proxy" ]
