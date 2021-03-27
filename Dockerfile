# Base
FROM golang:1.14-alpine AS builder

RUN apk add --no-cache git
RUN GO111MODULE=auto go get -u -v github.com/projectdiscovery/proxify/cmd/proxify

# Release
FROM alpine:latest

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /go/bin/proxify /usr/local/bin/

ENTRYPOINT ["proxify"]
