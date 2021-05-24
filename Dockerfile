# Base
FROM golang:1.16.4-alpine AS builder

RUN apk add --no-cache git
RUN GO111MODULE=on go get -v github.com/projectdiscovery/proxify/cmd/proxify

# Release
FROM alpine:latest

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /go/bin/proxify /usr/local/bin/

ENTRYPOINT ["proxify"]
