# Base
FROM golang:1.21.4-alpine AS builder

RUN apk add --no-cache git build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/proxify

FROM alpine:3.18.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/proxify /usr/local/bin/

ENTRYPOINT ["proxify"]
