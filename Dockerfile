FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump, filtering and manipulation via DSL language, upstream HTTP/SOCKS5 proxy."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="proxify"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/proxify"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/proxify /usr/local/bin/

ENTRYPOINT ["proxify"]
