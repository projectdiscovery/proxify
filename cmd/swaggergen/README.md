# SwaggerGen

SwaggerGen can generate [Swagger/OpenAPI Specification](https://swagger.io/specification/) from `proxify`'s request and response logs.

# Installation

Download the latest, ready-to-run binary from under [releases](https://github.com/projectdiscovery/proxify/releases/) or install/build it using `Go`:

```shell
go install -v github.com/projectdiscovery/proxify/cmd/swaggergen@latest
```

# Usage

```shell
swaggergen -help

Usage:
  ./swaggergen [flags]

Flags:
   -log-dir string           path to proxify's output log directory
   -api, -api-host string    API host (example: api.example.com)
   -os, -output-spec string  file to store Swagger/OpenAPI specification (example: OpenAPI.yaml)
```

### Running SwaggerGen

The following command generates and saves the Swagger/OpenAPI specification in `OpenAPI.yaml`, from the requests and responses captured for `localhost:8080` and stored in the `logs` directory:

```shell
swaggergen -api localhost:8080 -log-dir ./logs -os OpenAPI.yaml
```
