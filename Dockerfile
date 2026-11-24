# Bonus: builds and runs the server. Works on Cloud Run, which sets PORT.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
# CGO is off so the binary runs on a scratch image with no libc.
RUN CGO_ENABLED=0 go build -o /out/threat-alert-api .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/threat-alert-api /threat-alert-api
# Cloud Run overrides this with its own PORT value.
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/threat-alert-api"]
